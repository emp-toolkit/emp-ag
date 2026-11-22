#ifndef EMP_AG_BACKEND_TRIPLE_LAAND_H__
#define EMP_AG_BACKEND_TRIPLE_LAAND_H__
//
// Pi_LaAND: leaky authenticated AND triples by the half-gate technique. A row of L
// candidates is three aShare vectors a, b, r per peer (triple/triple_row.h); the leaky
// AND turns r into c = a AND b in place. The adversary may learn a through selective
// failure; b enters only the linear phi. Bucketing (triple/merge.h) removes the leakage
// on a.
//
// One check covers every row of a call:
//   nP == 2  a symmetric F_EQ over every row's transmitted bit window. feq_commit() gives
//            the commitment, which the caller sends with its next flight; finish_check()
//            opens it.
//   nP >= 3  one random linear combination of every row's windowed values, committed and
//            opened in two flights. Its challenge continues the caller's coin stream,
//            after the rotations.
//
// Implementation choices:
//
// (1) F_Zero is pairwise seed-and-expand under the ICM assumption on the AES-based PRG:
//     each pair shares a lambda-bit seed, both expand into B*L+1 blocks via PRG and XOR
//     them into local (z^i, u^i), once per call for every row. Each seed contributes to
//     exactly two parties, so Sigma_p z^p_k = 0 and Sigma_p u^p = 0 (common/fzero.h).
//
// (2) The s-bits (the spec's d^i) are sent without F_Com, every party's in one flight.
//     Seeing the honest parties' s-bits first tells a rushing party nothing about a, and
//     a wrong s-bit is caught by the check except with probability 2^-ssp. The check's
//     own value alpha^i (nP >= 3) is hash-committed (one flight) and then opened, since
//     the check needs binding.
//
#include "emp-ag/backend/ashare/share.h"       // LSB1
#include "emp-ag/backend/common/fs_hash.h"     // FsHash
#include "emp-ag/backend/common/feq.h"         // fs_coin_pair_group, symmetric F_eq
#include "emp-ag/backend/common/fzero.h"       // fzero_xor
#include "emp-ag/backend/common/laand_window.h"
#include "emp-ag/backend/common/lane_mesh.h"
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/common/profiling.h"
#include "emp-ag/backend/common/protocols.h"   // role_bound_commitment
#include "emp-ag/backend/common/runtime.h"     // parallel_for, lane_range
#include "emp-ag/backend/triple/triple_row.h"
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/core/block_vector.h"
#include "emp-tool/runtime/crypto/f2k.h"       // vector_inn_prdt_sum_no_red
#include "emp-tool/runtime/crypto/hash.h"
#include "emp-tool/runtime/crypto/mitccrh.h"
#include "emp-tool/runtime/crypto/prg.h"
#include "emp-tool/runtime/crypto/ro.h"
#include <algorithm>
#include <cstring>
#include <vector>

namespace emp::ag {

// ===== windowed F_eq (nP == 2) =====
// Fixed stripe width (in elements) for the parallel F_eq window fold below. It shapes the
// CHECK VALUE (stripe digests are what the running hash binds), so it must be identical
// at both parties: a compile-time constant, never a function of the local pool size.
inline constexpr int kFeqStripeElems = 1 << 16;

// Fold L windows of gb bytes each (the transmitted bits, zero-padded, contiguous at src)
// into the running F_eq hash. The fold is a fixed two-level hash: the window bytes are
// hashed per kFeqStripeElems-window stripe (independent stripes, so the hashing runs
// pool-parallel), and the ordered stripe digests feed the running feq. Collision
// resistance composes across the levels, so this binds exactly the window bytes; both
// parties use the same stripe constant and derive the same stripe count from the common
// L. One terminal symmetric F_eq fires per call; the caller owns it.
inline void accumulate_leaky_and_window_bytes(FsHash &feq,
                                              const unsigned char *src,
                                              int L, int gb, ThreadPool *pool) {
  const int ns = (L + kFeqStripeElems - 1) / kFeqStripeElems;
  std::vector<char> dg((size_t)ns * FsHash::DIGEST_SIZE);
  vector<future<void>> res;
  for (int s = 0; s < ns; ++s) {
    res.push_back(pool->enqueue([&, s]() {
      const int k0 = s * kFeqStripeElems;
      const int k1 = std::min(L, k0 + kFeqStripeElems);
      FsHash::hash_once(dg.data() + (size_t)s * FsHash::DIGEST_SIZE,
                        src + (size_t)k0 * gb,
                        (size_t)(k1 - k0) * gb);
    }));
  }
  joinNclean(res);
  feq.put(dg.data(), dg.size());
}

// The leaky ANDs of one session: one schedule for every nP (produce_rows), the check over
// a call's rows, and their reused scratch. `prg` is the calling protocol's (F_Zero's seeds,
// the F_eq nonce).
template <int nP>
class LeakyAnd {
public:
  LeakyAnd(const LaneMesh<nP> &mesh, int ssp, block session_id, block Delta, PRG *prg)
      : mesh_(mesh), party_(mesh.party), ssp_(ssp), sid_(session_id), Delta_(Delta),
        prg_(prg) {}

  // A new call: no row's check material yet.
  void begin_call() {
    alpha_masked_cat_.clear();
    alpha_u_ = zero_block;
  }

  // The half-gate leaky AND on every row of a call, B rows of L candidates (a, b, r) whose
  // COTs are all fixed. On return each row's r has been folded into c = a AND b in place,
  // and the rows' check material is accumulated; finish_check() runs the check.
  //   1. nP > 2: one F_Zero for every row: z, one block per candidate, blinds phi, and u
  //      the check.
  //   2. One transcript root per peer, RO-expanded by the batch shape and row index into
  //      each row's hash-stream seed.
  //   3. One flight: every row's half-gate rows to every peer, one sender and one receiver
  //      task per (peer, lane) walking the rows in order.
  //   4. One flight: every row's s-bits.
  //   5. Per row, the d-combine and the check material: the F_eq window fold at nP == 2,
  //      the windowed values for the RLC at nP > 2.
  void produce_rows(const std::vector<TripleRow<nP>> &rows, int L, FsHash &feq) {
    ThreadPool *pool = mesh_.pool;
    const int B = (int)rows.size();
    const int BL = B * L;
    const int any_peer = (party_ == 1) ? 2 : 1;
    const int gb = ag::laand_window_bytes(ssp_);
    const int gw = ag::laand_window_bits(ssp_);
    [[maybe_unused]] const block window_mask = ag::laand_window_mask(ssp_);
    std::vector<unsigned char>(&s)[nP + 1] = s_;
    for (int p = 1; p <= nP; ++p)
      if (s[p].size() < (size_t)BL) s[p].resize((size_t)BL);

#ifdef AG_PROFILE
    uint64_t _tp_hg0 = agmpc_now_ns();
#endif
    // 1. F_Zero (nP > 2), the zero-sharing that blinds every row's phi, plus u for the
    //    check (bound by the batched RLC).
    if constexpr (nP > 2) {
      if (z_.size() < (size_t)BL + 1) z_.resize((size_t)BL + 1);
      std::fill(z_.begin(), z_.begin() + BL + 1, zero_block);   // fzero_xor XOR-accumulates
      fzero_xor<nP>(mesh_.io, prg_, pool, party_, z_.data(), BL + 1, fzero_);
      alpha_u_ = z_[(size_t)BL];
    }
    // phi, the half-gate row's blind: the F_Zero share (nP > 2), the (sel & Delta) term
    // and the cross-peer key/mac sum of b. A cheap local expression over resident row
    // material, so each use recomputes it instead of retaining B*L extra blocks.
    auto phi = [this, any_peer](const TripleRow<nP> &r, int k, size_t flat) -> block {
      block p = select_mask[getLSB(r.mac[1][any_peer][k])] & Delta_;
      if constexpr (nP > 2) p = p ^ z_[flat];
      for (int j = 1; j <= nP; ++j) if (j != party_) p = p ^ r.key[1][j][k] ^ r.mac[1][j][k];
      return p;
    };

    // 2. Once all COT material is fixed, snapshot one transcript root per peer and
    //    RO-expand it by the public batch shape and row index. Each row restarts
    //    MITCCRH's gid, so the row separation is load-bearing.
    std::vector<block> seed((size_t)(nP + 1) * B, zero_block);
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
      const block root = fs_coin_pair_group<nP>(
          mesh_.io, mesh_.grp, peer, "AGMPC laand batch seed", sid_);
      for (int k = 0; k < B; ++k)
        seed[(size_t)peer * B + k] =
            RO("emp-ag:laand-layer-seed", sid_)
                .absorb(root)
                .absorb((uint64_t)B)
                .absorb((uint64_t)L)
                .absorb((uint64_t)k)
                .squeeze_block();
    }

    // Where the receivers write: at nP == 2 the whole value T's bit window (the peer's
    // term and the local ones), at nP > 2 each peer's term's window, combined below.
    if constexpr (nP == 2) {
      if (window_.size() < (size_t)BL * gb) window_.resize((size_t)BL * gb);
    } else {
      for (int p = 1; p <= nP; ++p)
        if (p != party_ && win_[p].size() < (size_t)BL * gb) win_[p].resize((size_t)BL * gb);
    }

#ifdef AG_PROFILE
    int64_t _phi0 = mesh_.io->count();
#endif
    // 3. One flight: one task per (peer, lane, direction) walks every row in canonical
    //    order (peer-major, lanes 0..T-1, direction-adjacent). Do not enqueue per-row
    //    tasks on one NetIO: their writes could interleave. The lane id domain-separates
    //    the CCR key in the free low 64 bits: key = seed ^ makeBlock(0, lane), and each
    //    row has its own seed.
    const int hg_chunk = ag::kLaandRowChunkRows;
    const int T = std::min(mesh_.lanes, std::max(1, L));
    vector<future<void>> tasks;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_)
      for (int lane = 0; lane < T; ++lane) {
        auto [lo, hi] = ag::lane_range(lane, L, T);
        NetIOMP<nP> *ch = mesh_.mesh(lane);
        // Sender: row = H(K) ^ H(K ^ Delta) ^ phi on its key of peer's a, low gw bits.
        tasks.push_back(pool->enqueue([&, ch, peer, lane, lo, hi]() {
          const int len = hi - lo;
          std::vector<unsigned char> gbuf((size_t)std::min(hg_chunk, len) * gb);
          std::vector<unsigned char> packed(ag::laand_row_wire_bytes(std::min(hg_chunk, len), gw));
          block pad[16];
          for (int layer = 0; layer < B; ++layer) {
            const TripleRow<nP> &r = rows[(size_t)layer];
            MITCCRH<> mitc;
            mitc.setS(seed[(size_t)peer * B + layer] ^ makeBlock(0, (uint64_t)lane));
            for (int st = lo; st < hi; st += hg_chunk) {
              const int ed = std::min(st + hg_chunk, hi);
              for (int k0 = st; k0 < ed; k0 += 8) {
                const int batch = std::min(8, ed - k0);
                for (int j = 0; j < 8; ++j) {
                  const block kk = (j < batch) ? r.key[0][peer][k0 + j] : zero_block;
                  pad[2 * j] = kk;
                  pad[2 * j + 1] = kk ^ Delta_;
                }
                mitc.hash_cir<8, 2>(pad);
                for (int j = 0; j < batch; ++j) {
                  const int k = k0 + j;
                  const block row =
                      pad[2 * j] ^ pad[2 * j + 1] ^ phi(r, k, (size_t)layer * L + k);
                  memcpy(gbuf.data() + (size_t)(k0 + j - st) * gb, &row, gb);
                }
              }
#ifdef EMP_AG_TEST_FLIP_LAAND
              // TEST-ONLY (never in production), nP > 2: a malicious party 2 flips bit 0 of
              // EVERY leaky-AND row it ships to party 1, so P1's values diverge. The
              // leaky-AND check (the batched windowed-alpha RLC) must abort during
              // preprocessing. Every row, because P1 folds a row in only when its own
              // selector bit for that AND is 1: a single faulty row is masked away half the
              // time, while with every row faulty the fault stays hidden only if all B*L of
              // P1's selectors are 0. Only ONE sender flips: P1 folds every sender's row
              // under the same selector bit, so if all nP-1 senders flipped, the copies
              // would cancel whenever nP-1 is even (nP = 3 here), a false negative.
              if constexpr (nP > 2)
                if (party_ == 2 && peer == 1)
                  for (int q = 0; q < ed - st; ++q) gbuf[(size_t)q * gb] ^= 0x1;
#endif
              ag::pack_laand_rows(packed.data(), gbuf.data(), ed - st, gw);
              ch->send_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
            }
          }
          ch->flush(peer);
        }));
        // Receiver: hash [mac, key] -> HM, HK on its MAC on its own a toward peer, and
        // write the peer's term HK ^ HM ^ (row & sel) ^ key[c] ^ mac[c]; at nP == 2 also
        // the local terms, giving the whole value.
        tasks.push_back(pool->enqueue([&, ch, peer, lane, lo, hi]() {
          const int len = hi - lo;
          std::vector<unsigned char> gbuf((size_t)std::min(hg_chunk, len) * gb);
          std::vector<unsigned char> packed(ag::laand_row_wire_bytes(std::min(hg_chunk, len), gw));
          BlockVec wire(std::min(hg_chunk, len));
          block pad[16];
          unsigned char *out = (nP == 2) ? window_.data() : win_[peer].data();
          for (int layer = 0; layer < B; ++layer) {
            const TripleRow<nP> &r = rows[(size_t)layer];
            MITCCRH<> mitc;
            mitc.setS(seed[(size_t)peer * B + layer] ^ makeBlock(0, (uint64_t)lane));
            for (int st = lo; st < hi; st += hg_chunk) {
              const int ed = std::min(st + hg_chunk, hi);
              ch->recv_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
              expecting(ag::unpack_laand_rows(gbuf.data(), packed.data(), ed - st, gw),
                        "LaAND row has nonzero padding");
              for (int q = 0; q < ed - st; ++q) {
                wire[q] = zero_block;
                memcpy(&wire[q], gbuf.data() + (size_t)q * gb, gb);
              }
              for (int k0 = st; k0 < ed; k0 += 8) {
                const int batch = std::min(8, ed - k0);
                for (int j = 0; j < 8; ++j) {
                  pad[2 * j] = (j < batch) ? r.mac[0][peer][k0 + j] : zero_block;   // -> H(M)
                  pad[2 * j + 1] = (j < batch) ? r.key[0][peer][k0 + j] : zero_block;  // -> H(K)
                }
                mitc.hash_cir<8, 2>(pad);
                for (int j = 0; j < batch; ++j) {
                  const int k = k0 + j;
                  const size_t flat = (size_t)layer * L + k;
                  const block E =
                      pad[2 * j] ^ (wire[k - st] & select_mask[getLSB(r.mac[0][any_peer][k])]);
                  block value = pad[2 * j + 1] ^ E ^ r.key[2][peer][k] ^ r.mac[2][peer][k];
                  if constexpr (nP == 2) {
                    value ^= phi(r, k, flat) & select_mask[getLSB(r.mac[0][any_peer][k])];
                    value ^= Delta_ & select_mask[getLSB(r.mac[2][any_peer][k])];
#ifdef EMP_AG_TEST_FLIP_LAAND
                    // Deterministically corrupt ONE late-row receiver value.
                    // Flipping a shipped row is masked away when its random selector
                    // is zero, which makes an ell==1 adversarial test probabilistic.
                    if (layer == B - 1 && k == 0 && party_ == 1 && lane == 0)
                      value ^= bit0_mask;
#endif
#ifdef EMP_AG_TEST_FLIP_LAAND_HIGH
                    // TEST-ONLY: the partial last byte must remain covered by F_eq.
                    if (layer == B - 1 && k == 0 && party_ == 1 && lane == 0) {
                      unsigned char fault[sizeof(block)] = {};
                      fault[(gw - 1) / 8] = 1u << ((gw - 1) % 8);
                      block delta;
                      memcpy(&delta, fault, sizeof(delta));
                      value ^= delta;
                    }
#endif
                    s[party_][flat] = LSB1(value);
                  }
                  memcpy(out + flat * gb, &value, gb);
                }
              }
            }
          }
        }));
      }
    joinNclean(tasks);   // every lane's send+recv joined before the s flight
#ifdef AG_PROFILE
    g_ag_phi_bytes += (uint64_t)(mesh_.io->count() - _phi0);
#endif

    // nP > 2: combine the peers' terms with the local ones into each value's window, the
    //   RLC's check input, and take its s-bit.
    if constexpr (nP > 2) {
      alpha_masked_cat_.resize((size_t)BL);
      for (int layer = 0; layer < B; ++layer) {
        const TripleRow<nP> &r = rows[(size_t)layer];
        ag::parallel_for(pool, L, [&, layer](int lo, int hi) {
          for (int k = lo; k < hi; ++k) {
            const size_t flat = (size_t)layer * L + k;
            block t = zero_block;
            for (int p = 1; p <= nP; ++p) if (p != party_) {
              block w = zero_block;
              memcpy(&w, win_[p].data() + flat * gb, gb);
              t = t ^ w;
            }
            t = t ^ (phi(r, k, flat) & select_mask[getLSB(r.mac[0][any_peer][k])]);
            t = t ^ (Delta_ & select_mask[getLSB(r.mac[2][any_peer][k])]);
            t = t & window_mask;
            s[party_][flat] = LSB1(t);
            alpha_masked_cat_[flat] = t;
          }
        });
      }
#ifdef EMP_AG_TEST_FLIP_LAAND_HIGH
      // TEST-ONLY: corrupt the highest retained coordinate of exactly one local check
      // input, after its s-bit is taken. Unlike a shipped-row fault, no selector masks it.
      if (party_ == 1 && BL > 0) {
        unsigned char fault[sizeof(block)] = {};
        fault[(gw - 1) / 8] = 1u << ((gw - 1) % 8);
        block delta;
        memcpy(&delta, fault, sizeof(delta));
        alpha_masked_cat_[0] ^= delta;
      }
#endif
    }
#ifdef AG_PROFILE
    g_ag_tp_hg_ns += agmpc_now_ns() - _tp_hg0;
    uint64_t _tp_so0 = agmpc_now_ns();
#endif

    // 4. One flight: every row's s vector.
    mesh_.fan_out(BL,
      [this, &s](NetIOMP<nP> *ch, int dst, int lo, int hi) {
        ch->send_bool(dst, (const bool *)(s[party_].data() + lo), hi - lo);
        ch->flush(dst);
      },
      [&s](NetIOMP<nP> *ch, int src, int lo, int hi) {
        ch->recv_bool(src, (bool *)(s[src].data() + lo), hi - lo);
      });
#ifdef AG_PROFILE
    g_ag_tp_sopen_ns += agmpc_now_ns() - _tp_so0;
    uint64_t _tp_ac0 = agmpc_now_ns();
#endif

    // 5. Per row, the d-combine: d = XOR_p s_p turns r into c (party 1 moves its share,
    //    everyone else its key on party 1's share) and corrects the check input by
    //    d * Delta; then the check material: at nP == 2 the row's window folds into F_eq
    //    (binding exactly the transmitted bit window, after the correction).
    const block dxor = Delta_ ^ bit0_mask;
    unsigned char delta_bytes[sizeof(block)];
    memcpy(delta_bytes, &Delta_, sizeof(block));
    for (int layer = 0; layer < B; ++layer) {
      const TripleRow<nP> &r = rows[(size_t)layer];
      unsigned char *window = (nP == 2) ? window_.data() + (size_t)layer * L * gb : nullptr;
      ag::parallel_for(pool, L, [&, layer, window](int lo, int hi) {
        for (int k = lo; k < hi; ++k) {
          const size_t flat = (size_t)layer * L + k;
          unsigned char d = 0;
          for (int p = 1; p <= nP; ++p) d ^= s[p][flat];
          if (d) {
            if (party_ == 1) {
              for (int j = 2; j <= nP; ++j) r.mac[2][j][k] ^= bit0_mask;
            } else {
              r.key[2][1][k] ^= dxor;
            }
            if constexpr (nP == 2) {
              for (int j = 0; j < gb; ++j) window[(size_t)k * gb + j] ^= delta_bytes[j];
            } else {
              alpha_masked_cat_[flat] = alpha_masked_cat_[flat] ^ (Delta_ & window_mask);
            }
          }
          if constexpr (nP == 2)
            window[(size_t)(k + 1) * gb - 1] &= ag::laand_last_byte_mask(gw);
        }
      });
      if constexpr (nP == 2) ag::accumulate_leaky_and_window_bytes(feq, window, L, gb, pool);
    }
    (void)feq;
#ifdef AG_PROFILE
    g_ag_tp_acheck_ns += agmpc_now_ns() - _tp_ac0;
#endif
  }

  // nP == 2: the F_eq commitment over the call's rows. The caller sends .commitment with
  // its next flight and receives the peer's into .peer_commitment.
  FeqSymmetric2PC feq_commit(FsHash &feq) {
    char Dme[FsHash::DIGEST_SIZE];
    feq.digest(Dme);
    return feq_prepare_symmetric_2pc(prg_, sid_, "emp-ag:laand", party_, Dme);
  }

  // The check over every row of the call. nP>=3: ONE batched RLC zero-sum over all rows'
  // stashed windowed alpha vectors, its challenge phi_cat continuing `prg` (the stream the
  // rotations were drawn from, so it rides the same post-commitment coin). nP==2: the
  // terminal F_eq.
  void finish_check(PRG &prg, const FeqSymmetric2PC &feq2) {
    const int party = party_;
    if constexpr (nP >= 3) {
      ThreadPool *pool = mesh_.pool;
      NetIOMP<nP> *io = mesh_.io;
      const int BL = (int)alpha_masked_cat_.size();   // = B * L
      BlockVec &phi_cat = phi_cat_;
      if (phi_cat.size() < (size_t)BL) phi_cat.resize((size_t)BL);
      prg.random_block(phi_cat.data(), BL);
      BlockVec ip[nP + 1];
      for (int i = 0; i <= nP; ++i) ip[i].resize(2);
      // Batched-RLC inner product over all B*L stashed alpha vectors.
      // Split into partial (lo,hi) sums and XOR-combine: GF(2^128) addition is
      // XOR and the product sum has no reduction here, so the split is
      // byte-identical to the sequential inner product.
      {
        const int W = std::max(1, (int)pool->size());
        const int width = (BL + W - 1) / W;
        std::vector<block> acc_lo(W, zero_block), acc_hi(W, zero_block);
        vector<future<void>> rres;
        int t = 0;
        for (int a = 0; a < BL; a += width, ++t) {
          const int b = std::min(a + width, BL);
          rres.push_back(pool->enqueue([&, a, b, t]() {
            block part[2];
            vector_inn_prdt_sum_no_red(part, phi_cat.data() + a,
                                       alpha_masked_cat_.data() + a, b - a);
            acc_lo[t] = part[0];
            acc_hi[t] = part[1];
          }));
        }
        joinNclean(rres);
        ip[party][0] = zero_block;
        ip[party][1] = zero_block;
        for (int w = 0; w < t; ++w) {
          ip[party][0] = ip[party][0] ^ acc_lo[w];
          ip[party][1] = ip[party][1] ^ acc_hi[w];
        }
      }
      ip[party][0] = ip[party][0] ^ alpha_u_;   // the call's F_Zero u
      char dgst[nP + 1][FsHash::DIGEST_SIZE];
      role_bound_commitment(dgst[party], sid_,
                            "emp-ag:laand-alpha", party,
                            ip[party].data(), sizeof(block) * 2);
      vector<future<void>> ares;
      for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
        ares.push_back(pool->enqueue([io, &dgst, peer, party]() {
          io->send_data(peer, dgst[party], FsHash::DIGEST_SIZE);
          io->flush(peer);
        }));
        ares.push_back(pool->enqueue([io, &dgst, peer]() {
          io->recv_data(peer, dgst[peer], FsHash::DIGEST_SIZE);
        }));
      }
      joinNclean(ares);
      char view_digest[FsHash::DIGEST_SIZE];
      FsHash::hash_once(view_digest, dgst[1], nP * FsHash::DIGEST_SIZE);
      char peer_view[nP + 1][FsHash::DIGEST_SIZE];
      vector<future<bool>> ares2;
      for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
        ares.push_back(pool->enqueue([io, &ip, &view_digest, peer, party]() {
          io->send_data(peer, ip[party].data(), sizeof(block) * 2);
          io->send_data(peer, view_digest, FsHash::DIGEST_SIZE);
          io->flush(peer);
        }));
        ares2.push_back(pool->enqueue(
            [this, io, &ip, &dgst, &peer_view, &view_digest, peer]() -> bool {
          io->recv_data(peer, ip[peer].data(), sizeof(block) * 2);
          io->recv_data(peer, peer_view[peer], FsHash::DIGEST_SIZE);
          char chk[FsHash::DIGEST_SIZE];
          role_bound_commitment(chk, sid_,
                                "emp-ag:laand-alpha", peer,
                                ip[peer].data(), sizeof(block) * 2);
          return memcmp(chk, dgst[peer], FsHash::DIGEST_SIZE) != 0 ||
                 memcmp(view_digest, peer_view[peer],
                        FsHash::DIGEST_SIZE) != 0;
        }));
      }
      joinNclean(ares);
      expecting(!joinNcleanCheat(ares2), "LaAND alpha: commit-open mismatch");
      for (int i = 2; i <= nP; ++i)
        xorBlocks_arr(ip[1].data(), ip[1].data(), ip[i].data(), 2);
      expecting(cmpBlock(&ip[1][0], &zero_block, 1) &&
                cmpBlock(&ip[1][1], &zero_block, 1),
                "LaAND alpha: Sigma alpha != 0");
    }
    if constexpr (nP == 2) {
      (void)prg;
      const int any_peer = (party == 1) ? 2 : 1;
      feq_finish_symmetric_2pc(
          mesh_.send_ch(any_peer), mesh_.recv_ch(any_peer), sid_,
          "emp-ag:laand", party, feq2,
          "AGMPC LaAND F_eq: leaky-AND check failed");
    }
  }

private:
  LaneMesh<nP> mesh_;
  int party_;
  int ssp_;
  block sid_;
  block Delta_;
  PRG *prg_;
  // The batched alpha-check stash (nP>=3): every row's windowed RLC vector and the call's
  // F_Zero u; cleared by begin_call().
  BlockVec alpha_masked_cat_;
  block alpha_u_ = zero_block;
  // Reused per-call scratch (grow-only). All assigned before read except z_
  // (XOR-accumulated by fzero_xor -> re-zeroed via std::fill each call).
  BlockVec z_, phi_cat_;                  // nP > 2: F_Zero's z and u; the RLC challenge
  std::vector<unsigned char> s_[nP + 1];   // every party's s-bits, as sent
  std::vector<unsigned char> window_;      // nP == 2: every value's bit window
  std::vector<unsigned char> win_[nP + 1]; // nP > 2: each peer's term's bit window
  BlockVec fzero_;                         // fzero_xor contribution scratch
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_TRIPLE_LAAND_H__
