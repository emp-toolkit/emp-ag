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
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

// The b operand of a row's candidate k toward peer p, as the leaky AND reads it: its MAC
// and its key. Only phi, a linear blind, reads b. RowB reads the row's own b; a protocol
// whose b is computed, say a public linear map of fewer authenticated bits, passes a reader
// of its own to produce_rows. Such a reader may also offer
//   void read_run(const TripleRow<nP> &r, int layer, int64_t k0, int n, int p,
//                 block *mac, block *key) const;
// b's MACs and keys at candidates k0 .. k0 + n - 1 in one call, which the one-lane 2PC
// path (rows_2pc_) uses in place of n calls of each.
template <int nP>
struct RowB {
  block mac(const TripleRow<nP> &r, int /*layer*/, int64_t k, int p) const { return r.mac[1][p][k]; }
  block key(const TripleRow<nP> &r, int /*layer*/, int64_t k, int p) const { return r.key[1][p][k]; }
};

// The leaky ANDs of one session: one schedule for every nP (produce_rows), the check over
// a call's rows, and their reused scratch. `prg` is the calling protocol's (F_Zero's seeds,
// the F_eq nonce). The rows carry `window_bits` bits of each value, ssp + 2 by default
// (laand_window.h); more widen the check, and fewer than ssp + 2 are refused.
template <int nP>
class LeakyAnd {
public:
  LeakyAnd(const LaneMesh<nP> &mesh, int ssp, block session_id, block Delta, PRG *prg,
           int window_bits = 0)
      : mesh_(mesh), party_(mesh.party), sid_(session_id), Delta_(Delta),
        prg_(prg), gw_(window_bits ? window_bits : ag::laand_window_bits(ssp)),
        gb_((gw_ + 7) / 8), window_mask_(ag::laand_bits_mask(gw_)) {
    expecting(gw_ >= ag::laand_window_bits(ssp) && gw_ <= 128,
              "leaky ANDs: the row window must keep ssp + 2 bits and fit a block");
  }

  // A new call: no row's check material yet.
  void begin_call() {
    alpha_masked_cat_.clear();
    alpha_u_ = zero_block;
  }

  // Bytes a caller adds to the rows flight and to the s-bit flight on mesh 0, and where
  // the peer's land (nP == 2 only: one peer). LeakyAndPrep's bucket coin rides here, its
  // commitments with the rows and its openings with the s-bits.
  struct Carry {
    const void *rows_out = nullptr;
    void *rows_in = nullptr;
    size_t rows_len = 0;
    const void *s_out = nullptr;
    void *s_in = nullptr;
    size_t s_len = 0;
  };

  // The half-gate leaky AND on every row of a call, B rows of L candidates (a, b, r) whose
  // COTs are all fixed. On return each row's r has been folded into c = a AND b in place,
  // and the rows' check material is accumulated; finish_check() runs the check.
  //   1. nP > 2: one F_Zero for every row: z, one block per candidate, blinds phi, and u
  //      the check.
  //   2. One transcript root per peer, RO-expanded by the batch shape and row index into
  //      each row's hash-stream seed.
  //   3. One flight: every row's half-gate rows to every peer, one sender and one receiver
  //      task per (peer, lane) walking the rows in order; carry's rows bytes on mesh 0.
  //   4. One flight: every row's s-bits; carry's s bytes on mesh 0.
  //   5. Per row, the d-combine and the check material: the F_eq window fold at nP == 2,
  //      the windowed values for the RLC at nP > 2.
  // `bread` reads each row's b operand (RowB above). roots[peer], when given, replaces the
  // transcript root of the hash streams shared with peer (step 2): a coin both ends hold,
  // drawn after every row's COTs are fixed.
  template <class BRead = RowB<nP>>
  void produce_rows(const std::vector<TripleRow<nP>> &rows, int L, FsHash &feq,
                    const Carry &carry = {}, const BRead &bread = {},
                    const block *roots = nullptr) {
    expecting(nP == 2 || (carry.rows_len == 0 && carry.s_len == 0),
              "leaky ANDs: carried bytes are for nP == 2");
    ThreadPool *pool = mesh_.pool;
    const int B = (int)rows.size();
    const int BL = B * L;
    const int any_peer = (party_ == 1) ? 2 : 1;
    const int gb = gb_;
    const int gw = gw_;
    [[maybe_unused]] const block window_mask = window_mask_;
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
    auto phi = [this, any_peer, &bread](const TripleRow<nP> &r, int layer, int k,
                                        size_t flat) -> block {
      block p = select_mask[getLSB(bread.mac(r, layer, k, any_peer))] & Delta_;
      if constexpr (nP > 2) p = p ^ z_[flat];
      for (int j = 1; j <= nP; ++j)
        if (j != party_) p = p ^ bread.key(r, layer, k, j) ^ bread.mac(r, layer, k, j);
      return p;
    };

    // 2. Once all COT material is fixed, snapshot one transcript root per peer and
    //    RO-expand it by the public batch shape and row index. Each row restarts
    //    MITCCRH's gid, so the row separation is load-bearing.
    std::vector<block> seed((size_t)(nP + 1) * B, zero_block);
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
      const block root = roots != nullptr
          ? roots[peer]
          : fs_coin_pair_group<nP>(mesh_.io, mesh_.grp, peer, "AGMPC laand batch seed", sid_);
      for (int k = 0; k < B; ++k)
        seed[(size_t)peer * B + k] =
            RO("emp-ag:laand-layer-seed", sid_)
                .absorb(root)
                .absorb((uint64_t)B)
                .absorb((uint64_t)L)
                .absorb((uint64_t)k)
                .squeeze_block();
    }

    // One lane at nP == 2 with rows narrower than a word: steps 3 and 5 run as
    // rows_2pc_ and check_2pc_ below, on this thread. Every other shape takes the
    // general tasks.
    const int T = std::min(mesh_.lanes, std::max(1, L));
    bool two_pc = false;
    if constexpr (nP == 2) two_pc = T == 1 && ag::laand_word_rows(gw);

    // Where the receivers write: at nP == 2 the whole value T's bit window (the peer's
    // term and the local ones), at nP > 2 each peer's term's window, combined below.
    // rows_2pc_ writes each window as one word: 8 bytes of slack after the last.
    if constexpr (nP == 2) {
      const size_t need = (size_t)BL * gb + (two_pc ? 8 : 0);
      if (window_.size() < need) window_.resize(need);
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
    //    row has its own seed. rows_2pc_ is the same flight as one pass on this thread.
    if constexpr (nP == 2) {
      if (two_pc) rows_2pc_(rows, L, carry, bread, seed);
    }
    const int hg_chunk = ag::kLaandRowChunkRows;
    vector<future<void>> tasks;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_ && !two_pc)
      for (int lane = 0; lane < T; ++lane) {
        auto [lo, hi] = ag::lane_range(lane, L, T);
        NetIOMP<nP> *ch = mesh_.mesh(lane);
        // Sender: row = H(K) ^ H(K ^ Delta) ^ phi on its key of peer's a, low gw bits.
        tasks.push_back(pool->enqueue([&, ch, peer, lane, lo, hi]() {
          const int len = hi - lo;
          BlockVec rowbuf(std::min(hg_chunk, len));
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
                  rowbuf[k - st] =
                      pad[2 * j] ^ pad[2 * j + 1] ^ phi(r, layer, k, (size_t)layer * L + k);
                }
              }
              if constexpr (kTestHooks && nP > 2) {
                // TEST-ONLY (hook flip_laand), nP > 2: a malicious party 2 flips bit 0 of
                // EVERY leaky-AND row it ships to party 1, so P1's values diverge. The
                // leaky-AND check (the batched windowed-alpha RLC) must abort during
                // preprocessing. Every row, because P1 folds a row in only when its own
                // selector bit for that AND is 1: a single faulty row is masked away half
                // the time, while with every row faulty the fault stays hidden only if all
                // B*L of P1's selectors are 0. Only ONE sender flips: P1 folds every
                // sender's row under the same selector bit, so if all nP-1 senders flipped,
                // the copies would cancel whenever nP-1 is even (nP = 3 here), a false
                // negative.
                if (hooks().flip_laand && party_ == 2 && peer == 1)
                  for (int q = 0; q < ed - st; ++q) rowbuf[q] = rowbuf[q] ^ bit0_mask;
              }
              ag::pack_laand_blocks(packed.data(), rowbuf.data(), ed - st, gw);
              ch->send_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
            }
          }
          if (lane == 0 && carry.rows_len > 0)
            ch->send_data(peer, carry.rows_out, carry.rows_len);
          ch->flush(peer);
        }));
        // Receiver: hash [mac, key] -> HM, HK on its MAC on its own a toward peer, and
        // write the peer's term HK ^ HM ^ (row & sel) ^ key[c] ^ mac[c]; at nP == 2 also
        // the local terms, giving the whole value.
        tasks.push_back(pool->enqueue([&, ch, peer, lane, lo, hi]() {
          const int len = hi - lo;
          // TEST-ONLY: the receiver-value hooks below, read once outside the loop.
          [[maybe_unused]] bool flip_value = false, flip_high = false;
          if constexpr (kTestHooks) {
            flip_value = hooks().flip_laand && party_ == 1 && lane == 0;
            flip_high = hooks().flip_laand_high && party_ == 1 && lane == 0;
          }
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
              expecting(ag::unpack_laand_blocks(wire.data(), packed.data(), ed - st, gw),
                        "LaAND row has nonzero padding");
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
                    value ^= phi(r, layer, k, flat) & select_mask[getLSB(r.mac[0][any_peer][k])];
                    value ^= Delta_ & select_mask[getLSB(r.mac[2][any_peer][k])];
                    if constexpr (kTestHooks) {
                      if ((flip_value || flip_high) && layer == B - 1 && k == 0) {
                        // TEST-ONLY (hook flip_laand): deterministically corrupt ONE
                        // late-row receiver value. Flipping a shipped row is masked away
                        // when its random selector is zero, which makes an ell==1
                        // adversarial test probabilistic.
                        if (flip_value) value ^= bit0_mask;
                        // TEST-ONLY (hook flip_laand_high): the partial last byte must
                        // remain covered by F_eq.
                        if (flip_high) {
                          unsigned char fault[sizeof(block)] = {};
                          fault[(gw - 1) / 8] = 1u << ((gw - 1) % 8);
                          block delta;
                          memcpy(&delta, fault, sizeof(delta));
                          value ^= delta;
                        }
                      }
                    }
                    s[party_][flat] = LSB1(value);
                  }
                  memcpy(out + flat * gb, &value, gb);
                }
              }
            }
          }
          if (lane == 0 && carry.rows_len > 0)
            ch->recv_data(peer, carry.rows_in, carry.rows_len);
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
            t = t ^ (phi(r, layer, k, flat) & select_mask[getLSB(r.mac[0][any_peer][k])]);
            t = t ^ (Delta_ & select_mask[getLSB(r.mac[2][any_peer][k])]);
            t = t & window_mask;
            s[party_][flat] = LSB1(t);
            alpha_masked_cat_[flat] = t;
          }
        });
      }
      if constexpr (kTestHooks) {
        // TEST-ONLY (hook flip_laand_high): corrupt the highest retained coordinate of
        // exactly one local check input, after its s-bit is taken. Unlike a shipped-row
        // fault, no selector masks it.
        if (hooks().flip_laand_high && party_ == 1 && BL > 0) {
          unsigned char fault[sizeof(block)] = {};
          fault[(gw - 1) / 8] = 1u << ((gw - 1) % 8);
          block delta;
          memcpy(&delta, fault, sizeof(delta));
          alpha_masked_cat_[0] ^= delta;
        }
      }
    }
#ifdef AG_PROFILE
    g_ag_tp_hg_ns += agmpc_now_ns() - _tp_hg0;
    uint64_t _tp_so0 = agmpc_now_ns();
#endif

    // 4. One flight: every row's s vector.
    mesh_.fan_out(BL,
      [this, &s, &carry](NetIOMP<nP> *ch, int dst, int lo, int hi) {
        ch->send_bool(dst, (const bool *)(s[party_].data() + lo), hi - lo);
        if (ch == mesh_.io && carry.s_len > 0) ch->send_data(dst, carry.s_out, carry.s_len);
        ch->flush(dst);
      },
      [this, &s, &carry](NetIOMP<nP> *ch, int src, int lo, int hi) {
        ch->recv_bool(src, (bool *)(s[src].data() + lo), hi - lo);
        if (ch == mesh_.io && carry.s_len > 0) ch->recv_data(src, carry.s_in, carry.s_len);
      });
#ifdef AG_PROFILE
    g_ag_tp_sopen_ns += agmpc_now_ns() - _tp_so0;
    uint64_t _tp_ac0 = agmpc_now_ns();
#endif

    // 5. Per row, the d-combine: d = XOR_p s_p turns r into c (party 1 moves its share,
    //    everyone else its key on party 1's share) and corrects the check input by
    //    d * Delta; then the check material: at nP == 2 the row's window folds into F_eq
    //    (binding exactly the transmitted bit window, after the correction).
    if constexpr (nP == 2) {
      if (two_pc) check_2pc_(rows, L, feq);
    }
    unsigned char delta_bytes[sizeof(block)];
    memcpy(delta_bytes, &Delta_, sizeof(block));
    for (int layer = 0; layer < B && !two_pc; ++layer) {
      const TripleRow<nP> &r = rows[(size_t)layer];
      unsigned char *window = (nP == 2) ? window_.data() + (size_t)layer * L * gb : nullptr;
      ag::parallel_for(pool, L, [&, layer, window](int lo, int hi) {
        for (int k = lo; k < hi; ++k) {
          const size_t flat = (size_t)layer * L + k;
          unsigned char d = 0;
          for (int p = 1; p <= nP; ++p) d ^= s[p][flat];
          if (d) {
            add_public_one<nP>(party_, Delta_,
                               [&](int p) -> block & { return r.mac[2][p][k]; },
                               [&](int p) -> block & { return r.key[2][p][k]; });
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

  // nP == 2: the same check when the caller carried the nonces on a flight of its own
  // (feq2.nonce out, the peer's nonce in), after both commitments were exchanged.
  void finish_check_2pc(const FeqSymmetric2PC &feq2, block peer_nonce) const {
    static_assert(nP == 2, "the carried F_eq opening is the two-party check");
    feq_check_symmetric_2pc(sid_, "emp-ag:laand", party_, feq2, peer_nonce,
                            "AGMPC LaAND F_eq: leaky-AND check failed");
  }

private:
  // b's MACs and keys at candidates k0 .. k0 + n - 1 of a layer toward p: one read_run
  // when the reader has it, else n reads of each.
  template <class BRead>
  static void read_b_(const BRead &bread, const TripleRow<nP> &r, int layer, int k0, int n,
                      int p, block *mac, block *key) {
    if constexpr (requires { bread.read_run(r, layer, (int64_t)k0, n, p, mac, key); }) {
      bread.read_run(r, layer, (int64_t)k0, n, p, mac, key);
    } else {
      for (int j = 0; j < n; ++j) {
        mac[j] = bread.mac(r, layer, (int64_t)k0 + j, p);
        key[j] = bread.key(r, layer, (int64_t)k0 + j, p);
      }
    }
  }

  // Candidates k0 .. k0 + n - 1 (n <= 8) of row r toward peer, nP == 2: one MITCCRH call
  // hashes K, K ^ Delta and M under each candidate's gid. row[j] is the half-gate row
  // the sender ships, H(K) ^ H(K ^ Delta) ^ phi. part[j] is the low word of the
  // receiver's value without its one term that reads the peer's row, (row & sel), and
  // sel[j] that selector, LSB(M):
  //   value = H(K) ^ H(M) ^ (row & sel) ^ key_c ^ mac_c ^ (phi & sel) ^ (Delta & LSB(mac_c)).
  template <class BRead>
  void half_gate8_(MITCCRH<> &mitc, const TripleRow<nP> &r, int layer, int k0, int n,
                   int peer, const BRead &bread, block row[8], uint64_t *part,
                   unsigned char *sel) const {
    block pad[24];
    unsigned char sa[8] = {};
    for (int j = 0; j < 8; ++j) {
      const block K = (j < n) ? r.key[0][peer][k0 + j] : zero_block;
      const block M = (j < n) ? r.mac[0][peer][k0 + j] : zero_block;
      pad[3 * j] = K;
      pad[3 * j + 1] = K ^ Delta_;
      pad[3 * j + 2] = M;
      sa[j] = getLSB(M);
    }
    mitc.hash_cir<8, 3>(pad);   // H(K), H(K ^ Delta), H(M)
    block bm[8], bk[8];
    read_b_(bread, r, layer, k0, n, peer, bm, bk);
    for (int j = 0; j < n; ++j) {
      const int k = k0 + j;
      const block phi = (select_mask[getLSB(bm[j])] & Delta_) ^ bk[j] ^ bm[j];
      row[j] = pad[3 * j] ^ pad[3 * j + 1] ^ phi;
      const block mac_c = r.mac[2][peer][k];
      const block v = pad[3 * j] ^ pad[3 * j + 2] ^ r.key[2][peer][k] ^ mac_c ^
                      (phi & select_mask[sa[j]]) ^ (Delta_ & select_mask[getLSB(mac_c)]);
      std::memcpy(&part[j], &v, sizeof(uint64_t));
      sel[j] = sa[j];
    }
  }

  // Step 3 at nP == 2 on one lane (T == 1), rows narrower than 64 bits: the sender and
  // receiver tasks as one pass on this thread. The general path's sender hashes
  // (K, K ^ Delta) and its receiver (M, K) under the same key and gids, so one call per
  // 8 candidates (half_gate8_) gives every hash they compute, H(K) once; phi is read and
  // computed once. Per chunk of kLaandFusedChunkRows candidates of a layer: the chunk's
  // rows are sent and each value's peer-free part kept; the peer's chunk is read one
  // chunk later, chunk c + 1 being sent before chunk c is read. So a chunk's transfer
  // overlaps the next chunk's work, and at most two chunks per direction are ever
  // unread, which default socket buffers hold: both parties sending at once cannot
  // deadlock. Chunks are whole wire bytes (laand_window.h), sent in the general path's
  // order, with the carried bytes after the last: the wire is unchanged byte for byte.
  template <class BRead>
  void rows_2pc_(const std::vector<TripleRow<nP>> &rows, int L, const Carry &carry,
                 const BRead &bread, const std::vector<block> &seed) {
    const int peer = (party_ == 1) ? 2 : 1;
    const int B = (int)rows.size();
    const int gw = gw_, gb = gb_;
    NetIOMP<nP> *ch = mesh_.mesh(0);
    constexpr int C = ag::kLaandFusedChunkRows;
    struct Chunk {
      int layer, st, ed;
    };
    std::vector<Chunk> chunks;
    for (int layer = 0; layer < B; ++layer)
      for (int st = 0; st < L; st += C) chunks.push_back({layer, st, std::min(st + C, L)});
    const int cap = std::min(C, std::max(L, 1));
    std::vector<unsigned char> out((size_t)ag::laand_row_wire_bytes(cap, gw)), in(out.size());
    std::vector<uint64_t> part[2] = {std::vector<uint64_t>(cap), std::vector<uint64_t>(cap)};
    std::vector<unsigned char> sel[2] = {std::vector<unsigned char>(cap),
                                         std::vector<unsigned char>(cap)};
    MITCCRH<> mitc;
    int mitc_layer = -1;
    // Chunk i's rows out; its parts and selectors kept in slot i % 2. The packer reads
    // rows in order, so each 8-candidate call runs as its first row is packed.
    auto send_chunk = [&](size_t i) {
      const Chunk &c = chunks[i];
      const TripleRow<nP> &r = rows[(size_t)c.layer];
      if (c.layer != mitc_layer) {   // the layer's hash stream from gid 0, lane 0
        mitc.setS(seed[(size_t)peer * B + c.layer] ^ makeBlock(0, 0));
        mitc_layer = c.layer;
      }
      uint64_t *pt = part[i & 1].data();
      unsigned char *sl = sel[i & 1].data();
      const int n = c.ed - c.st;
      block row[8];
      ag::pack_laand_words_(out.data(), n, gw, [&](int64_t q) -> uint64_t {
        if ((q & 7) == 0)
          half_gate8_(mitc, r, c.layer, c.st + (int)q, std::min(8, n - (int)q), peer, bread,
                      row, pt + q, sl + q);
        uint64_t v;
        std::memcpy(&v, &row[q & 7], sizeof(v));
        return v;
      });
      ch->send_data(peer, out.data(), ag::laand_row_wire_bytes(n, gw));
    };
    // The peer's chunk i completes its values: s-bits and windows.
    auto recv_chunk = [&](size_t i) {
      const Chunk &c = chunks[i];
      const int n = c.ed - c.st;
      const int64_t bytes = ag::laand_row_wire_bytes(n, gw);
      ch->recv_data(peer, in.data(), bytes);
      const int used = (int)(((int64_t)n * gw) % 8);
      expecting(used == 0 || (in[bytes - 1] >> used) == 0, "LaAND row has nonzero padding");
      const uint64_t *pt = part[i & 1].data();
      const unsigned char *sl = sel[i & 1].data();
      const size_t flat0 = (size_t)c.layer * L + c.st;
      unsigned char *win = window_.data() + flat0 * gb;
      unsigned char *sv = s_[party_].data() + flat0;
      const uint64_t wmask = (uint64_t(1) << gw) - 1;
      // TEST-ONLY: the receiver-value hooks below, read once outside the loop.
      [[maybe_unused]] bool flip_value = false, flip_high = false;
      if constexpr (kTestHooks) {
        flip_value = hooks().flip_laand && party_ == 1 && c.layer == B - 1 && c.st == 0;
        flip_high = hooks().flip_laand_high && party_ == 1 && c.layer == B - 1 && c.st == 0;
      }
      ag::unpack_laand_words_(in.data(), n, gw, [&](int64_t q, uint64_t w) {
        uint64_t v = pt[q] ^ (w & (uint64_t(0) - sl[q]));
        if constexpr (kTestHooks) {
          // TEST-ONLY (hooks flip_laand, flip_laand_high), as the general path: corrupt
          // the last layer's first receiver value, in bit 0 or in the window's top bit.
          if (q == 0) {
            if (flip_value) v ^= 1;
            if (flip_high) v ^= uint64_t(1) << (gw - 1);
          }
        }
        sv[q] = (unsigned char)((v >> 1) & 1);   // LSB1
        // The window, cut to its gw bits here rather than in step 5. Written as a word:
        // its bytes past gb land on the next window, which overwrites them.
        v &= wmask;
        std::memcpy(win + q * gb, &v, sizeof(v));
      });
    };
    if (!chunks.empty()) send_chunk(0);
    for (size_t i = 0; i < chunks.size(); ++i) {
      if (i + 1 < chunks.size()) send_chunk(i + 1);
      else if (carry.rows_len > 0) ch->send_data(peer, carry.rows_out, carry.rows_len);
      ch->flush(peer);
      recv_chunk(i);
    }
    if (chunks.empty()) {
      if (carry.rows_len > 0) ch->send_data(peer, carry.rows_out, carry.rows_len);
      ch->flush(peer);
    }
    if (carry.rows_len > 0) ch->recv_data(peer, carry.rows_in, carry.rows_len);
  }

  // Step 5 after rows_2pc_: the d-combine of each F_eq stripe inside the stripe's fold
  // task, so the stripe is hashed while cached. The windows are already cut to gw bits,
  // so d * Delta enters as one masked word, and adding the public 1 to c, one block per
  // AND at nP == 2 (party 1's MAC, party 2's key), as a masked XOR: no branch on d. A
  // window whose word would run past the stripe's end takes its gb bytes alone: the next
  // stripe may run concurrently.
  void check_2pc_(const std::vector<TripleRow<nP>> &rows, int L, FsHash &feq) {
    const int peer = (party_ == 1) ? 2 : 1;
    const int gb = gb_;
    uint64_t dwin;
    std::memcpy(&dwin, &Delta_, sizeof(dwin));
    dwin &= (uint64_t(1) << gw_) - 1;
    block one_mac = zero_block, one_key = zero_block;
    add_public_one<nP>(party_, Delta_, [&](int) -> block & { return one_mac; },
                       [&](int) -> block & { return one_key; });
    const bool on_mac = party_ == 1;
    const block one = on_mac ? one_mac : one_key;
    for (int layer = 0; layer < (int)rows.size(); ++layer) {
      const TripleRow<nP> &r = rows[(size_t)layer];
      block *c = on_mac ? r.mac[2][peer] : r.key[2][peer];
      unsigned char *window = window_.data() + (size_t)layer * L * gb;
      const unsigned char *s1 = s_[1].data() + (size_t)layer * L;
      const unsigned char *s2 = s_[2].data() + (size_t)layer * L;
      ag::accumulate_leaky_and_window_bytes(
          feq, window, L, gb, mesh_.pool, [c, window, s1, s2, one, dwin, gb](int k0, int k1) {
            // d at k: added to c[k]; returns d * Delta as k's window takes it.
            auto combine = [&](int k) -> uint64_t {
              const unsigned char d = s1[k] ^ s2[k];
              c[k] = c[k] ^ (one & select_mask[d]);
              return dwin & (uint64_t(0) - d);
            };
            const int whole =
                k0 + (int)std::max<int64_t>(0, ag::laand_rows_with_8_bytes(k1 - k0, gb));
            for (int k = k0; k < whole; ++k) {
              unsigned char *w = window + (size_t)k * gb;
              uint64_t v;
              std::memcpy(&v, w, sizeof(v));
              v ^= combine(k);
              std::memcpy(w, &v, sizeof(v));
            }
            for (int k = whole; k < k1; ++k) {
              unsigned char *w = window + (size_t)k * gb;
              uint64_t v = 0;
              std::memcpy(&v, w, (size_t)gb);
              v ^= combine(k);
              std::memcpy(w, &v, (size_t)gb);
            }
          });
    }
  }

  LaneMesh<nP> mesh_;
  int party_;
  block sid_;
  block Delta_;
  PRG *prg_;
  int gw_, gb_;           // the row window's bits and bytes
  block window_mask_;     // its bits within a block
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

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_TRIPLE_LAAND_H__
