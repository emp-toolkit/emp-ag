#ifndef EMP_AG_BACKEND_TRIPLE_LAAND_H__
#define EMP_AG_BACKEND_TRIPLE_LAAND_H__
//
// Pi_LaAND: leaky authenticated AND triples by the half-gate technique. A row of L
// candidates is laid out per peer as a = [0, L), b = [L, 2L), r = [2L, 3L); the leaky AND
// turns r into c = a AND b in place. The adversary may learn a through selective failure;
// b enters only the linear phi. Bucketing (triple/merge.h) removes the leakage on a.
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
//     each pair shares a lambda-bit seed, both expand into L+1 blocks via PRG and XOR them
//     into local (z^i, u^i). Each seed contributes to exactly two parties, so
//     Sigma_p z^p_k = 0 and Sigma_p u^p = 0 (common/fzero.h).
//
// (2) F_Com is collapsed to a single send for both d^i and alpha^i. No value derived from
//     the committed bits is sent before the matching open, so equivocation is impossible
//     and the commitment phase is redundant. alpha^i is hash-committed first (one round)
//     and then opened, since the alpha-check needs binding.
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

// Fold one row's L-vector into the running F_eq hash, restricted to the low `bits` bits
// of each element (the transmitted window), zero-padded locally to `gb` bytes. The fold
// is a fixed two-level hash: the window bytes are gathered and hashed per
// kFeqStripeElems-element stripe (independent stripes, so gather and hashing run
// pool-parallel), and the ordered stripe digests feed the running feq. Collision
// resistance composes across the levels, so this binds exactly the window bytes; both
// parties use the same stripe constant and derive the same stripe count from the common
// L. One terminal symmetric F_eq fires per call; the caller owns it.
inline void accumulate_leaky_and_window(FsHash &feq, const block *src, int L, int bits,
                                        std::vector<unsigned char> &scratch,
                                        ThreadPool *pool) {
  const int gb = (bits + 7) / 8;
  // Caller-owned grow-only scratch (a plain member, passed by ref -- no per-access
  // overhead): this runs B x per chunk, so a fresh L*gb buffer each
  // call is mmap/fault/munmap churn. Stripes write disjoint ranges.
  const size_t need = (size_t)L * gb;
  if (scratch.size() < need) scratch.resize(need);
  const int ns = (L + kFeqStripeElems - 1) / kFeqStripeElems;
  std::vector<char> dg((size_t)ns * FsHash::DIGEST_SIZE);
  vector<future<void>> res;
  for (int s = 0; s < ns; ++s) {
    res.push_back(pool->enqueue([&, s]() {
      const int k0 = s * kFeqStripeElems;
      const int k1 = std::min(L, k0 + kFeqStripeElems);
      unsigned char *dst = scratch.data() + (size_t)k0 * gb;
      for (int k = k0; k < k1; ++k) {
        memcpy(scratch.data() + (size_t)k * gb, &src[k], gb);
        scratch[(size_t)(k + 1) * gb - 1] &= laand_last_byte_mask(bits);
      }
      FsHash::hash_once(dg.data() + (size_t)s * FsHash::DIGEST_SIZE, dst,
                      (size_t)(k1 - k0) * gb);
    }));
  }
  joinNclean(res);
  feq.put(dg.data(), dg.size());
}

// Batched nP==2 production already keeps each zero-padded bit window contiguous, so
// preserve the exact same stripe-hash construction without gathering blocks
// through a second scratch buffer.
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

// The leaky ANDs of one session: the two schedules (produce_row at nP >= 3,
// produce_rows_2pc at nP == 2), the check over a call's rows, and their reused scratch.
// `prg` is the calling protocol's (F_Zero's seeds, the F_eq nonce).
template <int nP>
class LeakyAnd {
public:
  LeakyAnd(const LaneMesh<nP> &mesh, int ssp, block session_id, block Delta, PRG *prg)
      : mesh_(mesh), party_(mesh.party), ssp_(ssp), sid_(session_id), Delta_(Delta),
        prg_(prg) {}

  // A new call: no row's check material yet.
  void begin_call() {
    alpha_masked_cat_.clear();
    alpha_uzero_.clear();
  }

  // Multi-party half-gate leaky AND over one row of L candidates [a | b | r]. On return r
  // has been folded into c = a AND b in the same scratch region. This row's check material
  // is accumulated here; finish_check() runs the check over every row.
  void produce_row(BlockVec tMAC[nP + 1], BlockVec tKEY[nP + 1], int L, FsHash &feq) {
    // Per-row leaky-AND generator, generic in nP; the schedule calls it at nP>=3
    // (nP==2 runs produce_rows_2pc). FZero and the cross-party phi sum blind the
    // half-gate row, and every peer's row folds into tKEYphi[party] (the shared
    // result buffer) for the s-open, the d-combine, and the terminal-check
    // accumulation below.
    BlockVec(&tKEYphi)[nP + 1] = tKEYphi_;
    std::vector<unsigned char>(&s)[nP + 1] = s_;
    ThreadPool *pool = mesh_.pool;
    const int any_peer = (party_ == 1) ? 2 : 1;
    const int gb = ag::laand_window_bytes(ssp_);
    const int gw = ag::laand_window_bits(ssp_);
    block u_zero = zero_block;   // FZero blind (nP>2 only; bound by the batched check)
    for (int i = 0; i <= nP; ++i)
      if (s[i].size() < (size_t)L) s[i].resize((size_t)L);
    if (tKEYphi[party_].size() < (size_t)L) tKEYphi[party_].resize((size_t)L);

#ifdef AG_PROFILE
    uint64_t _tp_hg0 = agmpc_now_ns();
#endif
    // --- phi: the half-gate row correction (the blind C, generalized). At nP>2 it
    // starts from the FZero zero-share (carrying u_zero, bound by the batched check);
    // at nP==2 there is no FZero (z_u=0), so phi reduces to the bare local blind C. Then
    // add the (sel&Delta) term + the cross-peer key/mac sum (one peer at nP==2). ---
    BlockVec &phi = phi_;
    if (phi.size() < (size_t)L) phi.resize((size_t)L);
    if constexpr (nP > 2) {
      BlockVec &z_u = z_u_;
      if (z_u.size() < (size_t)(L + 1)) z_u.resize((size_t)(L + 1));
      std::fill(z_u.begin(), z_u.begin() + (L + 1), zero_block);  // fzero_xor XOR-accumulates
      fzero_xor<nP>(mesh_.io, prg_, pool, party_, z_u.data(), L + 1, fzero_);
      for (int k = 0; k < L; ++k) phi[k] = z_u[k];
      u_zero = z_u[L];
    } else {
      std::fill(phi.begin(), phi.begin() + L, zero_block);
    }
    int width = (L + pool->size() - 1) / pool->size();
    {
      vector<future<void>> res;
      for (int wi = 0; wi < (int)pool->size(); ++wi) {
        int st = wi * width, ed = std::min((wi + 1) * width, L);
        res.push_back(pool->enqueue([this, st, ed, L, any_peer, &tKEY, &tMAC, &phi]() {
          for (int k = st; k < ed; ++k) {
            phi[k] ^= (select_mask[getLSB(tMAC[any_peer][L + k])] & Delta_);
            for (int j = 1; j <= nP; ++j) if (j != party_) {
              phi[k] ^= tKEY[j][L + k];
              phi[k] ^= tMAC[j][L + k];
            }
          }
        }));
      }
      joinNclean(res);
    }

    // --- per-peer fused half-gate (MITCCRH hash_cir under the per-pair FS seed): one
    // peer at nP==2, n-1 in parallel at nP>2. The garbler ships row = H(key)^H(key^Delta)^phi
    // (low gw bits; F_eq / the windowed alpha check covers exactly that window). The
    // evaluator hashes [mac,key] -> HM,HK and folds the per-peer term HK ^ (HM ^ (w&sel))
    // ^ key[2L] ^ mac[2L] into tMACphi[peer]. ---
    BlockVec(&tMACphi)[nP + 1] = tMACphi_;
    for (int i = 1; i <= nP; ++i)
      if (i != party_ && tMACphi[i].size() < (size_t)L) tMACphi[i].resize((size_t)L);
    const int hg_chunk = ag::kLaandRowChunkRows;
#ifdef AG_PROFILE
    int64_t _phi0 = mesh_.io->count();
#endif
    {
      // Per-lane CCR key salt in the FREE low 64:
      // MITCCRH derives its AES key as start_point ^ makeBlock(gid>>ReuseShift, 0) -- the gid
      // COUNTER marches through the HIGH 64 bits of the key, the LOW 64 are always 0 (free).
      // So salt each lane's seed in that free low 64: setS(seed ^ makeBlock(0, lane)) => key =
      // seed ^ makeBlock(bucket, lane) -- counter in the high 64, lane in the low 64, a
      // DISJOINT field, unique per (lane, bucket), no key reuse. Blackbox, one call, no
      // gid-range constraint; lane 0 salts by 0. The AND-index range [0,L) is split into
      // T=min(lanes,L) contiguous slices; lane t transfers slice t on mesh t (lane 0 ==
      // mesh 0), assembling into the disjoint tMACphi range so the check folds on the full
      // [0,L). Only the bulk row bytes move; control-message flights stay on mesh 0, while
      // local FS challenges snapshot every lane transcript before deriving one shared seed.

      // Sender half-gate row transfer for AND-index range [lo,hi) under lane `lane`, on ch.
      auto laand_send = [this, &tKEY, &phi, hg_chunk, gb, gw](NetIOMP<nP> *ch, int peer, block seed, int lo, int hi, int lane) {
        MITCCRH<> mitc;
        mitc.setS(seed ^ makeBlock(0, (uint64_t)lane));   // lane in the free low 64 of the key
        block pad[16];
        const int len = hi - lo;
        std::vector<unsigned char> gbuf((size_t)std::min(hg_chunk, len) * gb);
        std::vector<unsigned char> packed(ag::laand_row_wire_bytes(std::min(hg_chunk, len), gw));
        for (int ci = 0; ci < (len + hg_chunk - 1) / hg_chunk; ++ci) {
          int st = lo + hg_chunk * ci, ed = std::min(lo + hg_chunk * (ci + 1), hi);
          for (int k0 = st; k0 < ed; k0 += 8) {
            int batch = std::min(8, ed - k0);
            for (int j = 0; j < 8; ++j) {
              block kk = (j < batch) ? tKEY[peer][k0 + j] : zero_block;
              pad[2 * j]     = kk;
              pad[2 * j + 1] = kk ^ Delta_;
            }
            mitc.hash_cir<8, 2>(pad);
            for (int j = 0; j < batch; ++j) {
              block row = pad[2 * j] ^ pad[2 * j + 1] ^ phi[k0 + j];   // full G row
              memcpy(gbuf.data() + (size_t)(k0 + j - st) * gb, &row, gb); // packed to gw bits below
            }
          }
#ifdef EMP_AG_TEST_FLIP_LAAND
          // TEST-ONLY (never in production): a malicious party 2 flips bit 0 of EVERY leaky-AND
          // row it ships to party 1, so P1's tKEYphi diverges. The leaky-AND consistency check
          // (the batched windowed-alpha RLC) must abort during preprocessing. Every row, because
          // P1 folds a row in only when its own selector bit for that AND is 1: a single faulty
          // row is masked away half the time, while with every row faulty the fault stays hidden
          // only if all B*L of P1's selectors are 0. Only ONE sender flips: P1 folds every
          // sender's row under the same selector bit, so if all nP-1 senders flipped, the copies
          // would cancel in the XOR-combined tKEYphi whenever nP-1 is even (nP = 3 here), a
          // false negative that hides the fault.
          if (party_ == 2 && peer == 1)
            for (int r = 0; r < ed - st; ++r) gbuf[(size_t)r * gb] ^= 0x1;
#endif
          ag::pack_laand_rows(packed.data(), gbuf.data(), ed - st, gw);
          ch->send_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
          ch->flush(peer);
        }
      };

      // Receiver: recompute tMACphi[peer][k] for k in [lo,hi) from the shipped rows on ch.
      auto laand_recv = [&tMAC, &tKEY, &tMACphi, any_peer, L, hg_chunk, gb, gw](NetIOMP<nP> *ch, int peer, block seed, int lo, int hi, int lane) {
        MITCCRH<> mitc;
        mitc.setS(seed ^ makeBlock(0, (uint64_t)lane));   // lane in the free low 64 of the key
        block pad[16];
        const int len = hi - lo;
        BlockVec wire(std::min(hg_chunk, len));
        std::vector<unsigned char> gbuf((size_t)std::min(hg_chunk, len) * gb);
        std::vector<unsigned char> packed(ag::laand_row_wire_bytes(std::min(hg_chunk, len), gw));
        for (int ci = 0; ci < (len + hg_chunk - 1) / hg_chunk; ++ci) {
          int st = lo + hg_chunk * ci, ed = std::min(lo + hg_chunk * (ci + 1), hi);
          ch->recv_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
          expecting(ag::unpack_laand_rows(gbuf.data(), packed.data(), ed - st, gw),
                    "LaAND row has nonzero padding");
          for (int r = 0; r < ed - st; ++r) {   // zero-extend each gb-byte row to a block
            wire[r] = zero_block;
            memcpy(&wire[r], gbuf.data() + (size_t)r * gb, gb);
          }
          for (int k0 = st; k0 < ed; k0 += 8) {
            int batch = std::min(8, ed - k0);
            for (int j = 0; j < 8; ++j) {
              pad[2 * j]     = (j < batch) ? tMAC[peer][k0 + j] : zero_block;  // -> H(M)
              pad[2 * j + 1] = (j < batch) ? tKEY[peer][k0 + j] : zero_block;  // -> H(K)
            }
            mitc.hash_cir<8, 2>(pad);
            for (int j = 0; j < batch; ++j) {
              int k = k0 + j;
              block HM = pad[2 * j], HK = pad[2 * j + 1];
              block E = HM ^ (wire[k - st] & select_mask[getLSB(tMAC[any_peer][k])]);
              tMACphi[peer][k] = HK ^ E ^ tKEY[peer][2 * L + k] ^ tMAC[peer][2 * L + k];
            }
          }
        }
      };

      // The leaky-AND transfer keeps its own fan-out (one per-peer seed shared by all
      // lanes) rather than LaneMesh::fan_out, but uses the shared ag::lane_range.
      int T = std::min(mesh_.lanes, std::max(1, L));   // T_eff = min(lanes, L): no empty slice

      vector<future<void>> res;
      for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
        // Snapshot both directed transcripts from every mesh, then share the resulting
        // per-peer seed across lanes (the lane id further domain-separates the CCR key).
        block seed = fs_coin_pair_group<nP>(
            mesh_.io, mesh_.grp, peer, "AGMPC laand seed", sid_);
        for (int t = 0; t < T; ++t) {   // canonical order: peer-major, lanes 0..T-1, dir-adjacent
          auto [lo, hi] = ag::lane_range(t, L, T);
          NetIOMP<nP> *ch = mesh_.mesh(t);
          res.push_back(pool->enqueue([&laand_send, ch, peer, seed, lo, hi, t]() { laand_send(ch, peer, seed, lo, hi, t); }));
          res.push_back(pool->enqueue([&laand_recv, ch, peer, seed, lo, hi, t]() { laand_recv(ch, peer, seed, lo, hi, t); }));
        }
      }
      joinNclean(res);   // all-lane flush barrier: every lane's send+recv joined before the coin
    }
#ifdef AG_PROFILE
    g_ag_phi_bytes += (uint64_t)(mesh_.io->count() - _phi0);
#endif

    // --- combine: sum the per-peer terms (one peer at nP==2) + the global phi/Delta
    // correction -> the leaky-AND result in tKEYphi[party]. ---
    {
      vector<future<void>> res;
      for (int wi = 0; wi < (int)pool->size(); ++wi) {
        int st = wi * width, ed = std::min((wi + 1) * width, L);
        res.push_back(pool->enqueue([this, st, ed, L, any_peer, &tKEYphi, &tMACphi, &tMAC, &phi]() {
          for (int k = st; k < ed; ++k) {
            block t = zero_block;
            for (int j = 1; j <= nP; ++j) if (j != party_) t = t ^ tMACphi[j][k];
            t = t ^ (phi[k] & select_mask[getLSB(tMAC[any_peer][k])]);
            t = t ^ (Delta_ & select_mask[getLSB(tMAC[any_peer][2 * L + k])]);
            tKEYphi[party_][k] = t;
          }
        }));
      }
      joinNclean(res);
    }
#ifdef AG_PROFILE
    g_ag_tp_hg_ns += agmpc_now_ns() - _tp_hg0;
    uint64_t _tp_so0 = agmpc_now_ns();
#endif

    // s-open (shared): d = LSB1(result). Exchange this party's s with every peer,
    // lane-split across the meshes. This runs before the coin and is covered by the
    // same all-bytes-on-wire-before-the-coin ordering as the leaky-AND rows above
    // (this join completes before produce_row returns). Combine stays on assembled s[].
    {
      for (int k = 0; k < L; ++k)
        s[party_][k] = LSB1(tKEYphi[party_][k]);
      mesh_.fan_out(L,
        [this, &s](NetIOMP<nP> *ch, int peer, int lo, int hi) {
          ch->send_bool(peer, (const bool *)(s[party_].data() + lo), hi - lo);
          ch->flush(peer);
        },
        [&s](NetIOMP<nP> *ch, int peer, int lo, int hi) {
          ch->recv_bool(peer, (bool *)(s[peer].data() + lo), hi - lo);
        });
    }

#ifdef AG_PROFILE
    g_ag_tp_sopen_ns += agmpc_now_ns() - _tp_so0;
    uint64_t _tp_ac0 = agmpc_now_ns();
#endif
    // d-combine (shared): fold d = ⊕_p s_p into region 2 (r -> c) and the result
    // vector. Width-split: every write is k-indexed (s[0][k], the 2L+k share slots,
    // T[k]) and every read is done, so ranges are race-free and the split matches
    // the serial loop.
    {
      block *T = tKEYphi[party_].data();
      block dxor = Delta_ ^ bit0_mask;
      ag::parallel_for(pool, L, [&](int lo, int hi) {
        for (int k = lo; k < hi; ++k) {
          s[0][k] = 0;
          for (int i = 1; i <= nP; ++i)
            s[0][k] = (s[0][k] != s[i][k]);
          block mask_s = select_mask[s[0][k]];
          if (party_ == 1) {
            if (s[0][k]) {
              for (int j = 1; j <= nP; ++j) if (j != party_)
                tMAC[j][2 * L + k] = tMAC[j][2 * L + k] ^ bit0_mask;
            }
          } else {
            tKEY[1][2 * L + k] = tKEY[1][2 * L + k] ^ (dxor & mask_s);
          }
          T[k] = T[k] ^ (Delta_ & mask_s);
        }
      });
    }

    // Terminal-check accumulation: batched per call. Each row accumulates its windowed
    // check object; ONE terminal check fires per call in finish_check(), with its coin
    // drawn only after every row is generated.
    if constexpr (nP == 2) {
      // F_eq: fold the low-gw-bit window of this row's L-vector into the running hash;
      // one terminal check fires in finish_check(). The hash over the whole windowed
      // vector IS the check.
      ag::accumulate_leaky_and_window(feq, &tKEYphi[party_][0], L, gw, window_, pool);
    } else {
      // nP>=3: STASH this row's windowed RLC vector (the high bits are not reconciled
      // cross-party once G is truncated; both ends zero them) + its FZero u_zero. The
      // single B*L GF(2^128) RLC zero-sum runs once per call in finish_check() over ALL B
      // rows -- tighter than B per-row checks by a factor B, and the challenge is drawn
      // post-commitment (after the whole B*L set is on the wire).
      const block window_mask = ag::laand_window_mask(ssp_);
      size_t off = alpha_masked_cat_.size();
      alpha_masked_cat_.resize(off + (size_t)L);
      for (int k = 0; k < L; ++k)
        alpha_masked_cat_[off + k] = tKEYphi[party_][k] & window_mask;
#ifdef EMP_AG_TEST_FLIP_LAAND_HIGH
      // TEST-ONLY: corrupt the highest retained coordinate of exactly one
      // local check input. Unlike a shipped-row fault, no selector masks it away.
      if (party_ == 1 && off == 0 && L > 0) {
        unsigned char fault[sizeof(block)] = {};
        fault[(gw - 1) / 8] = 1u << ((gw - 1) % 8);
        block delta;
        memcpy(&delta, fault, sizeof(delta));
        alpha_masked_cat_[off] ^= delta;
      }
#endif
      alpha_uzero_.push_back(u_zero);
    }
#ifdef AG_PROFILE
    g_ag_tp_acheck_ns += agmpc_now_ns() - _tp_ac0;
#endif
  }

  // Two-party batched LaAND schedule: every row's COTs are fixed first, one transcript
  // root domain-separates the B row seeds, all rows cross in one flight, and all
  // dependent s bits cross in the next. Row 0 is accMAC/accKEY, row k >= 1 is
  // sac_macs[k]/sac_keys[k].
  void produce_rows_2pc(
      BlockVec accMAC[nP + 1], BlockVec accKEY[nP + 1],
      std::vector<std::vector<BlockVec>> &sac_macs,
      std::vector<std::vector<BlockVec>> &sac_keys,
      int B, int L, FsHash &feq) {
    if constexpr (nP == 2) {
      ThreadPool *pool = mesh_.pool;
      const int peer = (party_ == 1) ? 2 : 1;
      const int gb = ag::laand_window_bytes(ssp_);
      const int gw = ag::laand_window_bits(ssp_);
      const int BL = B * L;
      auto layer_mac = [&](int k) -> BlockVec * {
        return k == 0 ? accMAC : sac_macs[k].data();
      };
      auto layer_key = [&](int k) -> BlockVec * {
        return k == 0 ? accKEY : sac_keys[k].data();
      };

      // Once all COT material is fixed, snapshot one transcript root and RO-expand
      // it by the public batch shape and row index.  Each row restarts MITCCRH's
      // gid, so the row separation is load-bearing.
      const block root = fs_coin_pair_group<nP>(
          mesh_.io, mesh_.grp, peer, "AGMPC laand batch seed", sid_);
      std::vector<block> layer_seed(B);
      for (int k = 0; k < B; ++k)
        layer_seed[k] =
            RO("emp-ag:laand-layer-seed", sid_)
                .absorb(root)
                .absorb((uint64_t)B)
                .absorb((uint64_t)L)
                .absorb((uint64_t)k)
                .squeeze_block();

      // Keep only the gb-byte T window needed after the bulk s open. phi is a
      // cheap local expression over resident row material, so each direction
      // recomputes it instead of retaining B*L extra blocks.
      if (window_.size() < (size_t)BL * gb)
        window_.resize((size_t)BL * gb);
      std::vector<unsigned char>(&s)[nP + 1] = s_;
      for (int p = 1; p <= nP; ++p)
        if (s[p].size() < (size_t)BL) s[p].resize((size_t)BL);

#ifdef AG_PROFILE
      uint64_t _tp_hg0 = agmpc_now_ns();
      int64_t _phi0 = mesh_.io->count();
#endif
      // One task per (lane,direction) walks every row in canonical order.
      // Do not enqueue per-row tasks on one NetIO: their writes could interleave.
      const int hg_chunk = ag::kLaandRowChunkRows;
      int T = std::min(mesh_.lanes, std::max(1, L));
      vector<future<void>> rows;
      for (int lane = 0; lane < T; ++lane) {
        auto [lo, hi] = ag::lane_range(lane, L, T);
        NetIOMP<nP> *ch = mesh_.mesh(lane);
        rows.push_back(pool->enqueue([&, ch, lane, lo, hi]() {
          const int len = hi - lo;
          std::vector<unsigned char> gbuf((size_t)std::min(hg_chunk, len) * gb);
          std::vector<unsigned char> packed(ag::laand_row_wire_bytes(std::min(hg_chunk, len), gw));
          block pad[16];
          for (int layer = 0; layer < B; ++layer) {
            BlockVec *mac = layer_mac(layer);
            BlockVec *key = layer_key(layer);
            MITCCRH<> mitc;
            mitc.setS(layer_seed[layer] ^ makeBlock(0, (uint64_t)lane));
            for (int st = lo; st < hi; st += hg_chunk) {
              const int ed = std::min(st + hg_chunk, hi);
              for (int k0 = st; k0 < ed; k0 += 8) {
                const int batch = std::min(8, ed - k0);
                for (int j = 0; j < 8; ++j) {
                  const block kk = (j < batch) ? key[peer][k0 + j] : zero_block;
                  pad[2 * j] = kk;
                  pad[2 * j + 1] = kk ^ Delta_;
                }
                mitc.hash_cir<8, 2>(pad);
                for (int j = 0; j < batch; ++j) {
                  const int k = k0 + j;
                  const block phi =
                      (select_mask[getLSB(mac[peer][L + k])] & Delta_) ^
                      key[peer][L + k] ^ mac[peer][L + k];
                  const block row = pad[2 * j] ^ pad[2 * j + 1] ^ phi;
                  memcpy(gbuf.data() + (size_t)(k0 + j - st) * gb, &row, gb);
                }
              }
              ag::pack_laand_rows(packed.data(), gbuf.data(), ed - st, gw);
              ch->send_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
            }
          }
          ch->flush(peer);
        }));
        rows.push_back(pool->enqueue([&, ch, lane, lo, hi]() {
          const int len = hi - lo;
          std::vector<unsigned char> gbuf((size_t)std::min(hg_chunk, len) * gb);
          std::vector<unsigned char> packed(ag::laand_row_wire_bytes(std::min(hg_chunk, len), gw));
          BlockVec wire(std::min(hg_chunk, len));
          block pad[16];
          for (int layer = 0; layer < B; ++layer) {
            BlockVec *mac = layer_mac(layer);
            BlockVec *key = layer_key(layer);
            MITCCRH<> mitc;
            mitc.setS(layer_seed[layer] ^ makeBlock(0, (uint64_t)lane));
            for (int st = lo; st < hi; st += hg_chunk) {
              const int ed = std::min(st + hg_chunk, hi);
              ch->recv_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
              expecting(ag::unpack_laand_rows(gbuf.data(), packed.data(), ed - st, gw),
                        "LaAND row has nonzero padding");
              for (int r = 0; r < ed - st; ++r) {
                wire[r] = zero_block;
                memcpy(&wire[r], gbuf.data() + (size_t)r * gb, gb);
              }
              for (int k0 = st; k0 < ed; k0 += 8) {
                const int batch = std::min(8, ed - k0);
                for (int j = 0; j < 8; ++j) {
                  pad[2 * j] = (j < batch) ? mac[peer][k0 + j] : zero_block;
                  pad[2 * j + 1] =
                      (j < batch) ? key[peer][k0 + j] : zero_block;
                }
                mitc.hash_cir<8, 2>(pad);
                for (int j = 0; j < batch; ++j) {
                  const int k = k0 + j;
                  const block E =
                      pad[2 * j] ^
                      (wire[k - st] & select_mask[getLSB(mac[peer][k])]);
                  block value = pad[2 * j + 1] ^ E ^ key[peer][2 * L + k] ^
                                mac[peer][2 * L + k];
                  const block phi =
                      (select_mask[getLSB(mac[peer][L + k])] & Delta_) ^
                      key[peer][L + k] ^ mac[peer][L + k];
                  value ^= phi & select_mask[getLSB(mac[peer][k])];
                  value ^= Delta_ & select_mask[getLSB(mac[peer][2 * L + k])];
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
                  const size_t flat = (size_t)layer * L + k;
                  s[party_][flat] = LSB1(value);
                  memcpy(window_.data() + flat * gb, &value, gb);
                }
              }
            }
          }
        }));
      }
      joinNclean(rows);
#ifdef AG_PROFILE
      g_ag_phi_bytes += (uint64_t)(mesh_.io->count() - _phi0);
      g_ag_tp_hg_ns += agmpc_now_ns() - _tp_hg0;
      uint64_t _tp_so0 = agmpc_now_ns();
#endif

      // The single dependent flight: open every row's s vector together.
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

      const block dxor = Delta_ ^ bit0_mask;
      unsigned char delta_bytes[sizeof(block)];
      memcpy(delta_bytes, &Delta_, sizeof(block));
      for (int layer = 0; layer < B; ++layer) {
        BlockVec *mac = layer_mac(layer);
        BlockVec *key = layer_key(layer);
        unsigned char *window =
            window_.data() + (size_t)layer * L * gb;
        ag::parallel_for(pool, L, [&](int lo, int hi) {
          for (int k = lo; k < hi; ++k) {
            const size_t flat = (size_t)layer * L + k;
            const unsigned char opened = s[1][flat] ^ s[2][flat];
            if (opened) {
              if (party_ == 1)
                mac[peer][2 * L + k] ^= bit0_mask;
              else
                key[1][2 * L + k] ^= dxor;
              for (int j = 0; j < gb; ++j)
                window[(size_t)k * gb + j] ^= delta_bytes[j];
            }
            // The equality check must bind exactly the transmitted bit window,
            // including after the local Delta correction above.
            window[(size_t)(k + 1) * gb - 1] &= ag::laand_last_byte_mask(gw);
          }
        });
        ag::accumulate_leaky_and_window_bytes(feq, window, L, gb, pool);
      }
#ifdef AG_PROFILE
      g_ag_tp_acheck_ns += agmpc_now_ns() - _tp_ac0;
#endif
    }
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
      block uz = zero_block;
      for (block u : alpha_uzero_) uz = uz ^ u;   // all B rows
      ip[party][0] = ip[party][0] ^ uz;
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
  // The batched alpha-check stash (nP>=3): each row's windowed RLC vector and its FZero
  // u_zero, accumulated across all B rows of a call; cleared by begin_call().
  BlockVec alpha_masked_cat_;
  std::vector<block> alpha_uzero_;
  // Reused per-row scratch (grow-only). All assigned/explicitly-zeroed before read
  // except z_u (XOR-accumulated by fzero_xor -> re-zeroed via std::fill each call).
  BlockVec tKEYphi_[nP + 1], tMACphi_[nP + 1];
  BlockVec phi_, z_u_, phi_cat_;
  std::vector<unsigned char> s_[nP + 1];
  std::vector<unsigned char> window_;   // accumulate_leaky_and_window scratch
  BlockVec fzero_;                      // fzero_xor contribution scratch
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_TRIPLE_LAAND_H__
