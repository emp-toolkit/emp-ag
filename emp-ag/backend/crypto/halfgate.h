#ifndef EMP_AG_BACKEND_CRYPTO_HALFGATE_H__
#define EMP_AG_BACKEND_CRYPTO_HALFGATE_H__
//
// Pure half-gate garbling kernels: the garbler's self half-gate row, the
// t_gamma witness (MAC form), and the half-gate hash's gid layout. Both kernels read
// shares ONLY through the ADL StorageTraits accessors (shares.h: peer_key_sum
// / own_dot / peer_mac), so ONE definition serves every nP; at nP=2 the peer
// loop collapses to a single scalar read. They carry no transmit policy --
// they return blocks and the pass decides what crosses the wire. No protocol
// or network state.
//
#include "emp-ag/backend/shares.h"
#include "emp-tool/runtime/core/block.h"   // block ops; makeBlock
#include "emp-tool/runtime/crypto/mitccrh.h"
#include <cstdint>

namespace emp::ag {

// Self-half-gate row: a garbler's own half-gate ciphertexts G0,G1 and the output 0-label
// ml_g0, from the four self-hashes of the input labels, ml_a0, and the four per-wire shares
// (alpha-in `a`, beta-in `b`, sigma=lambda_a*lambda_b `ab`, out `g`). The cross-garbler S
// terms (nP>2) are topology-specific and stay in the garble pass.
template <class B>
inline void self_halfgate_row(block H_a0, block H_a1, block H_b0, block H_b1,
                              block ml_a0, const B &a, const B &b, const B &ab,
                              const B &g, const block &Delta, block &G0,
                              block &G1, block &ml_g0) {
  G0    = H_a0 ^ H_a1 ^ peer_key_sum(b) ^ own_dot(b, Delta);
  G1    = H_b0 ^ H_b1 ^ ml_a0 ^ peer_key_sum(a) ^ own_dot(a, Delta);
  ml_g0 = H_a0 ^ H_b0 ^ peer_key_sum(ab) ^ own_dot(ab, Delta) ^
          peer_key_sum(g) ^ own_dot(g, Delta);
}

// Garbler's t_gamma witness (MAC form) under the evaluator's key slot s. P1's eval-side
// self-MAC row equals this witness; the eval pass assembles it from draw-time records
// (test/ev_records_equiv.cpp checks the equivalence):
//   m = peer_mac(sig,s) ^ peer_mac(out,s) ^ (La?peer_mac(in1,s)) ^ (Lb?peer_mac(in0,s))
// (s is ignored at nP=2 where the bundle is scalar.) La/Lb are the opened input masks.
template <class B>
inline block tgamma_witness_garbler(bool La, bool Lb, const B &in0, const B &in1,
                                    const B &out, const B &sig, int s) {
  block m = peer_mac(sig, s) ^ peer_mac(out, s);
  if (La) m = m ^ peer_mac(in1, s);
  if (Lb) m = m ^ peer_mac(in0, s);
  return m;
}

// Half-gate hash lanes -- the part of the byte contract that fixes WHICH (S, gid)
// each hash runs under; both ends derive it identically. Every party keeps one
// MITCCRH per sender it hashes for (a garbler: itself; the evaluator: one per
// source), all seeded with the shared per-chunk coin, and hashes the nP-1
// destinations of a gate as the lanes of ONE hash_cir call positioned by
// renew_ks(hash_gid(sender, gate)): destination d is lane d-2, i.e. gid
//
//   hash_gid(sender, gate) + (d - 2)
//     = ((sender << kHashGateBits) + gate) * kHashLaneStride + (d - 2).
//
// MITCCRH keys a lane by S ^ (gid >> ReuseShift) and puts T(gid) into the cipher
// input, so every (coin, sender, gate, d) is a distinct (S, gid) and the class,
// not this code, owns tweak uniqueness. kHashLaneStride is the power of two at
// or above nP-1, so a gate's lanes never straddle a key bucket, and
// kHashReuseShift = max(3, log2 stride): up to 9 parties a key covers 8 gids --
// 8/stride gates with all their destinations -- and beyond that one gate per key
// (nP-1 lanes). Schedules per gate never exceed one per destination per 8 gates,
// and a gate's lanes always run as one wide tile under one key.
inline constexpr int kHashGateBits = 40;   // gate index below, sender above

constexpr int hash_ceil_log2(int x) { int l = 0; while ((1 << l) < x) ++l; return l; }
template <int nP> inline constexpr int kHashLaneStride = 1 << hash_ceil_log2(nP - 1);
template <int nP> inline constexpr int kHashReuseShift =
    hash_ceil_log2(nP - 1) > 3 ? hash_ceil_log2(nP - 1) : 3;
template <int nP> using HalfGateHash = MITCCRH<nP - 1, kHashReuseShift<nP>>;

// gid of lane 0 (destination 2) of `gate` as hashed by `sender`.
template <int nP>
constexpr uint64_t hash_gid(int sender, int gate) {
  return (((uint64_t)sender << kHashGateBits) | (uint64_t)gate) * (uint64_t)kHashLaneStride<nP>;
}

}  // namespace emp::ag
#endif // EMP_AG_BACKEND_CRYPTO_HALFGATE_H__
