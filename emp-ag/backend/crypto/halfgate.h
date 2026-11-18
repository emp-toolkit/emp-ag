#ifndef EMP_AG_BACKEND_CRYPTO_HALFGATE_H__
#define EMP_AG_BACKEND_CRYPTO_HALFGATE_H__
//
// Pure half-gate garbling kernels: the garbler's self half-gate row, the
// t_gamma witness (MAC form), and the half-gate hash's lane layout. Both kernels read
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

// The half-gate hash -- the part of the byte contract that fixes WHICH (S, gid) each
// hash runs under; both ends derive it identically. Each sender has its own MITCCRH
// stream, started at the chunk's half-gate seed with the sender XORed into the low
// qword (MITCCRH's hook for a tweak dimension beyond the gid): a garbler keeps its
// own stream, the evaluator one per sender. An AND gate hashes 2 (nP-1) lanes:
// destination d contributes lane 2 (d-2), its first input's labels, and lane
// 2 (d-2) + 1, its second input's, so the stream gives every half of every
// destination its own gid. The halves must not share one: a lane has one tweak, so
// an AND whose inputs carry equal or complementary labels -- AND(a, a), AND(a, NOT a)
// -- would hash the second input's labels exactly as the first's, and the garbler's
// two half-gate rows would XOR to its 0-label of the input, handing the evaluator
// Delta. Both ends hash every AND gate once, in circuit order and with the same
// calls, so their streams advance in lockstep.
//
// ReuseShift stays 3 for every nP: each step above 3 would cost one more bit of the
// multi-instance bound (mitccrh.h). A stream call runs under one key, so its lanes
// fit one bucket of 2^ReuseShift gids, and a gate hashes its lanes in calls of at
// most that many. Up to 5 parties that is one call per gate, and one key covers 4
// gates at nP = 2, 2 at nP = 3 and one gate at nP = 4 and 5; beyond, a gate takes
// ceil(2 (nP-1) / 8) calls and as many keys.
template <int nP> inline constexpr int kHalfGateLanes = 2 * (nP - 1);
template <int nP> inline constexpr int kHalfGateReuseShift = 3;
template <int nP> using HalfGateHash = MITCCRH<kHalfGateReuseShift<nP>>;
// Lanes per stream call: one key bucket.
template <int nP> inline constexpr int kHalfGateCallLanes = 1 << kHalfGateReuseShift<nP>;

// Start point of `sender`'s stream for a chunk whose half-gate seed is `seed`.
inline block halfgate_stream_start(block seed, int sender) {
  return seed ^ makeBlock(0, (uint64_t)sender);
}

// Hash one AND gate's lanes of H blocks each, in place: whole buckets of lanes first,
// then the remaining lanes in one call.
template <int nP, int H>
inline void halfgate_hash_lanes(HalfGateHash<nP> &h, block *buf) {
  constexpr int per_call = kHalfGateCallLanes<nP>;
  constexpr int full = kHalfGateLanes<nP> / per_call, rest = kHalfGateLanes<nP> % per_call;
  for (int c = 0; c < full; ++c)
    h.template hash_cir<per_call, H>(buf + c * per_call * H);
  if constexpr (rest > 0)
    h.template hash_cir<rest, H>(buf + full * per_call * H);
}

// Garbler: hash, in place, one AND gate's labels for every destination. buf holds
// {a0, a1, b0, b1} per destination (4 (nP-1) blocks, destination d at 4 (d-2)): a0/a1
// the first input's labels, b0/b1 the second's.
template <int nP>
inline void halfgate_hash_garbler(HalfGateHash<nP> &h, block *buf) {
  halfgate_hash_lanes<nP, 2>(h, buf);
}

// Evaluator: hash, in place, its active labels of one AND gate as one sender garbled
// them. buf holds {A, B} per destination (2 (nP-1) blocks, destination d at 2 (d-2)):
// A the first input's active label, B the second's.
template <int nP>
inline void halfgate_hash_evaluator(HalfGateHash<nP> &h, block *buf) {
  halfgate_hash_lanes<nP, 1>(h, buf);
}

}  // namespace emp::ag
#endif // EMP_AG_BACKEND_CRYPTO_HALFGATE_H__
