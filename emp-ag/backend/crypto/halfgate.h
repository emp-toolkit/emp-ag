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
#include "emp-ag/backend/garble_config.h"   // Auth (the destinations a gate hashes for)
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

// The three rows a garbler sends toward the holder of key slot s: its MACs under that
// key on its shares of lambda_beta, of lambda_alpha, and of lambda_gamma xor sigma, each
// padded with that destination's hashes h = {H(a0), H(a1), H(b0), H(b1)} of the first
// (a) and second (b) input's labels. Given the active labels, the hashes leave exactly
//   La * row[0] ^ Lb * row[1] ^ row[2] ^ H(a_La) ^ H(b_Lb)
//     = M_s[La lambda_beta ^ Lb lambda_alpha ^ sigma ^ lambda_gamma],
// the MAC on this garbler's share of Lambda_gamma ^ La Lb: the destination's label
// material, or (toward P1) the value P1 authenticates Lambda with.
template <class B>
inline void cross_rows(const block *h, const B &a, const B &b, const B &ab,
                       const B &g, int s, block *row) {
  row[0] = h[0] ^ h[1] ^ peer_mac(b, s);
  row[1] = h[2] ^ h[3] ^ peer_mac(a, s);
  row[2] = h[0] ^ h[2] ^ peer_mac(g, s) ^ peer_mac(ab, s);
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
// calls, so their streams advance in lockstep. Under Auth::WRK, P1 is one more
// destination, after the garblers: its two lanes follow destination nP's, so a gate
// hashes 2 nP lanes.
//
// ReuseShift stays 3 for every nP: each step above 3 would cost one more bit of the
// multi-instance bound (mitccrh.h). A stream call runs under one key, so its lanes
// fit one bucket of 2^ReuseShift gids, and a gate hashes its lanes in calls of at
// most that many. A gate of D destinations takes ceil(2 D / 8) calls: one up to 4
// destinations (5 parties under KRRW, 4 under WRK, whose P1 is one more), where one key
// covers 4 gates at D = 1, 2 at D = 2 and one gate at D = 3 and 4.
// The destinations an AND gate hashes for: the garblers 2..nP, then P1 under WRK.
template <int nP, class Cfg>
inline constexpr int kHalfGateDests = nP - 1 + (Cfg::auth == Auth::WRK ? 1 : 0);
template <int D> inline constexpr int kHalfGateLanes = 2 * D;
template <int nP> inline constexpr int kHalfGateReuseShift = 3;
template <int nP> using HalfGateHash = MITCCRH<kHalfGateReuseShift<nP>>;
// Lanes per stream call: one key bucket.
template <int nP> inline constexpr int kHalfGateCallLanes = 1 << kHalfGateReuseShift<nP>;

// Start point of `sender`'s stream for a chunk whose half-gate seed is `seed`.
inline block halfgate_stream_start(block seed, int sender) {
  return seed ^ makeBlock(0, (uint64_t)sender);
}

// Hash one AND gate's lanes of H blocks each, for D destinations, in place: whole
// buckets of lanes first, then the remaining lanes in one call.
template <int nP, int H, int D = nP - 1>
inline void halfgate_hash_lanes(HalfGateHash<nP> &h, block *buf) {
  constexpr int per_call = kHalfGateCallLanes<nP>;
  constexpr int full = kHalfGateLanes<D> / per_call;
  constexpr int rest = kHalfGateLanes<D> % per_call;
  for (int c = 0; c < full; ++c)
    h.template hash_cir<per_call, H>(buf + c * per_call * H);
  if constexpr (rest > 0)
    h.template hash_cir<rest, H>(buf + full * per_call * H);
}

// Garbler: hash, in place, one AND gate's labels for every destination. buf holds
// {a0, a1, b0, b1} per destination (4 D blocks, garbler d at 4 (d-2), P1 last): a0/a1
// the first input's labels, b0/b1 the second's.
template <int nP, int D = nP - 1>
inline void halfgate_hash_garbler(HalfGateHash<nP> &h, block *buf) {
  halfgate_hash_lanes<nP, 2, D>(h, buf);
}

// Evaluator: hash, in place, its active labels of one AND gate as one sender garbled
// them. buf holds {A, B} per destination (2 D blocks, garbler d at 2 (d-2), P1 last):
// A the first input's active label, B the second's.
template <int nP, int D = nP - 1>
inline void halfgate_hash_evaluator(HalfGateHash<nP> &h, block *buf) {
  halfgate_hash_lanes<nP, 1, D>(h, buf);
}

}  // namespace emp::ag
#endif // EMP_AG_BACKEND_CRYPTO_HALFGATE_H__
