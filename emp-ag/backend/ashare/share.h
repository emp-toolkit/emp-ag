#ifndef EMP_AG_BACKEND_ASHARE_SHARE_H__
#define EMP_AG_BACKEND_ASHARE_SHARE_H__
//
// The authenticated-share data model: the physical per-wire share (AShareBundle and its
// ADL StorageTraits accessors) and peer_slot. The garbling layer's per-circuit wire
// container, SecureWires, is in garble/wires.h. The section comments below carry the
// detail.
//
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/core/block_vector.h"
#include <vector>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

//
// Per-wire authenticated-share storage — the single physical share type the whole stack
// carries.
//
// Layout (slot k indexes peers in increasing party-id order, skipping `self`):
//   km[2*k]     = mac for the k-th peer = M_k[x] = K_k[x] ^ x*Delta_k  (bit0 = x)
//   km[2*k + 1] = key for the k-th peer = K_me[x_k]
// Size = 2*(nP-1) blocks. At nP=2 (K=1) this is exactly 32B = {mac, key}, and the slot-0
// accessors + the XOR-over-one-peer traits below fold to scalar loads (the per-peer loop
// has one iteration; `zero_block ^ x` folds to `x`). That is what keeps the two-party hot
// loop's scalar codegen with no n-party machinery forced onto it (the StorageTraits seam:
// the ADL accessors below -- peer_key_sum / peer_mac_sum / own_bit / peer_mac / own_dot).
//
template <int nP> struct AShareBundle {
  static_assert(nP >= 2, "at least 2 parties");
  static constexpr int K = nP - 1;          // peers (everyone but self)
  static constexpr int N = 2 * (nP - 1);    // blocks: (mac,key) per peer
  block km[N];

  block &mac(int slot) { return km[2 * slot]; }
  block &key(int slot) { return km[2 * slot + 1]; }
  const block &mac(int slot) const { return km[2 * slot]; }
  const block &key(int slot) const { return km[2 * slot + 1]; }
};

// StorageTraits accessors, found by ADL from the garble / output-check kernels. At nP=2
// (K=1) the loop is one iteration and `zero_block ^ key(0)` folds to `key(0)`.
template <int nP> inline block peer_key_sum(const AShareBundle<nP> &b) {
  block s = zero_block;
  for (int k = 0; k < AShareBundle<nP>::K; ++k) s = s ^ b.key(k);
  return s;
}
// XOR of the local MACs over all peers = XOR_k M_k[x^me]. The MAC-side counterpart of
// peer_key_sum, used by the BDOZ->SPDZ collapse (collapse_cgamma_witness, garble/spdz.h): the SPDZ MAC share of
// x under the shared global key is own_dot(x,Delta_me) ^ peer_mac_sum(x) ^ peer_key_sum(x).
// At nP=2 (K=1) this folds to the single scalar mac(0).
template <int nP> inline block peer_mac_sum(const AShareBundle<nP> &b) {
  block s = zero_block;
  for (int k = 0; k < AShareBundle<nP>::K; ++k) s = s ^ b.mac(k);
  return s;
}
template <int nP> inline bool own_bit(const AShareBundle<nP> &b) {
  return getLSB(b.mac(0));
}
// own_bit * Delta, branchless via select_mask (folds the bit to 0 / Delta), as the
// half-gate and c_gamma kernels use it. Resolves own_bit by ADL on B.
template <class B>
inline block own_dot(const B &b, const block &Delta) {
  return select_mask[own_bit(b)] & Delta;
}
// MAC under a specific peer's key (slot s) -- the shared t_gamma garbler witness
// over the evaluator's slot. At nP=2 the only slot is 0.
template <int nP> inline block peer_mac(const AShareBundle<nP> &b, int s) {
  return b.mac(s);
}

template <int nP>
using AShareBundleVec =
    std::vector<AShareBundle<nP>, default_init_allocator<AShareBundle<nP>>>;

// Free-XOR share propagation: recompute a fabric wire's share bundle as the
// componentwise XOR of its (live) inputs. bit0 (the share-bit) rides along.
template <int nP>
inline void xor_share(AShareBundle<nP> &out, const AShareBundle<nP> &a,
                      const AShareBundle<nP> &b) {
  for (int t = 0; t < AShareBundle<nP>::N; ++t) out.km[t] = a.km[t] ^ b.km[t];
}
template <int nP>
inline void zero_share(AShareBundle<nP> &out) {
  for (int t = 0; t < AShareBundle<nP>::N; ++t) out.km[t] = zero_block;
}

// Map peer party-id (1-based) to a slot index in [0, nP-1) within a bundle
// owned by `self`. Caller must ensure peer != self. (Plain ints, no ADL.)
inline int peer_slot(int self, int peer) {
  return (peer < self) ? (peer - 1) : (peer - 2);
}

// Add the public bit 1 to an authenticated bit in this encoding: party 1 flips its share,
// bit 0 of its MAC toward every peer, and every other party moves its key on party 1's
// share by Delta, keeping that key's bit 0 clear. mac(p) and key(p) return, by
// reference, this party's MAC toward peer p and its key on p's share.
template <int nP, class Mac, class Key>
inline void add_public_one(int party, const block &Delta, Mac &&mac, Key &&key) {
  if (party == 1) {
    for (int p = 2; p <= nP; ++p) mac(p) = mac(p) ^ bit0_mask;
  } else {
    key(1) = key(1) ^ Delta ^ bit0_mask;
  }
}

// Bit 1 (second-lowest) of a block. Reserved for the half-gate Λ_γ recovery
// invariant LSB1(⊕_p Δ_p) = 1; bit 0 is reserved for share-value encoding
// (AShareBundle, above).
inline uint8_t LSB1(const block &b) { return getBit(b, 1); }

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_ASHARE_SHARE_H__
