#ifndef EMP_AG_BACKEND_GARBLE_SPDZ_H__
#define EMP_AG_BACKEND_GARBLE_SPDZ_H__
//
// The c_gamma SPDZ-collapse witness kernels and the GF(2^128) RLC fold: pure
// compute shared by the circuit walks that produce the witness material and
// the output check that folds it. No protocol or network state.
//
#include "emp-ag/backend/common/runtime.h"
#include "emp-ag/backend/ashare/share.h"
#include "emp-tool/emp-tool.h"   // gfmul, ThreadPool, joinNclean, select_mask

namespace emp::ag {

// ---- c_gamma SPDZ-collapse witness kernels (shared by the circuit walks that
// produce the witness material and the witness-folding pass that folds it) --------------
// BDOZ->SPDZ collapse for one wire mask x is purely local:
//   mu^i(x) = own_dot(x, Delta_i) ^ peer_mac_sum(x) ^ peer_key_sum(x),
// and XOR_i mu^i(x) = x * Delta because the pairwise K cross-terms cancel in
// GF(2^kappa). ONE block per wire at every nP.
template <class B>
inline block spdz_mac_share(const B &b, const block &Delta) {
  return own_dot(b, Delta) ^ peer_mac_sum(b) ^ peer_key_sum(b);
}

// Symmetric c_gamma MAC share for one AND gate. c_gamma is linear in the masks with
// PUBLIC Lambda coefficients
//   c_gamma = (La&Lb) ^ Lg ^ La*lam_b ^ Lb*lam_a ^ lam_ab ^ lam_g
// so its MAC share is that linear combination of the collapsed mu^i plus the public
// constant (La&Lb)^Lg carried as const*Delta_i at EVERY party. Honest gate =>
// c_gamma=0 => XOR_i mu=0; a wrong Lambda makes some c_gamma=1 => XOR_i mu = Delta != 0.
template <class B>
inline block collapse_cgamma_witness(bool La, bool Lb, bool Lg, const B &in0, const B &in1,
                                     const B &out, const B &sig, block Delta) {
  bool cst = (La & Lb) ^ Lg;                               // public constant (La&Lb)^Lg
  block m = select_mask[cst] & Delta;                     // const*Delta_i at EVERY party
  if (La) m = m ^ spdz_mac_share(in1, Delta);
  if (Lb) m = m ^ spdz_mac_share(in0, Delta);
  m = m ^ spdz_mac_share(sig, Delta) ^ spdz_mac_share(out, Delta);
  return m;
}

// Record-form sibling of collapse_cgamma_witness: assemble one AND gate's mu from the
// precomputed records s0 = S(sig)^S(out), s1 = S(in1), s2 = S(in0) instead of the live
// share bundles. MUST stay value-identical to collapse_cgamma_witness
// (test/ev_records_equiv.cpp checks it): every party's mu enters the same shared-zero
// check.
inline block collapse_cgamma_from_records(bool La, bool Lb, bool Lg, const block &s0,
                                          const block &s1, const block &s2,
                                          const block &Delta) {
  block mu = select_mask[(La & Lb) ^ Lg] & Delta;
  if (La) mu = mu ^ s1;
  if (Lb) mu = mu ^ s2;
  mu = mu ^ s0;
  return mu;
}

// Reduced chi^e by square-and-multiply. Field associativity makes any bracketing of
// the product give the same reduced element, so powers computed here are bit-identical
// to an iterated coeff <- coeff*chi chain.
inline block gf_pow(block x, uint64_t e) {
  block r = makeBlock(0, 1);   // the field's multiplicative identity
  while (e) {
    if (e & 1) gfmul(r, x, &r);
    gfmul(x, x, &x);
    e >>= 1;
  }
  return r;
}

// Lanes per RLC fold: splits the coeff <- coeff*chi gfmul dependency chain so the
// carryless multiplies pipeline (throughput-1, latency-several cycles). Purely local
// ILP — the folded VALUE is byte-identical to the serial Horner (every term
// reduce(mu_a * chi^{a+1}) is the same field element, and XOR of the same set of
// blocks is order-independent), so lane counts never need cross-party agreement.
inline constexpr int kRlcLanes = 8;

// m = XOR_a chi^{a+1} * mu_a over mu[0, n): width-split across the pool, K-lane
// chain-broken within each worker. Byte-identical to the serial fold (see above).
inline block rlc_fold_mu(const block *mu, int n, block chi, ThreadPool *pool) {
  if (n <= 0) return zero_block;
  const int W = std::max(1, (int)pool->size());
  const int width = (n + W - 1) / W;
  const int nt = (n + width - 1) / width;
  std::vector<block> part((size_t)nt, zero_block);
  vector<future<void>> res;
  int t = 0;
  for (int a0 = 0; a0 < n; a0 += width, ++t) {
    const int a1 = std::min(a0 + width, n);
    res.push_back(pool->enqueue([&part, mu, chi, a0, a1, t]() {
      constexpr int K = kRlcLanes;
      block powK = gf_pow(chi, K);
      block lane_pow[K], acc[K];
      block p = gf_pow(chi, (uint64_t)a0 + 1);
      for (int j = 0; j < K; ++j) {
        lane_pow[j] = p;
        acc[j] = zero_block;
        if (j + 1 < K) gfmul(p, chi, &p);
      }
      int a = a0;
      for (; a + K <= a1; a += K) {
        for (int j = 0; j < K; ++j) {
          block prod;
          gfmul(mu[a + j], lane_pow[j], &prod);
          acc[j] = acc[j] ^ prod;
          gfmul(lane_pow[j], powK, &lane_pow[j]);
        }
      }
      for (int j = 0; a + j < a1; ++j) {   // tail: lane_pow[j] already points at a+j
        block prod;
        gfmul(mu[a + j], lane_pow[j], &prod);
        acc[j] = acc[j] ^ prod;
      }
      block m = zero_block;
      for (int j = 0; j < K; ++j) m = m ^ acc[j];
      part[t] = m;
    }));
  }
  joinNclean(res);
  block m = zero_block;
  for (int i = 0; i < nt; ++i) m = m ^ part[i];
  return m;
}

}  // namespace emp::ag
#endif // EMP_AG_BACKEND_GARBLE_SPDZ_H__
