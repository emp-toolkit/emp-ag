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
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

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

// x^{-1} = x^(2^128 - 2) by Fermat, and 0 for x = 0. Each step takes x^(2^k - 1) to
// x^(2^(k+1) - 1) with one square and one multiply. Used once per check.
inline block gf_inv(block x) {
  block y = x;   // x^(2^1 - 1)
  for (int k = 1; k < 127; ++k) {
    gfmul(y, y, &y);
    gfmul(y, x, &y);
  }
  gfmul(y, y, &y);   // x^(2^128 - 2)
  return y;
}

// Lanes per RLC fold: K independent Horner chains, so the carryless multiplies pipeline
// (throughput-1, latency-several cycles). Purely local ILP — the folded VALUE is the same
// field element as the serial sum (every term is mu_a * chi^{a+1}, and field arithmetic is
// exact), so lane counts never need cross-party agreement.
inline constexpr int kRlcLanes = 8;

// m = XOR_a chi^{a+1} * mu_a over mu[0, n): width-split across the pool. Within a worker's
// range [a0, a1), lane j takes a0 + j + K*t and runs Horner from its last row down,
// acc_j = XOR_t chi^{K t} * mu[a0 + j + K t], one multiplication per term; it is then
// lifted by chi^{a0 + j + 1} once.
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
      const block powK = gf_pow(chi, K);
      block acc[K];
      for (int j = 0; j < K; ++j) acc[j] = zero_block;
      const int rows = (a1 - a0 + K - 1) / K;
      for (int r = rows - 1; r >= 0; --r) {
        const int base = a0 + K * r;
        const int len = std::min(K, a1 - base);   // the last row may be short
        for (int j = 0; j < K; ++j) {
          gfmul(acc[j], powK, &acc[j]);
          if (j < len) acc[j] = acc[j] ^ mu[base + j];
        }
      }
      block p = gf_pow(chi, (uint64_t)a0 + 1), m = zero_block;
      for (int j = 0; j < K; ++j) {   // lane j's terms carry chi^{a0 + j + 1} on top
        block lift;
        gfmul(acc[j], p, &lift);
        m = m ^ lift;
        gfmul(p, chi, &p);
      }
      part[t] = m;
    }));
  }
  joinNclean(res);
  block m = zero_block;
  for (int i = 0; i < nt; ++i) m = m ^ part[i];
  return m;
}

EMP_AG_NAMESPACE_END
#endif // EMP_AG_BACKEND_GARBLE_SPDZ_H__
