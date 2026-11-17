#ifndef EMP_AG_BACKEND_CRYPTO_BUCKETING_H__
#define EMP_AG_BACKEND_CRYPTO_BUCKETING_H__
//
// Cut-and-choose bucket size for the LaAND -> AND-triple step.
//
// A pure function of (ell = number of output triples, ssp), so the derivation is one
// copy and unit-testable in isolation. A wrong bucket size silently widens residual
// leakage and is invisible to functional tests, so it is derived from the proof bound,
// not tuned by hand.
//
// Residual leakage over the draw count g (number of leaky triples the adversary makes)
// is bounded by the first-moment form
//   Pr[Leak] <= max_{B<=g<=B*ell}  2^{-g} * (g/B)^B / ell^{B-1}:
// survival 2^{-g} (each leaky triple aborts w.p. 1/2) times E[# fully-leaky buckets] =
// prod_k c_k / ell^{B-1} (linearity over columns; c_k = #leaky in row k), maximized over
// placements at c_k = g/B by AM-GM => (g/B)^B; Pr[>=1] <= E[#] (Markov). This is at most
// the union count 2^{-g} * C(g,B) * g / ell^{B-1} for every g. The max sits at
// g* ~ B/ln2 ~ 1.4427 B, giving the closed form 2^{-0.914 B}/ell^{B-1}.
//
// Governs bucketing at EVERY party count (the combine is the same cut-and-choose for any
// nP). The cyclic-shift bucket FOLD compute (block/select_mask) lives in
// the preprocessing layer so this header stays pure-math (no emp-tool dependency) and
// unit-testable in isolation.
//
#include <algorithm>
#include <cmath>

namespace emp::ag {

inline int bucket_size(int ell, int ssp) {
  // With one output bucket there are exactly B candidates total, every cyclic
  // shift is zero, and a fully leaky bucket requires g == B.  The constrained
  // first-moment term therefore collapses to 2^{-B}; pretending ell==2 here
  // would return B=22 at ssp=40 and provide only about 22 bits for a one-AND
  // reactive flush.  B>=ssp is both safe and minimal for this boundary case.
  if (ell == 1) return std::max(2, ssp);

  const double log2_l = std::log2((double)std::max(ell, 2));
  // log2 of the first-moment leak bound. For ell>=2 the feasible ceiling
  // g<=B*ell is above the peak, so it does not truncate the maximum.
  // g(g) = -g + B*log2(g/B) is unimodal, peaking at g* ~ 1.4427 B; scanning
  // g in [B, 4B+16] therefore captures the integer maximum.
  auto log2_leak = [&](int B) {
    double m = -1e300;
    for (int g = B; g <= 4 * B + 16; ++g)
      m = std::max(m, -(double)g + (double)B * std::log2((double)g / (double)B));
    return m - (double)(B - 1) * log2_l;
  };
  int B = 2;
  while (log2_leak(B) > -(double)ssp) ++B;  // smallest B>=2 with Pr[Leak] <= 2^{-ssp}
  return B;
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_CRYPTO_BUCKETING_H__
