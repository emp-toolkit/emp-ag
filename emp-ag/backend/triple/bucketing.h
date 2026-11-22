#ifndef EMP_AG_BACKEND_TRIPLE_BUCKETING_H__
#define EMP_AG_BACKEND_TRIPLE_BUCKETING_H__
//
// The bound of the bucketing (triple/merge.h), and the leaky ANDs' bucket size from it.
//
// A pure function of (B, ell) and (ell = number of output triples, ssp), so the derivation
// is one copy and unit-testable in isolation. A wrong bucket size silently widens residual
// leakage and is invisible to functional tests, so it is derived from the proof bound,
// not tuned by hand.
//
// B rows of ell candidates, row 0 fixed and row m >= 1 rotated by r_m uniform in
// [0, ell), drawn after the rows are fixed. Let c_m be the number of leaky candidates in
// row m, each surviving its check with probability at most 1/2. Bucket j holds only
// leaky candidates only if j is leaky in row 0 and every r_m maps j onto a leaky
// candidate of row m, which has probability c_m / ell for each m; so, over row 0's c_0
// leaky positions, some bucket does with probability at most prod_m c_m / ell^{B-1}. All
// leaky candidates survive with probability at most 2^{-sum_m c_m}, independently of the
// rotations. Since c 2^{-c} <= 1/2 for every integer c >= 1 (and with some c_m = 0 no
// bucket is all leaky),
//   Pr[Leak] <= prod_m c_m 2^{-c_m} / ell^{B-1} <= 2^{-B} ell^{1-B}.
// The same bound holds at every party count and for both protocols that bucket: the
// leaky ANDs (bucket_size below) and the cut-and-choose triples' combine, whose leaky
// heads it counts (triple/cut_and_choose_bound.h).
//
#include <algorithm>
#include <cmath>

namespace emp::ag {

// log2 of the bound above, 2^{-B} ell^{1-B}, given log2(ell).
inline double bucket_log2_leakage(int B, double log2_ell) {
  return -(double)B - (double)(B - 1) * log2_ell;
}

// The leaky ANDs' bucket size: the smallest B >= 2 whose bound is at most 2^{-ssp}. With
// one output triple (ell == 1) every rotation is zero, so the bound is 2^{-B} and B = ssp.
inline int bucket_size(int ell, int ssp) {
  const double log2_ell = std::log2((double)std::max(ell, 1));
  int B = 2;
  while (bucket_log2_leakage(B, log2_ell) > -(double)ssp) ++B;
  return B;
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_TRIPLE_BUCKETING_H__
