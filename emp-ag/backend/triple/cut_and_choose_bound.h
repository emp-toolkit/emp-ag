#ifndef EMP_AG_BACKEND_TRIPLE_CUT_AND_CHOOSE_BOUND_H__
#define EMP_AG_BACKEND_TRIPLE_CUT_AND_CHOOSE_BOUND_H__
//
// Parameters of the cut-and-choose triple generator (triple/cut_and_choose_triples.h).
// A pure function of the number of output triples and the batch's statistical target, so
// the derivation is one copy and unit-testable in isolation
// (test/cut_and_choose_bound_test.cpp). A wrong parameter is invisible to every
// functional test: it only widens the error or leakage probability.
//
// A batch makes pop = t*T + cut candidate triples; then one coin fixes three things:
//   cut        a uniform subset of `cut` candidates, opened and checked (a*b == c);
//   sacrifice  the other t*T in T groups of t, t prime: head h of group 0 is checked
//              against position (h + s_k) mod t of every group k >= 1, one uniform shift
//              s_k per group, and a check passes iff the two candidates have equal errors;
//   combine    the heads [0, B*ell) in B groups of ell: output j merges position j of
//              group 0 with position (j + r_m) mod ell of every group m >= 1.
//
// Correctness. Fix the error pattern before the coin. If group 0's pattern is neither all
// correct nor all incorrect, it has no rotation symmetry when t is prime, so at most one
// shift per group k makes group k's pattern match it: the sacrifice passes with
// probability at most t^(1-T). If group 0 is all incorrect, passing needs the whole body
// incorrect and the whole cut correct, so the correct candidates must be exactly the cut:
// probability at most 1 / C(pop, cut). A composite t would admit periodic patterns, which
// pass whenever every shift is a multiple of the period.
//
// Leakage. A tampered product leaks the candidate's a, and the candidate survives with
// probability 1/2. Through the sacrifice's public a_h ^ a_k the leak reaches the head, so
// leaky heads are counted after the sacrifice: a head is leaky only if some member of its
// sacrifice bucket was tampered, so there are at most as many leaky heads as tampered
// candidates, and the batch passes with probability at most 2^-(leaky heads). With c_m
// leaky heads in combine group m, a union bound over group 0's gives
// prod_m c_m 2^-c_m / ell^(B-1) <= 2^-B ell^(1-B) that some output has only leaky members:
// the bucketing's bound (triple/bucketing.h), which the leaky ANDs use too.
//
// A session spends its 2^-ssp over its batches: batch i (from 1) is held to
// 2^-ssp / (i (i + 1)), and these sum to 2^-ssp.
//
#include "emp-ag/backend/triple/bucketing.h"   // bucket_log2_leakage
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <utility>
#include <vector>

namespace emp::ag {

struct CutAndChooseParams {
  int64_t ell = 0;               // output triples
  int B = 0;                     // combine bucket size
  int T = 0;                     // sacrifice groups
  int64_t t = 0;                 // sacrifice group size: the smallest prime >= B * ell
  int64_t cut = 0;               // candidates the cut opens
  int64_t pop = 0;               // candidates: t * T + cut
  double log2_correctness = 0;   // log2 of t^(1-T) + 1 / C(pop, cut)
  double log2_leakage = 0;       // log2 of 2^-B ell^(1-B)
};

inline bool cut_and_choose_is_prime(int64_t n) {
  if (n < 2) return false;
  if (n % 2 == 0) return n == 2;
  if (n % 3 == 0) return n == 3;
  for (int64_t d = 5; d * d <= n; d += 6)
    if (n % d == 0 || n % (d + 2) == 0) return false;
  return true;
}

// log2 C(n, k) and log2(2^x + 2^y).
inline double cut_and_choose_log2_binomial(int64_t n, int64_t k) {
  return (std::lgamma((double)n + 1) - std::lgamma((double)k + 1) -
          std::lgamma((double)(n - k) + 1)) / std::log(2.0);
}
inline double cut_and_choose_log2_add(double x, double y) {
  const double hi = std::max(x, y), lo = std::min(x, y);
  return hi + std::log2(1.0 + std::exp2(lo - hi));
}

// The statistical target, in bits, of batch i (from 1) of a session at ssp.
inline double cut_and_choose_batch_target(int ssp, int64_t batch) {
  return (double)ssp + std::log2((double)batch) + std::log2((double)batch + 1);
}

// The parameters with the fewest candidates for ell outputs whose two bounds sum to at
// most 2^-target. The cut is FKOS15's 3 log2 t (at least T), far more than the
// all-incorrect case needs; its exact term is part of the correctness bound.
inline CutAndChooseParams cut_and_choose_params(int64_t ell, double target) {
  CutAndChooseParams best;
  if (ell < 1 || !(target > 0)) return best;
  const double log2_ell = std::log2((double)ell);
  const int max_size = (int)target + 2;
  for (int B = 2; B <= max_size; ++B) {
    if (best.pop > 0 && 2 * (int64_t)B * ell > best.pop) break;   // pop >= 2t >= 2 B ell
    const double leak = bucket_log2_leakage(B, log2_ell);
    if (leak >= -target) continue;
    int64_t t = (int64_t)B * ell;
    while (!cut_and_choose_is_prime(t)) ++t;
    const double log2_t = std::log2((double)t);
    for (int T = 2; T <= max_size; ++T) {
      const int64_t cut = std::max<int64_t>(T, (int64_t)std::ceil(3 * log2_t));
      const int64_t pop = t * T + cut;
      const double corr = cut_and_choose_log2_add((1.0 - T) * log2_t,
                                                  -cut_and_choose_log2_binomial(pop, cut));
      if (cut_and_choose_log2_add(corr, leak) > -target) continue;
      if (best.pop == 0 || pop < best.pop) best = {ell, B, T, t, cut, pop, corr, leak};
      break;
    }
  }
  return best;
}

// The swaps that move the cut, an ascending subset of [0, pop), to the tail [body, pop),
// so that sacrifice group k is [k t, (k + 1) t): each pairs a subset position below body
// with a tail position outside the subset.
inline std::vector<std::pair<int64_t, int64_t>> cut_and_choose_tail_swaps(
    int64_t pop, int64_t body, const std::vector<int64_t> &subset) {
  std::vector<int64_t> spare;
  for (int64_t q = body; q < pop; ++q)
    if (!std::binary_search(subset.begin(), subset.end(), q)) spare.push_back(q);
  std::vector<std::pair<int64_t, int64_t>> swaps;
  for (int64_t q : subset) {
    if (q >= body) continue;
    swaps.emplace_back(q, spare.back());
    spare.pop_back();
  }
  return swaps;
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_TRIPLE_CUT_AND_CHOOSE_BOUND_H__
