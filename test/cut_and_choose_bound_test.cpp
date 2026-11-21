// Verify the cut-and-choose triple parameters (emp-ag/backend/crypto/cut_and_choose_bound.h)
// against the bounds they rest on. A wrong parameter is invisible to every functional test,
// so this is the gate that the derivation holds:
//   1. the rotation lemma: a pattern on Z_t that is neither all 0 nor all 1 has no
//      nontrivial rotation symmetry iff t is prime;
//   2. the correctness bound t^(1-T) + 1/C(pop, cut), against the exact probability over
//      every coin, maximized over every error pattern, for tiny batches;
//   3. the leakage bound 2^-B ell^(1-B), against the exact maximum over leaky-head sets;
//   4. the parameter search: valid, optimal over (B, T), and at known operating points.
//
// Pure-math test: includes only the header, no protocol run.
#include "emp-ag/backend/triple/cut_and_choose_bound.h"
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <vector>
using namespace emp::ag;

static bool ok = true;
static void fail(const char *what, long long a, long long b) {
  ok = false;
  std::printf("FAIL %s (%lld, %lld)\n", what, a, b);
}

// rot(p, s)[i] = p[(i + s) mod t]: the pattern a group shows after rotation by s.
static uint32_t rot(uint32_t p, int t, int s) {
  uint32_t r = 0;
  for (int i = 0; i < t; ++i)
    if ((p >> ((i + s) % t)) & 1) r |= 1u << i;
  return r;
}

// 1. Exactly the primes leave no pattern with a nontrivial symmetry.
static void test_rotation_lemma() {
  for (int t = 2; t <= 16; ++t) {
    bool some_symmetric = false;
    for (uint32_t p = 1; p + 1 < (1u << t); ++p)   // neither all 0 nor all 1
      for (int s = 1; s < t; ++s)
        if (rot(p, t, s) == p) some_symmetric = true;
    if (some_symmetric == cut_and_choose_is_prime(t)) fail("rotation lemma", t, some_symmetric);
  }
}

// 2. Exact correctness. Candidates carry an error bit; the coin is a cut subset plus T-1
// shifts. The batch is bad if every check passes and some head is incorrect.
static void combinations(int n, int k, int start, std::vector<int64_t> &cur,
                         std::vector<std::vector<int64_t>> &out) {
  if ((int)cur.size() == k) { out.push_back(cur); return; }
  for (int i = start; i < n; ++i) {
    cur.push_back(i);
    combinations(n, k, i + 1, cur, out);
    cur.pop_back();
  }
}
static void test_exact_correctness(int t, int T, int cut) {
  const int body = t * T, pop = body + cut;
  std::vector<std::vector<int64_t>> subsets;
  std::vector<int64_t> cur;
  combinations(pop, cut, 0, cur, subsets);
  // Per subset, the candidate at each body position after the move to the tail.
  std::vector<std::vector<int>> arrangement;
  for (const auto &sub : subsets) {
    std::vector<int> arr(pop);
    for (int i = 0; i < pop; ++i) arr[i] = i;
    for (const auto &[q, w] : cut_and_choose_tail_swaps(pop, body, sub)) std::swap(arr[q], arr[w]);
    arrangement.push_back(arr);
  }
  int shift_count = 1;
  for (int k = 1; k < T; ++k) shift_count *= t;
  const double coins = (double)subsets.size() * shift_count;
  double worst = 0;
  for (uint32_t E = 0; E < (1u << pop); ++E) {
    long long bad = 0;
    for (size_t si = 0; si < subsets.size(); ++si) {
      const std::vector<int> &arr = arrangement[si];
      bool cut_ok = true;
      for (int i = body; i < pop; ++i) cut_ok = cut_ok && !((E >> arr[i]) & 1);
      if (!cut_ok) continue;
      bool head_bad = false;
      for (int h = 0; h < t; ++h) head_bad = head_bad || ((E >> arr[h]) & 1);
      if (!head_bad) continue;
      for (int code = 0; code < shift_count; ++code) {
        bool pass = true;
        int c = code;
        for (int k = 1; k < T && pass; ++k) {
          const int s = c % t;
          c /= t;
          for (int h = 0; h < t && pass; ++h)
            pass = ((E >> arr[h]) & 1) == ((E >> arr[k * t + (h + s) % t]) & 1);
        }
        bad += pass;
      }
    }
    worst = std::max(worst, (double)bad / coins);
  }
  const double bound = std::exp2((1.0 - T) * std::log2((double)t)) +
                       std::exp2(-cut_and_choose_log2_binomial(pop, cut));
  if (worst > bound * (1 + 1e-12)) fail("exact correctness above bound", t * 100 + T, cut);
  std::printf("  correctness t=%d T=%d cut=%d: worst %.6f <= bound %.6f\n", t, T, cut, worst, bound);
}

// 3. Exact leakage. Heads [0, B ell) in B groups of ell; a set of leaky heads passes with
// probability 2^-(its size); output j is lost if all its members are leaky.
static void test_exact_leakage(int ell, int B) {
  const int heads = B * ell;
  int shift_count = 1;
  for (int m = 1; m < B; ++m) shift_count *= ell;
  double worst = 0;
  for (uint32_t L = 0; L < (1u << heads); ++L) {
    long long lost = 0;
    for (int code = 0; code < shift_count; ++code) {
      bool any = false;
      for (int j = 0; j < ell && !any; ++j) {
        bool all = (L >> j) & 1;
        int c = code;
        for (int m = 1; m < B && all; ++m) {
          const int r = c % ell;
          c /= ell;
          all = (L >> (m * ell + (j + r) % ell)) & 1;
        }
        any = all;
      }
      lost += any;
    }
    worst = std::max(worst, std::exp2(-(double)__builtin_popcount(L)) * lost / shift_count);
  }
  const double bound = std::exp2(-(double)B - (B - 1) * std::log2((double)ell));
  if (worst > bound * (1 + 1e-12)) fail("exact leakage above bound", ell, B);
  std::printf("  leakage ell=%d B=%d: worst %.6f <= bound %.6f\n", ell, B, worst, bound);
}

// 4. The parameter search.
static void test_params(int64_t ell, double target) {
  const CutAndChooseParams P = cut_and_choose_params(ell, target);
  if (P.pop <= 0) { fail("no parameters", ell, (long long)target); return; }
  if (!cut_and_choose_is_prime(P.t) || P.t < (int64_t)P.B * ell) fail("group size", ell, P.t);
  if (P.pop != P.t * P.T + P.cut || P.cut < P.T) fail("population", ell, P.pop);
  const double corr = cut_and_choose_log2_add((1.0 - P.T) * std::log2((double)P.t),
                                              -cut_and_choose_log2_binomial(P.pop, P.cut));
  const double leak = -(double)P.B - (P.B - 1) * std::log2((double)ell);
  if (cut_and_choose_log2_add(corr, leak) > -target + 1e-9) fail("bound not met", ell, P.pop);
  // No (B, T) needs fewer candidates.
  for (int B = 2; B <= P.B + 4; ++B) {
    int64_t t = (int64_t)B * ell;
    while (!cut_and_choose_is_prime(t)) ++t;
    for (int T = 2; T <= P.T + 4; ++T) {
      const int64_t cut = std::max<int64_t>(T, (int64_t)std::ceil(3 * std::log2((double)t)));
      const int64_t pop = t * T + cut;
      const double c = cut_and_choose_log2_add((1.0 - T) * std::log2((double)t),
                                               -cut_and_choose_log2_binomial(pop, cut));
      const double l = -(double)B - (B - 1) * std::log2((double)ell);
      if (cut_and_choose_log2_add(c, l) <= -target && pop < P.pop) fail("not optimal", ell, pop);
    }
  }
}

int main() {
  test_rotation_lemma();

  std::printf("exact correctness:\n");
  test_exact_correctness(2, 2, 1);
  test_exact_correctness(3, 2, 2);
  test_exact_correctness(5, 2, 2);
  test_exact_correctness(7, 2, 1);
  test_exact_correctness(2, 3, 2);
  test_exact_correctness(3, 3, 3);
  std::printf("exact leakage:\n");
  test_exact_leakage(3, 2);
  test_exact_leakage(5, 2);
  test_exact_leakage(8, 2);
  test_exact_leakage(3, 3);
  test_exact_leakage(4, 3);

  const int64_t ells[] = {1, 2, 64, 1000, 4096, 100000, 330000, 524288, 1 << 20, 10000000};
  const double targets[] = {40, 41, 42.58, 50, 80};
  for (double target : targets)
    for (int64_t ell : ells) test_params(ell, target);

  // Operating points: three and three from about half a million outputs at 40 bits; a
  // session's first batch, held to 41 bits, needs about a million.
  auto shape = [](int64_t ell, double target) {
    const CutAndChooseParams P = cut_and_choose_params(ell, target);
    return P.B * 10 + P.T;
  };
  if (shape(524288, 40) != 33) fail("2^19 at 40 bits", 524288, shape(524288, 40));
  if (shape(330000, 40) / 10 != 4) fail("330000 at 40 bits", 330000, shape(330000, 40));
  if (shape(1 << 20, 41) != 33) fail("2^20 at 41 bits", 1 << 20, shape(1 << 20, 41));
  if (shape(524288, 41) == 33) fail("2^19 at 41 bits", 524288, shape(524288, 41));

  // Cost: a session's first batch of 2^20 outputs draws 27 aShares per output triple
  // (3 per candidate, 9 candidates per output).
  {
    const CutAndChooseParams P = cut_and_choose_params(1 << 20, cut_and_choose_batch_target(40, 1));
    const double per = 3.0 * (double)P.pop / (double)P.ell;
    if (per > 27.01) fail("aShares per triple at 2^20", (long long)(per * 100), 2700);
  }

  // The session budget: batch i at ssp + log2(i (i + 1)), summing to at most 2^-ssp.
  if (std::fabs(cut_and_choose_batch_target(40, 1) - 41) > 1e-12) fail("batch 1 target", 1, 0);
  double spent = 0;
  for (int64_t i = 1; i <= 1000000; ++i) spent += std::exp2(40 - cut_and_choose_batch_target(40, i));
  if (spent > 1) fail("session budget overspent", (long long)(spent * 1e6), 1000000);

  std::printf(ok ? "cut_and_choose_bound_test: ALL PASS\n" : "cut_and_choose_bound_test: FAILED\n");
  return ok ? 0 : 1;
}
