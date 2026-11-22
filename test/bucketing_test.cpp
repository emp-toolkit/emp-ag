// Verify the bucketing bound (emp-ag/backend/triple/bucketing.h) and the leaky ANDs'
// bucket size from it. A wrong B is invisible to every functional/transcript test (it
// only widens residual leakage), so this is the gate that the derivation matches the
// bound.
//
// Pure-math test: includes only the header, no protocol run, no emp deps.
#include "emp-ag/backend/triple/bucketing.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
#include <vector>
using emp::ag::bucket_log2_leakage;
using emp::ag::bucket_size;

// The bound before its last step, maximized by brute force over the numbers of leaky
// candidates per row: log2 of max over c_m in [0, ell] of prod_m c_m 2^{-c_m} / ell^{B-1}.
static double brute_log2_leak(int B, int ell) {
  std::vector<int> c((size_t)B, 0);
  double best = 0;
  while (true) {
    double v = 1;
    for (int m = 0; m < B; ++m) v *= (double)c[(size_t)m] * std::pow(2.0, -(double)c[(size_t)m]);
    best = std::max(best, v / std::pow((double)ell, (double)(B - 1)));
    int m = 0;
    while (m < B && c[(size_t)m] == ell) c[(size_t)m++] = 0;
    if (m == B) break;
    ++c[(size_t)m];
  }
  return std::log2(best);
}

// B is safe at (ell, ssp): 2^{-B} ell^{1-B} <= 2^{-ssp}.
static bool safe(int B, int ell, int ssp) {
  return -(double)B - (double)(B - 1) * std::log2((double)ell) <= -(double)ssp;
}

int main() {
  bool ok = true;

  // The bound's last step, c 2^{-c} <= 1/2 for every integer c >= 1, is tight at c = 1
  // and 2: on small shapes the brute-force maximum is exactly 2^{-B} ell^{1-B}.
  for (int B = 2; B <= 4; ++B)
    for (int ell = 1; ell <= 6; ++ell) {
      const double brute = brute_log2_leak(B, ell);
      const double closed = bucket_log2_leakage(B, std::log2((double)ell));
      if (std::fabs(brute - closed) > 1e-9) {
        ok = false;
        printf("bound mismatch B=%d ell=%d: brute %.6f closed %.6f\n", B, ell, brute, closed);
      }
    }

  const int ells[] = {1, 2, 320, 3100, 50000, 280000, 1000000, 10000000};
  const int ssps[] = {40, 60, 80};
  for (int ssp : ssps)
    for (int ell : ells) {
      // The returned B is safe, and B-1 (>=2) is not (minimality).
      int B = bucket_size(ell, ssp);
      if (!safe(B, ell, ssp)) { ok = false; printf("unsafe ell=%d ssp=%d B=%d\n", ell, ssp, B); }
      if (B > 2 && safe(B - 1, ell, ssp)) { ok = false; printf("not minimal ell=%d ssp=%d B=%d\n", ell, ssp, B); }
    }

  // Pin known outcomes, including both sides of B = 4 -> 3 and 5 -> 4 at ssp = 40. A
  // looser bound, or an over-tight bug that under-provisions, trips here.
  struct Pin { int ell, ssp, B; };
  const Pin pins[] = {{1, 40, 40},      {1, 60, 60},          {1, 80, 80},
                      {320, 40, 6},     {4095, 40, 5},        {4096, 40, 4},
                      {4096, 39, 4},    {280000, 40, 4},      {370727, 40, 4},
                      {370728, 40, 3},  {1000000, 40, 3}};
  for (const Pin &p : pins)
    if (bucket_size(p.ell, p.ssp) != p.B) {
      ok = false;
      printf("regression: ell=%d ssp=%d B=%d (expect %d)\n", p.ell, p.ssp,
             bucket_size(p.ell, p.ssp), p.B);
    }

  printf("bucketing_test: %s\n", ok ? "GOOD!" : "BAD!");
  return ok ? 0 : 1;
}
