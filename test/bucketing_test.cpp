// Verify the cut-and-choose bucket-size derivation (emp-ag/backend/crypto/bucketing.h) against
// the proof bound directly. A wrong B is invisible to every functional/transcript test
// (it only widens residual leakage), so this is the gate that the derivation matches the
// residual-leakage bound.
//
// Pure-math test: includes only the header, no protocol run, no emp deps.
#include "emp-ag/backend/crypto/bucketing.h"
#include <algorithm>
#include <cmath>
#include <cstdio>
using emp::ag::bucket_size;

// The proof predicate "bucket B is safe at (ell, ssp)". emp-ag provisions off the
// FIRST-MOMENT form of the aAND bound:
//   Pr[Leak] <= max_{B<=g<=B*ell} 2^{-g} * (g/B)^B / ell^{B-1}
// (E[# fully-leaky buckets] with AM-GM-optimal placement, times the 2^{-g} survival; Markov).
// So B is safe when that max is <= 2^{-ssp}. It is <= the union count C(g,B)*g, hence
// <= the (2B+1)/ell^{B-1} form. Same at every nP.
static double log2_leak(int B, int ell) {
  double m = -1e300;  // log2 max over feasible g; unconstrained peak ~1.4427 B
  // There are only B*ell candidates.  The cap matters exactly at ell==1,
  // where g==B is the sole fully-leaky-bucket event; for ell>=2 the peak near
  // 1.4427B is already below the cap.
  const int g_max = std::min(4 * B + 16, B * ell);
  for (int g = B; g <= g_max; ++g)
    m = std::max(m, -(double)g + (double)B * std::log2((double)g / (double)B));
  return m - (double)(B - 1) * std::log2((double)ell);
}
static bool safe(int B, int ell, int ssp) { return log2_leak(B, ell) <= -(double)ssp; }

int main() {
  bool ok = true;
  const int ells[] = {1, 2, 320, 3100, 50000, 280000, 1000000, 10000000};
  const int ssps[] = {40, 60, 80};

  for (int ssp : ssps)
    for (int ell : ells) {
      // The returned B is safe, and B-1 (>=2) is not (minimality).
      int B = bucket_size(ell, ssp);
      if (!safe(B, ell, ssp)) { ok = false; printf("unsafe ell=%d ssp=%d B=%d\n", ell, ssp, B); }
      if (B > 2 && safe(B - 1, ell, ssp)) { ok = false; printf("not minimal ell=%d ssp=%d B=%d\n", ell, ssp, B); }
    }

  // Pin known outcomes of the first-moment bound: B=6 at (320,40), B=4 at ell=280k, and
  // B=3 at ell=1e6. A looser bound, or an over-tight bug that under-provisions, trips here.
  if (bucket_size(1, 40)       != 40) { ok = false; printf("regression: ell=1 ssp=40 B=%d (expect 40)\n", bucket_size(1, 40)); }
  if (bucket_size(1, 60)       != 60) { ok = false; printf("regression: ell=1 ssp=60 B=%d (expect 60)\n", bucket_size(1, 60)); }
  if (bucket_size(1, 80)       != 80) { ok = false; printf("regression: ell=1 ssp=80 B=%d (expect 80)\n", bucket_size(1, 80)); }
  if (bucket_size(320, 40)     != 6) { ok = false; printf("regression: ell=320 ssp=40 B=%d (expect 6)\n", bucket_size(320, 40)); }
  if (bucket_size(4096, 39)    != 4) { ok = false; printf("regression: ell=4096 ssp=39 B=%d (expect 4)\n", bucket_size(4096, 39)); }
  if (bucket_size(4096, 40)    != 5) { ok = false; printf("regression: ell=4096 ssp=40 B=%d (expect 5)\n", bucket_size(4096, 40)); }
  if (bucket_size(280000, 40)  != 4) { ok = false; printf("regression: ell=280k ssp=40 B=%d (expect 4)\n", bucket_size(280000, 40)); }
  if (bucket_size(1000000, 40) != 3) { ok = false; printf("regression: ell=1e6 ssp=40 B=%d (expect 3)\n", bucket_size(1000000, 40)); }

  printf("bucketing_test: %s\n", ok ? "GOOD!" : "BAD!");
  return ok ? 0 : 1;
}
