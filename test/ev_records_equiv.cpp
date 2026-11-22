// Value-identity guard for P1's draw-time record extraction (garble/passes/draw_beaver.h
// in-walk capture + sigma sweep -> state.h ev_tg/ev_mu) against the live-bundle kernels
// (tgamma_witness_garbler / collapse_cgamma_witness) that compute the same per-AND terms.
//
// The eval walk consumes two bundle-derived quantities per AND, both affine in the
// masked values (La, Lb) unknown until eval:
//   tgamma row  Mr(1,i) = tgamma_witness_garbler(La, Lb, in0, in1, out, sig, i-2)
//   c_gamma mu  = collapse_cgamma_witness(La, Lb, Lg, in0, in1, out, sig, Delta)
// The capture and the sigma sweep store their affine bases from the DrawBeaverPass
// captures (acc a/b
// MAC/KEY rows, the pool SoA out rows, the share bits) plus sigma:
//   TG: A_i = in1.mac(i-2), B_i = in0.mac(i-2), C_i = out.mac(i-2) ^ sig.mac(i-2)
//   MU: s1 = spdz(in1), s2 = spdz(in0), s0 = spdz(out) ^ spdz(sig), each spdz
//       assembled from the rows as own_bit*Delta ^ mac-sum ^ key-sum.
// This test emulates the captures from random bundles and pins both folds
// bit-for-bit at nP=2/3/4 for all 8 (La, Lb, Lg) selections. trace_np2 pins the
// transcript only at nP==2; at nP>=3 a divergence would surface only as a
// poorly-localized MACCheck abort, so the identity is pinned here directly.
#include "emp-ag/backend/ashare/share.h"
#include "emp-ag/backend/garble/spdz.h"
#include "emp-ag/backend/garble/halfgate.h"
#include "emp-tool/emp-tool.h"
#include <cstdio>
#include <cstdlib>

using namespace emp;

template <int nP>
static void check() {
  PRG prg;
  for (int iter = 0; iter < 4000; ++iter) {
    ag::AShareBundle<nP> in0, in1, out, sig;
    prg.random_block(in0.km, ag::AShareBundle<nP>::N);
    prg.random_block(in1.km, ag::AShareBundle<nP>::N);
    prg.random_block(out.km, ag::AShareBundle<nP>::N);
    prg.random_block(sig.km, ag::AShareBundle<nP>::N);
    block Delta;
    prg.random_block(&Delta, 1);

    // --- the DrawBeaverPass captures, as draw_and_seed sees them ---
    // acc a-row = in0's (mac,key) per peer slot; b-row = in1's; pre = out's;
    // a_bit/b_bit = own bits (bit0 of mac slot 0).
    // In-walk capture (before and_prep->run) + sigma sweep (fold sigma).
    block tg[3 * (nP - 1)];
    block m1 = zero_block, k1 = zero_block;
    block m0 = zero_block, k0 = zero_block;
    block mo = zero_block, ko = zero_block;
    for (int i = 2; i <= nP; ++i) {
      const int s = i - 2;
      tg[3 * s + 0] = in1.mac(s);                    // A_i (La-gated)
      tg[3 * s + 1] = in0.mac(s);                    // B_i (Lb-gated)
      tg[3 * s + 2] = out.mac(s) ^ sig.mac(s);       // C_i (capture + sigma sweep)
      m1 = m1 ^ in1.mac(s); k1 = k1 ^ in1.key(s);
      m0 = m0 ^ in0.mac(s); k0 = k0 ^ in0.key(s);
      mo = mo ^ out.mac(s); ko = ko ^ out.key(s);
    }
    const unsigned char a_bit = (unsigned char)getLSB(in0.mac(0));
    const unsigned char b_bit = (unsigned char)getLSB(in1.mac(0));
    block s0 = (select_mask[getLSB(out.mac(0))] & Delta) ^ mo ^ ko;   // capture
    s0 = s0 ^ ag::spdz_mac_share(sig, Delta);                          // sigma sweep
    const block s1 = (select_mask[b_bit] & Delta) ^ m1 ^ k1;
    const block s2 = (select_mask[a_bit] & Delta) ^ m0 ^ k0;

    for (int m = 0; m < 8; ++m) {
      bool La = m & 1, Lb = m & 2, Lg = m & 4;
      const block mLa = select_mask[La], mLb = select_mask[Lb];
      // tgamma rows: record fold (garble/passes/evaluate.h) vs live-bundle kernel.
      for (int i = 2; i <= nP; ++i) {
        const block *r = tg + 3 * (i - 2);
        block rec = r[2] ^ (r[0] & mLa) ^ (r[1] & mLb);
        block live =
            ag::tgamma_witness_garbler(La, Lb, in0, in1, out, sig, i - 2);
        if (!cmpBlock(&rec, &live, 1)) {
          printf("TG MISMATCH nP=%d iter=%d i=%d (La=%d Lb=%d)\n", nP, iter, i,
                 La, Lb);
          exit(1);
        }
      }
      // mu: record fold vs live-bundle collapse.
      block mu_rec = ag::collapse_cgamma_from_records(La, Lb, Lg, s0, s1, s2, Delta);
      block mu_live =
          ag::collapse_cgamma_witness(La, Lb, Lg, in0, in1, out, sig, Delta);
      if (!cmpBlock(&mu_rec, &mu_live, 1)) {
        printf("MU MISMATCH nP=%d iter=%d (La=%d Lb=%d Lg=%d)\n", nP, iter, La,
               Lb, Lg);
        exit(1);
      }
    }
  }
}

int main() {
  check<2>();
  check<3>();
  check<4>();
  printf("GOOD!\n");
  return 0;
}
