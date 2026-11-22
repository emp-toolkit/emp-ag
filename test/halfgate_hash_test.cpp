// Half-gate hash layout (garble/halfgate.h): per AND gate, a sender's stream hashes
// both halves of every destination under distinct gids, and the evaluator's stream for
// that sender reproduces the garbler's hashes gate after gate.
//
// The halves must not share a gid. With one gid per destination, an AND whose inputs
// carry equal or complementary labels -- AND(a, a), or AND(a, NOT a), NOT XORing Delta
// into the labels -- hashes its second input's labels exactly as its first's. The
// garbler's self rows then satisfy G0 ^ G1 = a0 and every cross row S0 ^ S1 = 0, so P1,
// which holds a0 ^ Lambda_a * Delta, reads off Delta whenever Lambda_a = 1. This test
// drives the helpers the garble and evaluate passes call, at nP = 2, 3, 4, 5, 6, 8, 9
// and 10: one call per gate up to nP = 5 (6 lanes in an aligned run of 8 at nP = 4),
// then whole 8-lane calls with a shorter last one (8 + 2 lanes at nP = 6, 8 + 6 at
// nP = 8, 8 + 8 + 2 at nP = 10) or without (8 + 8 at nP = 9).
#include "emp-ag/backend/garble/halfgate.h"
#include "emp-ag/backend/ashare/share.h"
#include "emp-tool/emp-tool.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>

using namespace emp;

static bool same(const block &a, const block &b) { return memcmp(&a, &b, sizeof(block)) == 0; }

static void fail(const char *what, int nP, int sender, int gate) {
  printf("FAIL nP=%d sender=%d gate=%d: %s\n", nP, sender, gate, what);
  exit(1);
}

// AND(a, a) on even gates, AND(a, NOT a) on odd ones, over 20 consecutive gates per
// sender, the evaluator's stream advanced alongside the garbler's. D destinations: the
// garblers 2..nP (D = nP - 1), plus P1 under Auth::WRK (D = nP, its lanes last).
template <int nP, int D>
static void check_self_and_and_lockstep() {
  PRG prg;
  for (int iter = 0; iter < 20; ++iter) {
    block seed, Delta;
    prg.random_block(&seed, 1);
    prg.random_block(&Delta, 1);
    Delta = Delta | makeBlock(0, 1);   // bit0(Delta) = 1, as the pool pins it
    for (int sender = 2; sender <= nP; ++sender) {
      ag::HalfGateHash<nP> garbler, evaluator;
      garbler.setS(ag::halfgate_stream_start(seed, sender));
      evaluator.setS(ag::halfgate_stream_start(seed, sender));
      for (int gate = 0; gate < 20; ++gate) {
        block a0;
        prg.random_block(&a0, 1);
        const block b0 = (gate & 1) ? (a0 ^ Delta) : a0;
        block g[4 * D];
        for (int k = 0; k < D; ++k) {
          g[4 * k] = a0;
          g[4 * k + 1] = a0 ^ Delta;
          g[4 * k + 2] = b0;
          g[4 * k + 3] = b0 ^ Delta;
        }
        ag::halfgate_hash_garbler<nP, D>(garbler, g);

        for (int k = 0; k < D; ++k)
          for (int i = 0; i < 2; ++i)
            for (int j = 2; j < 4; ++j)
              if (same(g[4 * k + i], g[4 * k + j]))
                fail("the two halves of a destination hash a label alike", nP, sender, gate);
        for (int k1 = 0; k1 < D; ++k1)
          for (int k2 = 0; k2 < k1; ++k2)
            if (same(g[4 * k1], g[4 * k2]))
              fail("two destinations hash a label alike", nP, sender, gate);

        // Self row: both inputs carry the same share bundle, so only the hashes keep
        // G0 ^ G1 away from the garbler's 0-label (or its complement).
        ag::AShareBundle<nP> x, ab, out;
        prg.random_block(x.km, ag::AShareBundle<nP>::N);
        prg.random_block(ab.km, ag::AShareBundle<nP>::N);
        prg.random_block(out.km, ag::AShareBundle<nP>::N);
        const int s = sender - 2;
        block G0, G1, ml_g0;
        ag::self_halfgate_row(g[4 * s], g[4 * s + 1], g[4 * s + 2], g[4 * s + 3], a0,
                              x, x, ab, out, Delta, G0, G1, ml_g0);
        if (same(G0 ^ G1, a0) || same(G0 ^ G1, a0 ^ Delta))
          fail("self row: G0 ^ G1 reveals the 0-label", nP, sender, gate);
        // Cross rows: with equal input bundles S0 ^ S1 is the XOR of the four hashes.
        for (int k = 0; k < D; ++k)
          if (k != s && same(g[4 * k] ^ g[4 * k + 1] ^ g[4 * k + 2] ^ g[4 * k + 3], zero_block))
            fail("cross row: S0 ^ S1 = 0", nP, sender, gate);

        // The evaluator hashes its active labels at the same gids; (La, Lb) cycles
        // through all four masked-value pairs.
        const int La = (gate >> 1) & 1, Lb = gate & 1;
        block e[2 * D];
        for (int k = 0; k < D; ++k) {
          e[2 * k] = La ? (a0 ^ Delta) : a0;
          e[2 * k + 1] = Lb ? (b0 ^ Delta) : b0;
        }
        ag::halfgate_hash_evaluator<nP, D>(evaluator, e);
        for (int k = 0; k < D; ++k)
          if (!same(e[2 * k], g[4 * k + La]) || !same(e[2 * k + 1], g[4 * k + 2 + Lb]))
            fail("evaluator hash differs from the garbler's", nP, sender, gate);
      }
    }
  }
}

// The stream moves on every gate (the same labels hash differently at the next gate),
// and different senders' streams differ.
template <int nP, int D>
static void check_streams_advance_and_differ() {
  PRG prg;
  block seed, x, Delta;
  prg.random_block(&seed, 1);
  prg.random_block(&x, 1);
  prg.random_block(&Delta, 1);
  block first[nP + 1][4 * D];
  for (int sender = 2; sender <= nP; ++sender) {
    ag::HalfGateHash<nP> h;
    h.setS(ag::halfgate_stream_start(seed, sender));
    block prev[4 * D];
    for (int gate = 0; gate < 12; ++gate) {
      block g[4 * D];
      for (int i = 0; i < 4 * D; ++i) g[i] = (i & 1) ? (x ^ Delta) : x;
      ag::halfgate_hash_garbler<nP, D>(h, g);
      if (gate == 0) memcpy(first[sender], g, sizeof(g));
      else
        for (int i = 0; i < 4 * D; ++i)
          if (same(g[i], prev[i])) fail("stream did not advance", nP, sender, gate);
      memcpy(prev, g, sizeof(g));
    }
  }
  for (int s1 = 2; s1 <= nP; ++s1)
    for (int s2 = 2; s2 < s1; ++s2)
      for (int i = 0; i < 4 * D; ++i)
        if (same(first[s1][i], first[s2][i])) fail("two senders' streams agree", nP, s1, 0);
}

template <int nP>
static void check() {
  check_self_and_and_lockstep<nP, nP - 1>();     // KRRW
  check_streams_advance_and_differ<nP, nP - 1>();
  check_self_and_and_lockstep<nP, nP>();         // WRK: P1 is one more destination
  check_streams_advance_and_differ<nP, nP>();
}

int main() {
  check<2>();
  check<3>();
  check<4>();
  check<5>();
  check<6>();
  check<8>();
  check<9>();
  check<10>();
  printf("GOOD!\n");
  return 0;
}
