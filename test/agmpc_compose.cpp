// Compose path equivalence (nP-party). A body that calls a pre-compiled Linear unit
// via run(ctx, unit, args) must, run through run_compose (run is opaque on a
// ComposeCtx -> instances replayed on the fly by run_composed, nothing flattened),
// reveal the SAME output as the SAME body COMPILED FLAT (run inlines the unit) and
// run as a normal program, AND as a plaintext oracle. Covers a chain (output->input)
// and SIMD + glue (two instances, results added). Regression gate for run_composed.
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/transform.h"
#include "emp-tool/circuits/frontend/rec.h"
#include "emp-tool/circuits/frontend/compose.h"
#include "emp-ag/emp-ag.h"
#include "test_options.h"
#include <cstdio>
using namespace std;
using namespace emp;
namespace cf = emp::frontend;

const static int nP = 3;

// f(s) = s*3 + 1 over UInt32 (the shared unit).
static uint32_t f_clear(uint32_t s) { return s * 3u + 1u; }

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool, test_options(TestArgs(argc, argv, {TEST_OPTION_ARGS})));
  using Ctx = AGMPCSession<nP>::ctx_t;
  using UInt32 = UInt_T<Ctx, 32>;

  auto unit = cf::compile_linear<rec::UInt<32>>(
      [](auto s) { return s * s.constant(3u) + s.constant(1u); });
  const uint32_t S = 0xDEADBEEFu, A = 0xC0FFEEu, B = 0x1234567u;
  bool ok = true;

  // ---- chain: call the unit 5x, output -> input ----
  {
    auto body = [&unit](auto &ctx, auto s) {
      for (int i = 0; i < 5; ++i) s = cf::run(ctx, unit, s);
      return s;
    };
    auto flat = cf::compile<rec::UInt<32>>(body);   // run inlines the unit -> dense flat

    auto s1 = sess.input<UInt32>(1, party == 1 ? S : 0);
    auto zf = sess.run(flat, s1);                   // dense
    auto rf = sess.reveal(zf, 1);

    auto s2 = sess.input<UInt32>(1, party == 1 ? S : 0);
    auto zc = sess.run_compose(body, s2);           // compose (run_composed)
    auto rc = sess.reveal(zc, 1);

    if (party == 1) {
      uint32_t expect = S;
      for (int i = 0; i < 5; ++i) expect = f_clear(expect);
      bool agree = rf.has_value() && rc.has_value() && rf.value() == rc.value();
      bool correct = rc.has_value() && (uint32_t)rc.value() == expect;
      printf("compose[chain x5 ] flat==compose=%d  correct=%d  %s\n",
             (int)agree, (int)correct, (agree && correct) ? "GOOD!" : "BAD!");
      ok &= agree && correct;
    }
  }

  // ---- SIMD + glue: two independent instances, results added ----
  {
    auto body = [&unit](auto &ctx, auto a, auto b) {
      auto x = cf::run(ctx, unit, a);
      auto y = cf::run(ctx, unit, b);
      return x + y;
    };
    auto flat = cf::compile<rec::UInt<32>, rec::UInt<32>>(body);

    auto a1 = sess.input<UInt32>(1, party == 1 ? A : 0);
    auto b1 = sess.input<UInt32>(2, party == 2 ? B : 0);
    auto zf = sess.run(flat, a1, b1);
    auto rf = sess.reveal(zf, 1);

    auto a2 = sess.input<UInt32>(1, party == 1 ? A : 0);
    auto b2 = sess.input<UInt32>(2, party == 2 ? B : 0);
    auto zc = sess.run_compose(body, a2, b2);
    auto rc = sess.reveal(zc, 1);

    if (party == 1) {
      uint32_t expect = f_clear(A) + f_clear(B);
      bool agree = rf.has_value() && rc.has_value() && rf.value() == rc.value();
      bool correct = rc.has_value() && (uint32_t)rc.value() == expect;
      printf("compose[simd+glue] flat==compose=%d  correct=%d  %s\n",
             (int)agree, (int)correct, (agree && correct) ? "GOOD!" : "BAD!");
      ok &= agree && correct;
    }
  }

  // ---- run_tiled sugar: same as the chain, via the one-liner ----
  {
    auto s3 = sess.input<UInt32>(1, party == 1 ? S : 0);
    auto zt = sess.run_tiled(unit, 5, s3);
    auto rt = sess.reveal(zt, 1);
    if (party == 1) {
      uint32_t expect = S;
      for (int i = 0; i < 5; ++i) expect = f_clear(expect);
      bool correct = rt.has_value() && (uint32_t)rt.value() == expect;
      printf("compose[run_tiled] correct=%d  %s\n", (int)correct, correct ? "GOOD!" : "BAD!");
      ok &= correct;
    }
  }

  if (party == 1)
    printf("agmpc_compose: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == 1 && !ok) ? 1 : 0;
}
