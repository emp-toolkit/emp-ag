// The three ways to run a circuit on AGMPCSession — the same computation,
// (x + y) * (x XOR y), authored three ways:
//
//   1. direct:   operators on live session values record gates as they execute;
//   2. body:     sess.run(pure_lambda, args...) replays a pure body on the fly;
//   3. compiled: frontend::compile records the body once into a reusable
//                circuit that any session can replay via sess.run(circuit, ...).
//
// Plus the composition mode: run_compose chains a compiled unit output->input
// (here f(s) = 3s + 1, five times) without materializing the flattened circuit.
// All four results are revealed to party 1 and checked against cleartext.
// Run from the repo root:
//
//   ./runN 3 build/bin/example_modes
#include <emp-ag/emp-ag.h>
#include "emp-tool/circuits/frontend/rec.h"
#include "emp-tool/circuits/frontend/compose.h"
#include <cstdio>
using namespace emp;
namespace cf = emp::frontend;

constexpr int nP = 3;

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(), /*ip table*/ nullptr, &pool);

  using Ctx    = AGMPCSession<nP>::ctx_t;
  using UInt32 = UInt_T<Ctx, 32>;
  auto in = [&](int owner, uint32_t v) {
    return sess.input<UInt32>(owner, party == owner ? v : 0u);
  };
  auto out = [&](auto w) { return sess.reveal(w, /*recipient*/ 1).value_or(0); };

  const uint32_t X = 1234567u, Y = 7654321u;
  const uint32_t expect = (X + Y) * (X ^ Y);
  auto f = [](auto x, auto y) { return (x + y) * (x ^ y); };

  // 1. direct: gates record as the operators run.
  uint32_t direct;
  {
    auto a = in(1, X), b = in(2, Y);
    direct = out((a + b) * (a ^ b));
  }

  // 2. body: the same computation as a pure lambda, replayed live.
  uint32_t body;
  {
    auto a = in(1, X), b = in(2, Y);
    body = out(sess.run(f, a, b));
  }

  // 3. compiled: record once over RecordCtx, replay the artifact on the session.
  uint32_t compiled;
  {
    auto circ = cf::compile<rec::UInt<32>, rec::UInt<32>>(f);
    auto a = in(1, X), b = in(2, Y);
    compiled = out(sess.run(circ, a, b));
  }

  // Composition: a compiled unit g(s) = 3s + 1 chained five times, output->input.
  const uint32_t S = 0xDEADBEEFu;
  uint32_t chain_expect = S;
  for (int i = 0; i < 5; ++i) chain_expect = chain_expect * 3u + 1u;
  uint32_t chained;
  {
    auto unit = cf::compile_linear<rec::UInt<32>>(
        [](auto s) { return s * s.constant(3u) + s.constant(1u); });
    auto s0 = in(1, S);
    chained = out(sess.run_compose([&unit](auto &ctx, auto st) {
      for (int i = 0; i < 5; ++i) st = cf::run(ctx, unit, st);
      return st;
    }, s0));
  }

  if (party == 1) {
    bool ok = direct == expect && body == expect && compiled == expect &&
              chained == chain_expect;
    printf("direct=%u body=%u compiled=%u (expect %u); chained=%u (expect %u)  %s\n",
           direct, body, compiled, expect, chained, chain_expect,
           ok ? "GOOD!" : "BAD!");
    return ok ? 0 : 1;                             // the ctest verdict
  }
  return 0;
}
