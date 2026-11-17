// Compiled / stored-program replay through AGMPCSession<2>'s passes:
//   1) a compiled UInt32 adder via sess.run(circuit, ...);
//   2) a hand-authored RecordCtx a+b BooleanProgram via sess.run_artifact<UInt32>;
//   3) a compiled fp32 adder (exercises the float .empbc builtin) via sess.run;
//   4) the pending-arg rule: a direct-chunk value is rejected by run() until a
//      checkpoint materializes it, after which run() accepts it.
//   5) reusing one mutable raw-program object rebuilds its lowering rather than
//      replaying a stale pointer-keyed cache entry.
//   6) a compiled Linear circuit exercises both owner-cache preparation and hit.
// n=2: party 1 = evaluator/verdict, party 2 = garbler; the output is revealed to
// party 1, which checks.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdint>
#include <cstdio>
#include <span>
using namespace std;
using namespace emp;
namespace cf = emp::frontend;

const static int nP = 2;

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool);

  using UInt32 = UInt_T<AGMPCSession<nP>::ctx_t, 32>;
  using Float32 = Float_T<AGMPCSession<nP>::ctx_t, 32>;
  using Bit = Bit_T<AGMPCSession<nP>::ctx_t>;
  bool ok = true;

  // 1) compiled UInt32 adder, replayed standalone.
  {
    const uint32_t xa = 1234567u, yb = 7654321u, ref = xa + yb;
    auto c = cf::compile<rec::UInt<32>, rec::UInt<32>>([](auto x, auto y) { return x + y; });
    auto a = sess.input<UInt32>(1, party == 1 ? xa : 0);
    auto b = sess.input<UInt32>(2, party == 2 ? yb : 0);
    uint32_t got = (uint32_t)sess.reveal(sess.run(c, a, b), 1).value_or(0);
    if (party == 1) {
      ok &= (got == ref);
      printf("  compiled run UInt32 a+b = %u (exp %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
    }
  }

  // 2) hand-authored RecordCtx a+b program, run via the typed raw-program path.
  {
    RecordCtx rc;
    uint32_t base = rc.external_input(64);
    uint32_t aw[32], bw[32];
    for (int i = 0; i < 32; ++i) { aw[i] = base + i; bw[i] = base + 32 + i; }
    auto rs = UInt_T<RecordCtx, 32>::from_wires(rc, aw) +
              UInt_T<RecordCtx, 32>::from_wires(rc, bw);
    uint32_t outw[32]; rs.pack_wires(outw);
    circuit::BooleanProgram prog = rc.finish(std::span<const uint32_t>(outw, 32));

    const uint32_t xa = 1000u, yb = 2000u, ref = xa + yb;
    auto a = sess.input<UInt32>(1, party == 1 ? xa : 0);
    auto b = sess.input<UInt32>(2, party == 2 ? yb : 0);
    uint32_t got = (uint32_t)sess.reveal(sess.run_artifact<UInt32>(prog, a, b), 1).value_or(0);
    if (party == 1) {
      ok &= (got == ref);
      printf("  run_artifact hand-authored a+b = %u (exp %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
    }
  }

  // 3) compiled fp32 adder (float builtin): 1.5 + 2.25 = 3.75.
  {
    auto cfp = cf::compile<rec::Float<32>, rec::Float<32>>([](auto a, auto b) { return a + b; });
    auto a = sess.input<Float32>(1, party == 1 ? 1.5f : 0.0f);
    auto b = sess.input<Float32>(2, party == 2 ? 2.25f : 0.0f);
    float got = sess.reveal(sess.run(cfp, a, b), 1).value_or(0.0f);
    if (party == 1) {
      ok &= (got == 3.75f);
      printf("  compiled run Float32 1.5+2.25 = %g (exp 3.75)  %s\n", got,
             got == 3.75f ? "GOOD!" : "BAD!");
    }
  }

  // 4) checkpoint -> run: a pending direct-chunk value is not a valid run() arg,
  // but checkpointing it materializes the value so run() accepts it. (The negative
  // half — passing a still-pending value — is an expecting() -> _Exit(1) that would
  // desync a live multi-party run, so it is validated by construction rather than
  // death-tested here.)
  {
    const uint32_t xa = 70u, yb = 5u, ref = (xa + yb) + yb;
    auto c = cf::compile<rec::UInt<32>, rec::UInt<32>>([](auto x, auto y) { return x + y; });
    auto a = sess.input<UInt32>(1, party == 1 ? xa : 0);
    auto b = sess.input<UInt32>(2, party == 2 ? yb : 0);
    auto z = a + b;            // pending in the open direct chunk
    sess.checkpoint(z, b);     // materialize z (and keep b) -> now valid run() args
    uint32_t got = (uint32_t)sess.reveal(sess.run(c, z, b), 1).value_or(0);
    if (party == 1) {
      ok &= (got == ref);
      printf("  checkpoint(z) then run(c, z, b) = %u (exp %u)  %s\n", got, ref,
             got == ref ? "GOOD!" : "BAD!");
    }
  }

  // 5) The raw-program escape hatch is mutable. These two valid Linear programs
  // have identical shape and identical first/last gates but differ at one middle
  // operand. A cross-call cache keyed only by object address would return 0 twice.
  {
    circuit::BooleanProgram prog;
    prog.num_inputs = 2;
    prog.num_wires = 6;
    prog.wire_reuse = circuit::WireReuse::Linear;
    prog.gates = {
        {0, 1, 2, circuit::Op::And},
        {2, 1, 3, circuit::Op::Xor},
        {3, 0, 4, circuit::Op::Not},
        {4, 0, 5, circuit::Op::Xor},
    };
    prog.outputs = {5};

    auto x = sess.input<Bit>(1, party == 1);
    auto y = sess.input<Bit>(2, false);
    bool first = sess.reveal(sess.run_artifact<Bit>(prog, x, y), 1).value_or(false);
    prog.gates[1].in1 = 0;
    bool second = sess.reveal(sess.run_artifact<Bit>(prog, x, y), 1).value_or(false);
    if (party == 1) {
      const bool good = !first && second;
      ok &= good;
      printf("  mutable raw program rebuild: first=%d second=%d  %s\n",
             (int)first, (int)second, good ? "GOOD!" : "BAD!");
    }
  }

  // 6) Compiled Linear artifacts are immutable and owner-bearing, so their
  // lowering is cached safely. Run the same artifact twice to cover both paths.
  {
    auto c = cf::compile_linear<rec::Bit, rec::Bit>(
        [](auto x, auto y) { return x & y; });
    auto x = sess.input<Bit>(1, party == 1);
    auto y = sess.input<Bit>(2, party == 2);
    const uint64_t before = sess.num_and();
    bool first = sess.reveal(sess.run(c, x, y), 1).value_or(false);
    bool second = sess.reveal(sess.run(c, x, y), 1).value_or(false);
    if (party == 1) {
      const bool good = first && second && sess.num_and() == before + 2;
      ok &= good;
      printf("  compiled Linear cache: first=%d second=%d  %s\n",
             (int)first, (int)second, good ? "GOOD!" : "BAD!");
    }
  }

  if (party == 1)
    printf("agmpc_program_replay: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == 1 && !ok) ? 1 : 0;
}
