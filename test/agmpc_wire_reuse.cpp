// Wire-reuse trust-path equivalence (nP-party). A circuit run through the DENSE
// path (None program -> run_program recomputes liveness + the slot-reuse layout)
// must reveal the SAME output as the SAME circuit compacted to WireReuse::Linear
// and run through the TRUST path (ids ARE the slots, identity phys, no layout).
// The transcript is not deterministic, so the gate is semantic: both
// paths must agree with each other AND with a plaintext oracle. A slot-mapping
// bug in the trust path would corrupt the revealed output. Covers compiled
// arithmetic bodies (fabric + AND mix) and the aes128 builtin (fabric-heavy).
// Also hosts the three-strategy agreement block:
// run(body) / run(compiled) / run_artifact over ONE shared input bundle must
// agree on a + b + a.constant(1) — the live-body dedup_consts cross-pass
// invariant at nP > 2, and same-bundle reuse across the three runners.
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/builtins.h"
#include "emp-tool/ir/transform.h"
#include "emp-tool/circuits/frontend/rec.h"
#include "emp-ag/emp-ag.h"
#include "test_options.h"
#include "clear_oracle.h"
#include <array>
#include <cstdio>
using namespace std;
using namespace emp;
namespace cf = emp::frontend;

const static int nP = 3;

static circuit::BooleanProgram to_linear(const circuit::BooleanProgram &dense) {
  return circuit::make_compact(dense, circuit::WireReuse::Linear).prog;
}

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool, test_options(TestArgs(argc, argv, {TEST_OPTION_ARGS})));
  using Ctx = AGMPCSession<nP>::ctx_t;
  using UInt32 = UInt_T<Ctx, 32>;
  using BV128 = BitVec_T<Ctx, 128>;

  const uint32_t A = 0xC0FFEEu, B = 0x1234567u;
  bool ok = true;

  // ---- compiled arithmetic bodies: dense (None) vs Linear (trust) ----
  auto check2 = [&](const char *name, auto body, uint32_t expect) {
    auto c = cf::compile<rec::UInt<32>, rec::UInt<32>>(body);
    circuit::BooleanProgram lin = to_linear(c.program());

    auto a1 = sess.input<UInt32>(1, party == 1 ? A : 0);
    auto b1 = sess.input<UInt32>(2, party == 2 ? B : 0);
    auto zd = sess.run_artifact<UInt32>(c.program(), a1, b1);   // None -> dense
    auto rd = sess.reveal(zd, 1);

    auto a2 = sess.input<UInt32>(1, party == 1 ? A : 0);
    auto b2 = sess.input<UInt32>(2, party == 2 ? B : 0);
    auto zt = sess.run_artifact<UInt32>(lin, a2, b2);           // Linear -> trust
    auto rt = sess.reveal(zt, 1);

    if (party == 1) {
      bool agree = rd.has_value() && rt.has_value() && rd.value() == rt.value();
      bool correct = rd.has_value() && (uint32_t)rd.value() == expect;
      printf("trust[%-8s] dense==trust=%d  correct=%d  (compact %u/%u wires)  %s\n",
             name, (int)agree, (int)correct, lin.num_wires, c.program().num_wires,
             (agree && correct) ? "GOOD!" : "BAD!");
      ok &= agree && correct;
    }
  };
  check2("add",   [](auto a, auto b) { return a + b; },                A + B);
  check2("mul",   [](auto a, auto b) { return a * b; },                A * B);
  check2("mul+k", [](auto a, auto b) { return a * b + a.constant(7u); }, A * B + 7u);

  // ---- aes128 builtin: dense vs Linear (trust), fabric-heavy ----
  {
    const circuit::BooleanProgram &aes = circuit::builtin_circuit("aes128");
    circuit::BooleanProgram lin = to_linear(aes);
    array<bool, 128> k{}, pt{};
    for (int i = 0; i < 128; ++i) { k[i] = ((i * 7 + 3) % 5) == 0; pt[i] = ((i * 3 + 1) % 4) == 0; }

    auto P1 = sess.input<BV128>(2, party == 2 ? pt : array<bool, 128>{});
    auto K1 = sess.input<BV128>(1, party == 1 ? k : array<bool, 128>{});
    auto cd = sess.run_artifact<BV128>(aes, P1, K1);            // None -> dense
    auto rd = sess.reveal(cd, 1);

    auto P2 = sess.input<BV128>(2, party == 2 ? pt : array<bool, 128>{});
    auto K2 = sess.input<BV128>(1, party == 1 ? k : array<bool, 128>{});
    auto ct = sess.run_artifact<BV128>(lin, P2, K2);           // Linear -> trust
    auto rt = sess.reveal(ct, 1);

    if (party == 1) {
      vector<uint8_t> in(256);
      for (int i = 0; i < 128; ++i) { in[i] = pt[i]; in[128 + i] = k[i]; }
      auto ref = agmpc_test::clear_eval(aes, in);
      bool agree = rd.has_value() && rt.has_value();
      bool correct = agree && (int)ref.size() == 128;
      for (int i = 0; i < 128 && agree; ++i) agree = (rd.value()[i] == rt.value()[i]);
      for (int i = 0; i < 128 && correct; ++i) correct = (rd.value()[i] == (bool)ref[i]);
      printf("trust[aes128  ] dense==trust=%d  correct=%d  (compact %u/%u wires)  %s\n",
             (int)agree, (int)correct, lin.num_wires, aes.num_wires,
             (agree && correct) ? "GOOD!" : "BAD!");
      ok &= agree && correct;
    }
  }

  // ---- three-strategy agreement over ONE shared input bundle: run(body) /
  // run(compiled) / run_artifact must all compute a + b + a.constant(1) —
  // live-body dedup_consts across passes at nP > 2, and the same input bundle
  // reused across the three runners (two settles). ----
  {
    const uint32_t xa = 1234567u, yb = 7654321u;
    const uint32_t ref = xa + yb + 1u;
    auto add1 = [](auto a, auto b) { return a + b + a.constant(1); };

    auto a = sess.input<UInt32>(1, party == 1 ? xa : 0u);
    auto b = sess.input<UInt32>(2, party == 2 ? yb : 0u);

    // 1) LIVE BODY replay
    uint32_t via_body = (uint32_t)sess.reveal(sess.run(add1, a, b), 1).value_or(0);
    // 2) COMPILED replay (a stored typed Circuit)
    auto compiled = cf::compile<rec::UInt<32>, rec::UInt<32>>(add1);
    uint32_t via_compiled = (uint32_t)sess.reveal(sess.run(compiled, a, b), 1).value_or(0);
    // 3) raw-program runner over the compiled program
    uint32_t via_program =
        (uint32_t)sess.reveal(sess.run_artifact<UInt32>(compiled.program(), a, b), 1).value_or(0);

    if (party == 1) {
      bool sok = via_body == ref && via_compiled == ref && via_program == ref;
      printf("strategies[add1  ] body=%u compiled=%u program=%u expected=%u  %s\n",
             via_body, via_compiled, via_program, ref, sok ? "GOOD!" : "BAD!");
      ok &= sok;
    }
  }

  if (party == 1)
    printf("agmpc_wire_reuse: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == 1 && !ok) ? 1 : 0;
}
