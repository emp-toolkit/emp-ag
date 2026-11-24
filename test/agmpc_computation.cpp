// Circuit mode on AGMPCSession: Computations with declared owners and
// recipients, prepared offline and run online. Every party derives the same
// programs and inputs from fixed seeds, binds only its own Party slots and every
// Public slot, and checks each output slot it receives (and only those) against
// ClearSession's circuit mode over the same artifact (for a composed one, its
// flattening). test/CMakeLists.txt builds it for both Auth options, both Delivery
// options, both triple sources and nP = 2, 3, 4; the COT backend is the build's. The
// COMP_* switches select the misuse cases that must stop before any traffic.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <random>
#include <utility>
#include <vector>

using namespace emp;
using namespace emp::circuit;
namespace cf = emp::frontend;

#ifndef COMP_NP
#define COMP_NP 2
#endif
#ifndef COMP_SSP
#define COMP_SSP 40
#endif
#ifndef COMP_SSP_SKEW   // misuse case: party 2 runs at COMP_SSP + COMP_SSP_SKEW
#define COMP_SSP_SKEW 0
#endif
constexpr int nP = COMP_NP;
using AgSession = AGMPCSession<nP>;

static int fails = 0;
static void check(bool ok, const char *what, int party) {
  if (!ok) {
    std::printf("  [FAIL] P%d: %s\n", party, what);
    ++fails;
  }
}

// A random dense program over `ni` inputs: `ng` gates, about half of them AND
// when `ands` is set and none otherwise. Each constant value appears at most
// once.
static std::shared_ptr<BooleanProgram> random_program(std::mt19937_64 &rng, uint32_t ni,
                                                      uint32_t ng, bool ands) {
  auto p = std::make_shared<BooleanProgram>();
  p->num_inputs = ni;
  p->num_wires = ni + ng;
  bool have_const[2] = {false, false};
  for (uint32_t g = 0; g < ng; ++g) {
    const uint32_t out = ni + g;
    Gate x;
    x.out = out;
    const uint64_t r = rng() % 10;
    const bool one = (rng() & 1) != 0;
    if (out == 0 || (r == 9 && !have_const[one])) {
      x.op = one ? Op::Const1 : Op::Const0;
      have_const[one] = true;
    } else if (ands && r < 5) {
      x.op = Op::And;
      x.in0 = (uint32_t)(rng() % out);
      x.in1 = (uint32_t)(rng() % out);
    } else if (r < 8) {
      x.op = Op::Xor;
      x.in0 = (uint32_t)(rng() % out);
      x.in1 = (uint32_t)(rng() % out);
    } else {
      x.op = Op::Not;
      x.in0 = (uint32_t)(rng() % out);
    }
    p->gates.push_back(x);
  }
  return p;
}

// Inputs: one Party slot per party (widths 1..6), then a Public slot. Outputs:
// a slot to P1, one to each garbler, and a Public one; among their wires are
// repeats and input wires (an owner's own input and another party's).
static ComputationArtifact random_computation(std::mt19937_64 &rng, bool ands,
                                              bool public_inputs_only = false) {
  IoSignature io;
  uint32_t ni = 0;
  if (!public_inputs_only)
    for (int p = 1; p <= nP; ++p) {
      const uint32_t w = 1 + (uint32_t)(rng() % 6);
      io.inputs.push_back({w, InputKind::Party, p});
      ni += w;
    }
  const uint32_t wp = 1 + (uint32_t)(rng() % 5);
  io.inputs.push_back({wp, InputKind::Public, PUBLIC});
  ni += wp;
  auto p = random_program(rng, ni, 40 + (uint32_t)(rng() % 160), ands);

  auto add_out = [&](OutputRole role) {
    for (uint32_t k = 0; k < role.width; ++k) {
      const uint64_t r = rng() % 8;
      p->outputs.push_back(r == 0 ? (uint32_t)(rng() % ni) : (uint32_t)(rng() % p->num_wires));
    }
    io.outputs.push_back(role);
  };
  add_out({1 + (uint32_t)(rng() % 8), OutputKind::Party, 1});
  for (int g = 2; g <= nP; ++g) add_out({1 + (uint32_t)(rng() % 8), OutputKind::Party, g});
  add_out({1 + (uint32_t)(rng() % 4), OutputKind::Public, PUBLIC});
  if (!p->outputs.empty()) p->outputs.back() = p->outputs.front();   // a repeat across slots

  ComputationArtifact a;
  a.program = std::move(p);
  a.io = std::move(io);
  validate_computation(a);
  return a;
}

// A composed Computation: the plan as the frontend records it and its slots.
struct Composed {
  std::shared_ptr<const ComposePlan> plan;
  IoSignature io;
};

// The same slots over a composed program: a random unit with AND gates called `calls`
// times, glue XOR and AND gates between the calls, and every argument and output drawn
// from the inputs, the glue and the earlier calls' outputs.
static Composed random_composed_computation(std::mt19937_64 &rng, int calls) {
  IoSignature io;
  uint32_t ni = 0;
  for (int p = 1; p <= nP; ++p) {
    const uint32_t w = 1 + (uint32_t)(rng() % 6);
    io.inputs.push_back({w, InputKind::Party, p});
    ni += w;
  }
  const uint32_t wp = 1 + (uint32_t)(rng() % 5);
  io.inputs.push_back({wp, InputKind::Public, PUBLIC});
  ni += wp;
  auto unit = random_program(rng, 4, 20 + (uint32_t)(rng() % 40), true);
  for (int k = 0; k < 5; ++k) unit->outputs.push_back((uint32_t)(rng() % unit->num_wires));

  ComposeCtx cx;
  const uint32_t first = cx.external_input(ni);
  std::vector<uint32_t> live(ni);
  for (uint32_t i = 0; i < ni; ++i) live[i] = first + i;
  const auto pick = [&] { return live[rng() % live.size()]; };
  for (int c = 0; c < calls; ++c) {
    if (rng() % 2) live.push_back(cx.xor_gate(pick(), pick()));
    if (rng() % 3 == 0) live.push_back(cx.and_gate(pick(), pick()));
    const uint32_t args[4] = {pick(), pick(), pick(), pick()};
    const std::vector<uint32_t> out = cx.call_unit(unit, args, 4);
    live.insert(live.end(), out.begin(), out.end());
  }
  std::vector<uint32_t> outs;
  auto add_out = [&](OutputRole role) {
    for (uint32_t k = 0; k < role.width; ++k) outs.push_back(rng() % 8 == 0 ? first + (uint32_t)(rng() % ni) : pick());
    io.outputs.push_back(role);
  };
  add_out({1 + (uint32_t)(rng() % 8), OutputKind::Party, 1});
  for (int g = 2; g <= nP; ++g) add_out({1 + (uint32_t)(rng() % 8), OutputKind::Party, g});
  add_out({1 + (uint32_t)(rng() % 4), OutputKind::Public, PUBLIC});

  return {std::make_shared<const ComposePlan>(cx.finish(outs)), std::move(io)};
}

// Every slot's bits, the same at every party.
static std::vector<emp::session::Bits> random_inputs(std::mt19937_64 &rng, const IoSignature &io) {
  std::vector<emp::session::Bits> v;
  for (const InputRole &r : io.inputs) {
    emp::session::Bits b(r.width);
    for (uint8_t &x : b) x = (uint8_t)(rng() & 1);
    v.push_back(std::move(b));
  }
  return v;
}

// Run the prepared `job` with this party's bindings and check each output slot it
// receives (and only those) against ClearSession's run of `flat`, the same computation.
static void check_run(AgSession &sess, AgSession::job_t job, const ComputationArtifact &flat,
                      const std::vector<emp::session::Bits> &in, const char *what) {
  const int me = sess.party();
  emp::session::RawBindings mine, all;
  for (size_t s = 0; s < flat.io.inputs.size(); ++s) {
    all.inputs.emplace_back(in[s]);
    mine.inputs.emplace_back(emp::session::binds(flat.io.inputs[s], me)
                                 ? std::optional<emp::session::Bits>(in[s])
                                 : std::nullopt);
  }
  ClearSession oracle;
  const emp::session::RawResult want = oracle.run_computation(
      oracle.prepare_computation(std::make_shared<const ComputationArtifact>(flat)), all);

  const emp::session::RawResult got = sess.run_computation(std::move(job), mine);
  bool ok = got.outputs.size() == flat.io.outputs.size();
  for (size_t s = 0; ok && s < flat.io.outputs.size(); ++s) {
    if (emp::session::receives(flat.io.outputs[s], me))
      ok = got.outputs[s].has_value() && *got.outputs[s] == *want.outputs[s];
    else
      ok = !got.outputs[s].has_value();
  }
  check(ok, what, me);
}
static void run_and_check(AgSession &sess, const ComputationArtifact &a,
                          const std::vector<emp::session::Bits> &in, const char *what) {
  check_run(sess, sess.prepare_computation(std::make_shared<const ComputationArtifact>(a)), a,
            in, what);
}
// A composed one runs as composed; ClearSession runs its flattening.
static void run_and_check(AgSession &sess, const Composed &c,
                          const std::vector<emp::session::Bits> &in, const char *what) {
  ComputationArtifact flat;
  flat.program = std::make_shared<const BooleanProgram>(flatten_compose(*c.plan));
  flat.io = c.io;
  check_run(sess, sess.prepare_computation(c.plan, c.io), flat, in, what);
}

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));
  AgSession sess(party, peer_port(), nullptr, &pool, COMP_SSP + (party == 2 ? COMP_SSP_SKEW : 0));
  static_assert(ComputationSession<AgSession>);
  static_assert(!std::is_copy_constructible_v<AgSession::job_t> &&
                std::is_move_constructible_v<AgSession::job_t>);

#if defined(COMP_BUSY)
  {
    std::mt19937_64 rng(1);
    auto job = sess.prepare_computation(
        std::make_shared<const ComputationArtifact>(random_computation(rng, true)));
    using U8 = UInt_T<AgSession::ctx_t, 8>;
    (void)sess.input<U8>(1, 3);   // must stop: a Computation job is outstanding
    return 1;
  }
#elif defined(COMP_BAD_OWNER)
  {
    std::mt19937_64 rng(2);
    ComputationArtifact a = random_computation(rng, true);
    a.io.inputs[0].owner = nP + 1;
    (void)sess.prepare_computation(std::make_shared<const ComputationArtifact>(a));
    return 1;
  }
#elif defined(COMP_FULL_REUSE)
  {
    std::mt19937_64 rng(3);
    ComputationArtifact a = random_computation(rng, true);
    auto p = std::make_shared<BooleanProgram>(*a.program);
    p->wire_reuse = WireReuse::Full;
    a.program = p;
    (void)sess.prepare_computation(std::make_shared<const ComputationArtifact>(a));
    return 1;
  }
#elif defined(COMP_COMPOSED_FULL_UNIT)
  {
    std::mt19937_64 rng(7);
    const Composed c = random_composed_computation(rng, 2);
    auto plan = std::make_shared<ComposePlan>(*c.plan);
    auto unit = std::make_shared<BooleanProgram>(*plan->instances[0].unit);
    unit->wire_reuse = WireReuse::Full;
    for (ComposeInstance &inst : plan->instances) inst.unit = unit;
    (void)sess.prepare_computation(plan, c.io);   // must stop: a WireReuse::Full unit
    return 1;
  }
#else
  // Random computations with AND gates: every kind of slot and recipient.
  for (int t = 0; t < 6; ++t) {
    std::mt19937_64 rng(1000 + (uint64_t)t);
    const ComputationArtifact a = random_computation(rng, true);
    run_and_check(sess, a, random_inputs(rng, a.io), "random computation");
  }

  // Composed programs: one unit lowered once and replayed per call, glue between.
  for (int t = 0; t < 4; ++t) {
    std::mt19937_64 rng(7000 + (uint64_t)t);
    const Composed c = random_composed_computation(rng, 1 + (int)(rng() % 4));
    run_and_check(sess, c, random_inputs(rng, c.io), "composed computation");
  }
  {
    std::mt19937_64 rng(7100);
    const Composed c = random_composed_computation(rng, 40);
    run_and_check(sess, c, random_inputs(rng, c.io), "a unit called 40 times");
  }

  // No AND gate: garblers still decode only through P1's hand-off under WRK.
  for (int t = 0; t < 3; ++t) {
    std::mt19937_64 rng(2000 + (uint64_t)t);
    const ComputationArtifact a = random_computation(rng, false);
    run_and_check(sess, a, random_inputs(rng, a.io), "computation with no AND gate");
  }

  // Only Public inputs: no owner broadcast, one flight of labels.
  {
    std::mt19937_64 rng(3000);
    const ComputationArtifact a = random_computation(rng, true, /*public_inputs_only=*/true);
    run_and_check(sess, a, random_inputs(rng, a.io), "Public inputs only");
  }

  // No inputs at all.
  {
    std::mt19937_64 rng(3001);
    ComputationArtifact a;
    auto p = random_program(rng, 0, 30, true);
    for (int k = 0; k < 6; ++k) p->outputs.push_back((uint32_t)(rng() % p->num_wires));
    a.program = std::move(p);
    a.io.outputs = {{3, OutputKind::Party, nP}, {3, OutputKind::Public, PUBLIC}};
    run_and_check(sess, a, {}, "computation with no inputs");
  }

  // A dropped job: prepared, never run. The session continues.
  {
    std::mt19937_64 rng(4000);
    auto dropped = sess.prepare_computation(
        std::make_shared<const ComputationArtifact>(random_computation(rng, true)));
    (void)dropped;
  }
  {
    std::mt19937_64 rng(4001);
    const ComputationArtifact a = random_computation(rng, true);
    run_and_check(sess, a, random_inputs(rng, a.io), "a computation after a dropped job");
  }

  // The typed surface, dense and WireReuse::Linear: x from P1, y from the last
  // party, k public; the sum goes to garbler 2, the comparison to everyone.
  {
    using rec32 = rec::UInt<32>;
    auto sum = cf::compile<rec32, rec32, rec32>([](auto x, auto y, auto k) { return (x + y) ^ k; });
    auto less = cf::compile_linear<rec32, rec32, rec32>([](auto x, auto y, auto k) { return (x ^ k) < y; });
    auto c1 = cf::computation(sum, cf::to(2), cf::from(1), cf::from(nP), cf::from(PUBLIC));
    auto c2 = cf::computation(less, cf::to(PUBLIC), cf::from(1), cf::from(nP), cf::from(PUBLIC));
    auto [o1, x1, y1, k1] = c1.handles();
    auto [o2, x2, y2, k2] = c2.handles();
    for (int t = 0; t < 3; ++t) {
      std::mt19937_64 rng(5000 + (uint64_t)t);
      const uint32_t x = (uint32_t)rng(), y = (uint32_t)rng(), k = (uint32_t)rng();
      {
        auto job = cf::prepare(sess, c1);
        auto r = party == 1   ? cf::run(sess, std::move(job), cf::bind(x1, x), cf::bind(k1, k))
               : party == nP  ? cf::run(sess, std::move(job), cf::bind(y1, y), cf::bind(k1, k))
                              : cf::run(sess, std::move(job), cf::bind(k1, k));
        if (party == 2) check(r[o1].has_value() && *r[o1] == ((x + y) ^ k), "typed sum to garbler 2", party);
        else check(!r[o1].has_value(), "typed sum reaches a non-recipient", party);
      }
      {
        auto job = cf::prepare(sess, c2);
        auto r = party == 1   ? cf::run(sess, std::move(job), cf::bind(x2, x), cf::bind(k2, k))
               : party == nP  ? cf::run(sess, std::move(job), cf::bind(y2, y), cf::bind(k2, k))
                              : cf::run(sess, std::move(job), cf::bind(k2, k));
        check(r[o2].has_value() && *r[o2] == ((x ^ k) < y), "typed comparison to everyone", party);
      }
    }
  }

  // The direct-mode paths still work between computations.
  {
    using U8 = UInt_T<AgSession::ctx_t, 8>;
    auto a = sess.input<U8>(1, 200);
    auto b = sess.input<U8>(nP, 77);
    const std::optional<uint64_t> s = sess.reveal(a + b, PUBLIC);
    check(s.has_value() && *s == (uint8_t)(200 + 77), "direct mode between computations", party);
    std::mt19937_64 rng(6000);
    const ComputationArtifact c = random_computation(rng, true);
    run_and_check(sess, c, random_inputs(rng, c.io), "a computation after direct mode");
  }
#endif

  if (fails) {
    std::printf("P%d: FAIL (%d)\n", party, fails);
    return 1;
  }
  if (party == 1) std::printf("agmpc_computation nP=%d: OK\n", nP);
  return 0;
}
