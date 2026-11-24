// Computations whose Party slots are bound at prepare to share-mode values
// (AGMPCSession::prepare_computation(art, bound)): each bound wire takes its value as its
// mask, with masked value 0, so nothing about it is opened. Every party derives the same
// inputs from fixed seeds (test only). Share mode computes the bound values from every
// party's input bits (share_evaluate); each Computation takes them beside its other slots,
// and its outputs go to every party, to P1 and to garbler nP. Checked against the circuits
// evaluated in the clear:
//   1. a bound slot, a Party slot of party 2's bound at run time and a Public slot, with
//      AND gates over all three;
//   2. every Party slot bound, so only Public bits arrive at run time;
//   3. no AND gates: outputs linear in the bound, Party and Public bits;
//   4. a bound value from share_input and share_random alone, which also runs on the
//      leaky ANDs (BOUND_LEAKY: the only case there, as share_evaluate needs a bank);
//   5. a composed Computation with a bound slot.
// test/CMakeLists.txt builds it at nP = 2, 3, 4 under each Auth; the BOUND_MISUSE cases
// are refused before any traffic.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <random>
#include <vector>

using namespace emp;
using namespace emp::circuit;

#ifndef BOUND_NP
#define BOUND_NP 2
#endif
constexpr int nP = BOUND_NP;
using AgSession = AGMPCSession<nP>;
using Wires = AgSession::SharedWires;
using Bits = emp::session::Bits;
constexpr uint32_t W = 8;   // bits per slot

static int fails = 0;
static void check(bool ok, const char *what, int party) {
  if (!ok) {
    std::printf("  [FAIL] P%d: %s\n", party, what);
    ++fails;
  }
}

static Bits random_bits(std::mt19937_64 &rng, size_t n) {
  Bits v(n);
  for (uint8_t &b : v) b = (uint8_t)(rng() & 1);
  return v;
}

// A circuit builder over a dense program.
struct Builder {
  BooleanProgram p;
  uint32_t next;
  explicit Builder(uint32_t ni) : next(ni) { p.num_inputs = ni; }
  uint32_t gate(Op op, uint32_t a, uint32_t b = 0) {
    Gate g;
    g.op = op;
    g.in0 = a;
    g.in1 = b;
    g.out = next++;
    p.gates.push_back(g);
    return g.out;
  }
  BooleanProgram done() {
    p.num_wires = next;
    return p;
  }
};

// The bound values: W bits from every party's 4 input bits, bit k = (in[k] AND in[k+1])
// XOR in[k+2] (indices mod the input count). Returns the shares and the clear bits.
static Wires bound_values(AgSession &sess, int party, std::mt19937_64 &rng, Bits *clear) {
  Wires in;
  Bits all;
  for (int o = 1; o <= nP; ++o) {
    const Bits bits = random_bits(rng, 4);
    const Wires w = sess.share_input(o, party == o ? bits : Bits(4, 0));
    in = Wires::concat({&in, &w});
    all.insert(all.end(), bits.begin(), bits.end());
  }
  const uint32_t ni = (uint32_t)all.size();
  Builder b(ni);
  clear->assign(W, 0);
  for (uint32_t k = 0; k < W; ++k) {
    const uint32_t t = b.gate(Op::And, k % ni, (k + 1) % ni);
    b.p.outputs.push_back(b.gate(Op::Xor, t, (k + 2) % ni));
    (*clear)[k] = (uint8_t)((all[k % ni] & all[(k + 1) % ni]) ^ all[(k + 2) % ni]);
  }
  return sess.share_evaluate(b.done(), in);
}

static std::shared_ptr<const ComputationArtifact> artifact(BooleanProgram p, IoSignature io) {
  auto art = std::make_shared<ComputationArtifact>();
  art->program = std::make_shared<const BooleanProgram>(std::move(p));
  art->io = std::move(io);
  validate_computation(*art);
  return art;
}

// Each output slot this party receives holds `want`, and no other.
static void check_outputs(const IoSignature &io, const emp::session::RawResult &r, int party,
                          const char *name, const std::vector<Bits> &want) {
  for (size_t s = 0; s < io.outputs.size(); ++s) {
    const bool mine = emp::session::receives(io.outputs[s], party);
    check(mine ? (r.outputs[s].has_value() && *r.outputs[s] == want[s]) : !r.outputs[s].has_value(),
          name, party);
  }
}

// Run `art` with `bound` and this party's bindings; check each output slot it receives.
static void run_and_check(AgSession &sess, int party, const char *name,
                          const std::shared_ptr<const ComputationArtifact> &art,
                          const std::vector<const Wires *> &bound, const emp::session::RawBindings &b,
                          const std::vector<Bits> &want) {
  auto job = sess.prepare_computation(art, bound);
  check_outputs(art->io, sess.run_computation(std::move(job), b), party, name, want);
}

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));

#ifdef BOUND_MISUSE
  {
    // BOUND_MISUSE = 1: a bound value of the wrong width; 2: a bound Public slot;
    // 3: wires another session built. Sessions over one mesh, one at a time.
    NetIOMP<nP> io(party, peer_port());
    Builder bl(2 * W);
    for (uint32_t k = 0; k < W; ++k) bl.p.outputs.push_back(bl.gate(Op::Xor, k, W + k));
    IoSignature sig;
    sig.inputs.push_back({W, InputKind::Party, 1});
    sig.inputs.push_back({W, InputKind::Public, PUBLIC});
    sig.outputs.push_back({W, OutputKind::Public, PUBLIC});
    const auto art = artifact(bl.done(), sig);
    Wires v;
#if BOUND_MISUSE == 3
    {
      AgSession first(&io, &pool, party);
      v = first.share_random(W);
    }
#endif
    AgSession sess(&io, &pool, party);
#if BOUND_MISUSE == 1
    v = sess.share_random(W);
    const Wires narrow = v.slice(0, W - 1);
    (void)sess.prepare_computation(art, {&narrow, nullptr});
#elif BOUND_MISUSE == 2
    v = sess.share_random(W);
    (void)sess.prepare_computation(art, {nullptr, &v});
#else
    (void)sess.prepare_computation(art, {&v, nullptr});
#endif
    return 1;
  }
#else
#ifdef BOUND_LEAKY
  AgSession sess(party, peer_port(), nullptr, &pool);
#else
  AgSession sess(party, peer_port(), nullptr, &pool, 40, -1, std::nullopt, BaseOtKind::CSW, -1, -1,
                 ag::cut_and_choose_prep<nP>(1024));
#endif
  std::mt19937_64 rng(4242);

#ifndef BOUND_LEAKY
  // 1. bound | party 2's bits | Public bits; out: u to every party, v to P1, v ^ b to garbler nP.
  {
    Bits bc;
    const Wires bv = bound_values(sess, party, rng, &bc);
    const Bits x = random_bits(rng, W), q = random_bits(rng, W);
    Builder bl(3 * W);
    std::vector<uint32_t> u(W), v(W);
    for (uint32_t k = 0; k < W; ++k) {
      const uint32_t t = bl.gate(Op::And, k, W + k);
      u[k] = bl.gate(Op::Xor, t, 2 * W + k);
    }
    for (uint32_t k = 0; k < W; ++k) v[k] = bl.gate(Op::And, u[k], (k + 1) % W);
    std::vector<uint32_t> vb(W);
    for (uint32_t k = 0; k < W; ++k) vb[k] = bl.gate(Op::Xor, v[k], k);
    for (uint32_t k = 0; k < W; ++k) bl.p.outputs.push_back(u[k]);
    for (uint32_t k = 0; k < W; ++k) bl.p.outputs.push_back(v[k]);
    for (uint32_t k = 0; k < W; ++k) bl.p.outputs.push_back(vb[k]);
    IoSignature io;
    io.inputs.push_back({W, InputKind::Party, 1});   // bound
    io.inputs.push_back({W, InputKind::Party, 2});
    io.inputs.push_back({W, InputKind::Public, PUBLIC});
    io.outputs.push_back({W, OutputKind::Public, PUBLIC});
    io.outputs.push_back({W, OutputKind::Party, 1});
    io.outputs.push_back({W, OutputKind::Party, nP});
    std::vector<Bits> want(3, Bits(W));
    for (uint32_t k = 0; k < W; ++k) want[0][k] = (uint8_t)((bc[k] & x[k]) ^ q[k]);
    for (uint32_t k = 0; k < W; ++k) want[1][k] = (uint8_t)(want[0][k] & bc[(k + 1) % W]);
    for (uint32_t k = 0; k < W; ++k) want[2][k] = (uint8_t)(want[1][k] ^ bc[k]);
    emp::session::RawBindings b;
    b.inputs.resize(3);
    if (party == 2) b.inputs[1] = x;
    b.inputs[2] = q;
    run_and_check(sess, party, "bound, Party and Public slots", artifact(bl.done(), io),
                  {&bv, nullptr, nullptr}, b, want);
  }
  // 2. every Party slot bound: two bound slots and Public bits.
  {
    Bits bc0, bc1;
    const Wires b0 = bound_values(sess, party, rng, &bc0);
    const Wires b1 = bound_values(sess, party, rng, &bc1);
    const Bits q = random_bits(rng, W);
    Builder bl(3 * W);
    for (uint32_t k = 0; k < W; ++k) {
      const uint32_t t = bl.gate(Op::And, k, W + k);
      bl.p.outputs.push_back(bl.gate(Op::Xor, t, 2 * W + k));
    }
    for (uint32_t k = 0; k < W; ++k) bl.p.outputs.push_back(bl.gate(Op::And, k, 2 * W + k));
    IoSignature io;
    io.inputs.push_back({W, InputKind::Party, 2});   // bound
    io.inputs.push_back({W, InputKind::Party, 1});   // bound
    io.inputs.push_back({W, InputKind::Public, PUBLIC});
    io.outputs.push_back({W, OutputKind::Public, PUBLIC});
    io.outputs.push_back({W, OutputKind::Party, nP});
    std::vector<Bits> want(2, Bits(W));
    for (uint32_t k = 0; k < W; ++k) want[0][k] = (uint8_t)((bc0[k] & bc1[k]) ^ q[k]);
    for (uint32_t k = 0; k < W; ++k) want[1][k] = (uint8_t)(bc0[k] & q[k]);
    emp::session::RawBindings b;
    b.inputs.resize(3);
    b.inputs[2] = q;   // the owners pass nothing for their bound slots
    run_and_check(sess, party, "every Party slot bound", artifact(bl.done(), io), {&b0, &b1, nullptr},
                  b, want);
  }
  // 3. no AND gates.
  {
    Bits bc;
    const Wires bv = bound_values(sess, party, rng, &bc);
    const Bits x = random_bits(rng, W), q = random_bits(rng, W);
    Builder bl(3 * W);
    for (uint32_t k = 0; k < W; ++k) {
      const uint32_t t = bl.gate(Op::Xor, k, W + k);
      bl.p.outputs.push_back(bl.gate(Op::Xor, t, 2 * W + k));
    }
    for (uint32_t k = 0; k < W; ++k) bl.p.outputs.push_back(bl.gate(Op::Not, k));
    IoSignature io;
    io.inputs.push_back({W, InputKind::Party, 1});   // bound
    io.inputs.push_back({W, InputKind::Party, nP});
    io.inputs.push_back({W, InputKind::Public, PUBLIC});
    io.outputs.push_back({W, OutputKind::Party, 1});
    io.outputs.push_back({W, OutputKind::Public, PUBLIC});
    std::vector<Bits> want(2, Bits(W));
    for (uint32_t k = 0; k < W; ++k) want[0][k] = (uint8_t)(bc[k] ^ x[k] ^ q[k]);
    for (uint32_t k = 0; k < W; ++k) want[1][k] = (uint8_t)(bc[k] ^ 1);
    emp::session::RawBindings b;
    b.inputs.resize(3);
    if (party == nP) b.inputs[1] = x;
    b.inputs[2] = q;
    run_and_check(sess, party, "no AND gates", artifact(bl.done(), io), {&bv, nullptr, nullptr}, b, want);
  }
  // 5. a composed Computation: a unit u(a, b) = (a AND b) XOR a, called on (bound, Party)
  //    and then on (that, Public).
  {
    Bits bc;
    const Wires bv = bound_values(sess, party, rng, &bc);
    const Bits x = random_bits(rng, W), q = random_bits(rng, W);
    auto unit = std::make_shared<BooleanProgram>();
    {
      Builder u(2);
      const uint32_t t = u.gate(Op::And, 0, 1);
      u.p.outputs.push_back(u.gate(Op::Xor, t, 0));
      *unit = u.done();
    }
    ComposeCtx cx;
    const uint32_t first = cx.external_input(3 * W);
    std::vector<uint32_t> o1(W), o2(W);
    for (uint32_t k = 0; k < W; ++k) {
      const uint32_t a[2] = {first + k, first + W + k};
      o1[k] = cx.call_unit(unit, a, 2)[0];
    }
    for (uint32_t k = 0; k < W; ++k) {
      const uint32_t a[2] = {o1[k], first + 2 * W + k};
      o2[k] = cx.call_unit(unit, a, 2)[0];
    }
    std::vector<uint32_t> outs(o2);
    outs.insert(outs.end(), o1.begin(), o1.end());
    auto plan = std::make_shared<const ComposePlan>(cx.finish(outs));
    IoSignature io;
    io.inputs.push_back({W, InputKind::Party, 1});   // bound
    io.inputs.push_back({W, InputKind::Party, 2});
    io.inputs.push_back({W, InputKind::Public, PUBLIC});
    io.outputs.push_back({W, OutputKind::Public, PUBLIC});
    io.outputs.push_back({W, OutputKind::Party, 1});
    std::vector<Bits> want(2, Bits(W));
    for (uint32_t k = 0; k < W; ++k) {
      want[1][k] = (uint8_t)((bc[k] & x[k]) ^ bc[k]);
      want[0][k] = (uint8_t)((want[1][k] & q[k]) ^ want[1][k]);
    }
    emp::session::RawBindings b;
    b.inputs.resize(3);
    if (party == 2) b.inputs[1] = x;
    b.inputs[2] = q;
    auto job = sess.prepare_computation(plan, io, {&bv, nullptr, nullptr});
    check_outputs(io, sess.run_computation(std::move(job), b), party, "composed, bound", want);
  }
#endif
  // 4. bound values from share_input and share_random alone (no bank needed).
  {
    const Bits mine = random_bits(rng, W);   // party 1's, known to all: test only
    const Wires in1 = sess.share_input(1, party == 1 ? mine : Bits(W, 0));
    const Wires r = sess.share_random(W);
    const Wires bv = in1 ^ r;
    const std::optional<Bits> rv = sess.share_reveal(r, PUBLIC);
    check(rv.has_value(), "random shares revealed", party);
    Bits bc(W);
    for (uint32_t k = 0; k < W; ++k) bc[k] = (uint8_t)(mine[k] ^ (*rv)[k]);
    const Bits q = random_bits(rng, W);
    Builder bl(2 * W);
    for (uint32_t k = 0; k < W; ++k) bl.p.outputs.push_back(bl.gate(Op::And, k, W + k));
    IoSignature io;
    io.inputs.push_back({W, InputKind::Party, 1});   // bound
    io.inputs.push_back({W, InputKind::Public, PUBLIC});
    io.outputs.push_back({W, OutputKind::Public, PUBLIC});
    std::vector<Bits> want(1, Bits(W));
    for (uint32_t k = 0; k < W; ++k) want[0][k] = (uint8_t)(bc[k] & q[k]);
    emp::session::RawBindings b;
    b.inputs.resize(2);
    if (party == 1) b.inputs[0] = random_bits(rng, W);   // ignored: the slot is bound
    else (void)random_bits(rng, W);
    b.inputs[1] = q;
    run_and_check(sess, party, "bound from share_input and share_random", artifact(bl.done(), io),
                  {&bv, nullptr}, b, want);
  }

  if (fails) {
    std::printf("P%d: FAIL (%d)\n", party, fails);
    return 1;
  }
  if (party == 1) std::printf("bound computations: all cases passed\n");
  return 0;
#endif
}
