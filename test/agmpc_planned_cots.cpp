// AGMPCSession::planned_cots: a session given each COT stream's plan runs one Computation
// and draws exactly the plan from every stream. Each case runs a fresh session on one
// shared mesh, on the build's COT streams unless noted:
//   1. the leaky ANDs, over Party and Public inputs and 40 AND gates;
//   2. cut-and-choose triples in batches of 16 over the same 40 AND gates: three
//      batches, each at its own statistical target;
//   3. the build's default AND-gate protocol over a computation without AND gates, so
//      the inputs' masks are the only draw;
//   4. at nP == 2, on SoftSpoken streams: the leaky ANDs, and 32 more COTs that party 1
//      sends party 2 through draw_cots(job, ...), planned on those two streams only;
//   5. the leaky ANDs on SilentFerret streams with the B13 LPN set;
//   6. share mode on cut-and-choose triples in batches of 16: five input bits from every
//      party, three random shares, and 40 AND gates in two evaluations (three batches),
//      planned from the draws' lengths (planned_cots_of_draws);
//   7. case 1 with party 1's slot bound at prepare to share_input(1, x): the bound wires
//      draw no masks, so the plan is share_input's draw and the Computation's others.
// A SoftSpoken stream aborts on a plan short of its draws; a plan beyond them leaves
// cots_drawn() below it, which the check catches. Every case also checks the output, and
// the Computation cases that planned_cots from the input-wire and AND-gate counts gives
// the same plan.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <vector>

using namespace emp;
using namespace emp::circuit;

#ifndef PLANNED_NP
#define PLANNED_NP 2
#endif
constexpr int nP = PLANNED_NP;
constexpr int kSsp = 40;
constexpr int W = 16;          // bits in each Party slot and in the output
constexpr int kPublic = 8;     // bits in the Public slot
constexpr uint32_t kX = 0xb4e1u, kY = 0x2d7cu, kP = 0x9au;   // known to every party: test only

// Slot 0: party 1's W bits; slot 1: party 2's; slot 2: kPublic Public bits. The output, W
// Public bits: acc = x ^ y, then `ands` AND gates acc[i] &= (k odd ? x[i] : ~y[i]) for
// k = 0, 1, ... with i = k mod W, then each bit XORed with a Public bit.
static ComputationArtifact make_art(int ands) {
  auto p = std::make_shared<BooleanProgram>();
  p->num_inputs = 2 * W + kPublic;
  uint32_t next = p->num_inputs;
  auto gate = [&](Op op, uint32_t a, uint32_t b) {
    Gate g;
    g.op = op; g.in0 = a; g.in1 = b; g.out = next++;
    p->gates.push_back(g);
    return g.out;
  };
  std::vector<uint32_t> acc(W);
  for (uint32_t i = 0; i < (uint32_t)W; ++i) acc[i] = gate(Op::Xor, i, W + i);
  for (int k = 0; k < ands; ++k) {
    const uint32_t i = (uint32_t)(k % W);
    const uint32_t other = (k % 2) ? i : gate(Op::Not, W + i, 0);
    acc[i] = gate(Op::And, acc[i], other);
  }
  for (uint32_t i = 0; i < (uint32_t)W; ++i)
    p->outputs.push_back(gate(Op::Xor, acc[i], 2 * W + i % kPublic));
  p->num_wires = next;
  ComputationArtifact art;
  art.program = std::move(p);
  art.io.inputs.push_back({(uint32_t)W, InputKind::Party, 1});
  art.io.inputs.push_back({(uint32_t)W, InputKind::Party, 2});
  art.io.inputs.push_back({(uint32_t)kPublic, InputKind::Public, PUBLIC});
  art.io.outputs.push_back({(uint32_t)W, OutputKind::Public, PUBLIC});
  validate_computation(art);
  return art;
}

static uint32_t clear_output(int ands) {
  uint32_t acc = kX ^ kY;
  for (int k = 0; k < ands; ++k) {
    const int i = k % W;
    const uint32_t other = (k % 2) ? (kX >> i) & 1 : ((kY >> i) & 1) ^ 1;
    acc &= ~(((((acc >> i) & 1) & other) ^ 1) << i);
  }
  uint32_t out = 0;
  for (int i = 0; i < W; ++i) out |= (((acc >> i) ^ (kP >> (i % kPublic))) & 1) << i;
  return out;
}

static emp::session::Bits bits_of(uint32_t v, int n) {
  emp::session::Bits b((size_t)n);
  for (int i = 0; i < n; ++i) b[(size_t)i] = (uint8_t)((v >> i) & 1);
  return b;
}

// One session: plan, run the Computation of make_art(ands), check the output and every
// stream's count. `extra` COTs go from party 1 to party 2 through draw_cots(job, ...).
template <class Cfg>
static bool run_case(NetIOMP<nP> &io, ThreadPool &pool, int party, const char *name, int ands,
                     const ag::AndPrepFactory<nP> &prep, int64_t extra = 0) {
  using Sess = AGMPCSession<nP, Cfg>;
  auto art = std::make_shared<const ComputationArtifact>(make_art(ands));
  const int64_t plan = Sess::planned_cots(*art, kSsp, prep);
  bool ok = Sess::planned_cots((int64_t)art->program->num_inputs,
                               ag::agmpc_count_ands(*art->program), kSsp, prep) == plan;
  const int64_t sends = plan + (party == 1 ? extra : 0);
  const int64_t receives = plan + (party == 2 ? extra : 0);
  {
    Sess sess(&io, &pool, party, kSsp, nullptr, std::nullopt, BaseOtKind::CSW, sends,
              receives, prep);
    auto job = sess.prepare_computation(art);
    if (extra > 0) {
      std::vector<block> cot((size_t)extra);
      sess.draw_cots(job, 3 - party, party == 1, cot.data(), extra);
      sess.check_cots(job);
    }
    emp::session::RawBindings b;
    b.inputs.resize(3);
    if (party == 1) b.inputs[0] = bits_of(kX, W);
    if (party == 2) b.inputs[1] = bits_of(kY, W);
    b.inputs[2] = bits_of(kP, kPublic);
    const emp::session::RawResult r = sess.run_computation(std::move(job), b);
    uint32_t got = 0;
    for (int i = 0; i < W; ++i) got |= (uint32_t)((*r.outputs[0])[(size_t)i] & 1) << i;
    ok = ok && got == clear_output(ands);
    for (int p = 1; p <= nP; ++p) {
      if (p == party) continue;
      const int64_t want_send = plan + (party == 1 && p == 2 ? extra : 0);
      const int64_t want_recv = plan + (party == 2 && p == 1 ? extra : 0);
      ok = ok && sess.protocol().abit->cots_drawn(p, true) == want_send &&
           sess.protocol().abit->cots_drawn(p, false) == want_recv;
    }
  }
  std::printf("agmpc_planned_cots[np=%d, %s] party %d: plan %lld: %s\n", nP, name, party,
              (long long)plan, ok ? "GOOD" : "BAD");
  return ok;
}

// n AND gates, gate k on inputs k and k + shift (mod ni), each an output.
static BooleanProgram and_pairs(uint32_t ni, int n, uint32_t shift) {
  BooleanProgram p;
  p.num_inputs = ni;
  uint32_t next = ni;
  for (int k = 0; k < n; ++k) {
    Gate g;
    g.op = Op::And;
    g.in0 = (uint32_t)k % ni;
    g.in1 = ((uint32_t)k + shift) % ni;
    g.out = next++;
    p.gates.push_back(g);
    p.outputs.push_back(g.out);
  }
  p.num_wires = next;
  return p;
}

template <class Cfg>
static bool run_share_case(NetIOMP<nP> &io, ThreadPool &pool, int party) {
  using Sess = AGMPCSession<nP, Cfg>;
  using Wires = typename Sess::SharedWires;
  constexpr int kIn = 5, kRandom = 3, kAnds = 20;
  const ag::AndPrepFactory<nP> prep = ag::cut_and_choose_prep<nP>(16);
  std::vector<int64_t> draws(nP, kIn);
  draws.push_back(kRandom);
  for (int64_t n : prep.draws(2 * kAnds, kSsp)) draws.push_back(n);
  const int64_t plan = Sess::planned_cots_of_draws(draws);
  bool ok = true;
  {
    Sess sess(&io, &pool, party, kSsp, nullptr, std::nullopt, BaseOtKind::CSW, plan, plan, prep);
    Wires in;
    std::vector<uint8_t> clear;
    for (int o = 1; o <= nP; ++o) {
      const emp::session::Bits mine = bits_of(0x15u + (uint32_t)o, kIn);   // known to all: test only
      const Wires w = sess.share_input(o, party == o ? mine : emp::session::Bits(kIn, 0));
      in = Wires::concat({&in, &w});
      clear.insert(clear.end(), mine.begin(), mine.end());
    }
    const Wires r = sess.share_random(kRandom);
    const std::optional<emp::session::Bits> rv = sess.share_reveal(r, PUBLIC);
    ok = rv.has_value() && rv->size() == (size_t)kRandom;
    for (uint32_t shift : {1u, 3u}) {
      const BooleanProgram p = and_pairs((uint32_t)in.size(), kAnds, shift);
      const std::optional<emp::session::Bits> got = sess.share_reveal(sess.share_evaluate(p, in), PUBLIC);
      for (int k = 0; k < kAnds; ++k)
        ok = ok && got.has_value() &&
             (*got)[(size_t)k] == (clear[p.gates[(size_t)k].in0] & clear[p.gates[(size_t)k].in1]);
    }
    for (int p = 1; p <= nP; ++p) {
      if (p == party) continue;
      ok = ok && sess.protocol().abit->cots_drawn(p, true) == plan &&
           sess.protocol().abit->cots_drawn(p, false) == plan;
    }
  }
  std::printf("agmpc_planned_cots[np=%d, share mode] party %d: plan %lld: %s\n", nP, party,
              (long long)plan, ok ? "GOOD" : "BAD");
  return ok;
}

template <class Cfg>
static bool run_bound_case(NetIOMP<nP> &io, ThreadPool &pool, int party) {
  using Sess = AGMPCSession<nP, Cfg>;
  constexpr int kAnds = 40;
  const ag::AndPrepFactory<nP> prep = ag::leaky_and_prep<nP>();
  auto art = std::make_shared<const ComputationArtifact>(make_art(kAnds));
  std::vector<int64_t> comp = {(int64_t)art->program->num_inputs - W, kAnds};
  for (int64_t n : prep.draws(kAnds, kSsp)) comp.push_back(n);
  std::vector<int64_t> draws = {W};
  draws.insert(draws.end(), comp.begin(), comp.end());
  const int64_t plan = Sess::planned_cots_of_draws(draws);
  bool ok = Sess::planned_cots(*art, kSsp, prep, {true, false, false}) == Sess::planned_cots_of_draws(comp);
  {
    Sess sess(&io, &pool, party, kSsp, nullptr, std::nullopt, BaseOtKind::CSW, plan, plan, prep);
    const typename Sess::SharedWires x =
        sess.share_input(1, party == 1 ? bits_of(kX, W) : emp::session::Bits(W, 0));
    auto job = sess.prepare_computation(art, {&x, nullptr, nullptr});
    emp::session::RawBindings b;
    b.inputs.resize(3);
    if (party == 2) b.inputs[1] = bits_of(kY, W);
    b.inputs[2] = bits_of(kP, kPublic);
    const emp::session::RawResult r = sess.run_computation(std::move(job), b);
    uint32_t got = 0;
    for (int i = 0; i < W; ++i) got |= (uint32_t)((*r.outputs[0])[(size_t)i] & 1) << i;
    ok = ok && got == clear_output(kAnds);
    for (int p = 1; p <= nP; ++p) {
      if (p == party) continue;
      ok = ok && sess.protocol().abit->cots_drawn(p, true) == plan &&
           sess.protocol().abit->cots_drawn(p, false) == plan;
    }
  }
  std::printf("agmpc_planned_cots[np=%d, bound slot] party %d: plan %lld: %s\n", nP, party,
              (long long)plan, ok ? "GOOD" : "BAD");
  return ok;
}

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  if (party > nP) return 0;
  NetIOMP<nP> io(party, peer_port());
  ThreadPool pool(ag::default_pool_size(nP));
  using Build = ag::GarbleConfig<>;

  bool ok = run_case<Build>(io, pool, party, "leaky", 40, ag::leaky_and_prep<nP>());
  ok = run_case<Build>(io, pool, party, "cut-and-choose", 40, ag::cut_and_choose_prep<nP>(16)) && ok;
  ok = run_case<Build>(io, pool, party, "no AND gates", 0, ag::AndPrepFactory<nP>{}) && ok;
  if constexpr (nP == 2) {
    using SoftSpoken = ag::GarbleConfig<ag::Auth::EMP_AG_GARBLE_AUTH,
                                        ag::Delivery::EMP_AG_GARBLE_DELIVERY, ag::Cot::SoftSpoken>;
    ok = run_case<SoftSpoken>(io, pool, party, "draw_cots(job)", 40, ag::leaky_and_prep<nP>(), 32) && ok;
  }
  using Ferret13 = ag::GarbleConfig<ag::Auth::EMP_AG_GARBLE_AUTH, ag::Delivery::EMP_AG_GARBLE_DELIVERY,
                                    ag::Cot::SilentFerret, ag::FerretLpn::B13>;
  ok = run_case<Ferret13>(io, pool, party, "SilentFerret b13", 40, ag::leaky_and_prep<nP>()) && ok;
  ok = run_share_case<Build>(io, pool, party) && ok;
  ok = run_bound_case<Build>(io, pool, party) && ok;
  return ok ? 0 : 1;
}
