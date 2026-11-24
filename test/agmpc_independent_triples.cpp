// Live COT-demand check for WRK preprocessing: each AND consumes one output mask and B
// leaky triples, all fresh but the b of the first, which is the gate's second input
// mask: 3B COTs. Exact budgets must suffice in both direct and prepared execution. A
// prepared run with one COT less must fail; reusing any other circuit mask (above all as
// a leaky AND's a, the operand its selective failure leaks) would consume fewer COTs and
// incorrectly let that run complete.
#include "emp-ag/emp-ag.h"
#include "test_args.h"
#include "emp-tool/emp-tool.h"

#include <cstdint>
#include <cstdio>
#include <utility>

using namespace emp;
namespace cf = emp::frontend;

int main(int argc, char **argv) {
  constexpr int nP = 2;
  constexpr int ssp = 40;
  constexpr int width = 32;
  constexpr std::int64_t input_pads = 2 * width;
  constexpr std::uint32_t a_clear = 0xa5c3f00du;
  constexpr std::uint32_t b_clear = 0x3c5aa55au;
  constexpr std::uint32_t expected = a_clear & b_clear;
  const int party = parse_party(argv, nP);
  if (party > nP) return 0;
  // prepared: run through prepare(); short (with prepared): plan one COT less than the run
  // needs, which the COT stream must refuse.
  const TestArgs args(argc, argv, {"prepared", "short"});
  const bool prepared_run = args.has("prepared"), short_budget = args.has("short");
  expecting(!short_budget || prepared_run, "independent triples: short needs prepared");

  auto circuit = cf::compile<rec::UInt<width>, rec::UInt<width>>(
      [](auto a, auto b) { return a & b; });
  if (ag::agmpc_count_ands(circuit.program()) != width ||
      circuit.program().num_inputs != input_pads) {
    std::fprintf(stderr, "independent triples: unexpected test circuit shape\n");
    return 1;
  }

  // The exact budget: 128 prefix COTs, one COT per input pad, and 3B COTs per AND, in
  // EACH direction.
  const int B = ag::bucket_size(width, ssp);
  const std::int64_t expected_cots = 128 + input_pads + width * 3LL * B;

  const std::int64_t planned_cots = expected_cots - (short_budget ? 1 : 0);
  ThreadPool pool(2);
  bool ok = false;
  {
    AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool, ssp,
                          /*lanes=*/1, zero_block, BaseOtKind::CSW,
                          planned_cots, planned_cots);
    using U32 = UInt_T<typename AGMPCSession<nP>::ctx_t, width>;

    auto out = [&]() -> U32 {
      if (prepared_run) {
        auto prepared = sess.prepare(circuit);
        auto a = sess.input<U32>(1, party == 1 ? a_clear : 0);
        auto b = sess.input<U32>(2, party == 2 ? b_clear : 0);
        return sess.run(std::move(prepared), a, b);
      }
      auto a = sess.input<U32>(1, party == 1 ? a_clear : 0);
      auto b = sess.input<U32>(2, party == 2 ? b_clear : 0);
      return a & b;
    }();
    const auto opened = sess.reveal(out, PUBLIC);
    ok = opened.has_value() && static_cast<std::uint32_t>(*opened) == expected &&
         sess.num_and() == width;
    sess.checkpoint();
  }

  if (short_budget) {
    // Do not print the expected abort text here: CTest requires the actual COT
    // stream to reject the insufficient budget, rather than this fallback.
    std::fprintf(stderr,
                 "independent triples: underprovisioned prepared run completed\n");
    return 1;
  }
  std::printf("agmpc_independent_triples[%s,party=%d]: %s\n",
              prepared_run ? "prepared" : "direct", party,
              ok ? "GOOD" : "BAD");
  return ok ? 0 : 1;
}
