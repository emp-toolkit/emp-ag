// Live COT-demand check for WRK preprocessing: each AND consumes one output mask and B
// leaky triples, all fresh but the b of the first, which is the gate's second input
// mask: 3B COTs. Exact budgets must suffice in both direct and prepared execution. A
// prepared run with one COT less must fail; reusing any other circuit mask (above all as
// a leaky AND's a, the operand its selective failure leaks) would consume fewer COTs and
// incorrectly let that run complete.
#include "emp-ag/emp-ag.h"
#include "emp-tool/emp-tool.h"

#include <cstdint>
#include <cstdio>
#include <utility>

using namespace emp;
namespace cf = emp::frontend;

#ifndef INDEPENDENT_TRIPLES_PREPARED
#define INDEPENDENT_TRIPLES_PREPARED 0
#endif
#ifndef INDEPENDENT_TRIPLES_SHORT
#define INDEPENDENT_TRIPLES_SHORT 0
#endif

static_assert(!INDEPENDENT_TRIPLES_SHORT || INDEPENDENT_TRIPLES_PREPARED);

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

  const std::int64_t planned_cots = expected_cots - INDEPENDENT_TRIPLES_SHORT;
  ThreadPool pool(2);
  bool ok = false;
  {
    AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool, ssp,
                          /*lanes=*/1, zero_block, BaseOtKind::CSW,
                          planned_cots, planned_cots);
    using U32 = UInt_T<typename AGMPCSession<nP>::ctx_t, width>;

#if INDEPENDENT_TRIPLES_PREPARED
    auto prepared = sess.prepare(circuit);
    auto a = sess.input<U32>(1, party == 1 ? a_clear : 0);
    auto b = sess.input<U32>(2, party == 2 ? b_clear : 0);
    auto out = sess.run(std::move(prepared), a, b);
#else
    auto a = sess.input<U32>(1, party == 1 ? a_clear : 0);
    auto b = sess.input<U32>(2, party == 2 ? b_clear : 0);
    auto out = a & b;
#endif
    const auto opened = sess.reveal(out, PUBLIC);
    ok = opened.has_value() && static_cast<std::uint32_t>(*opened) == expected &&
         sess.num_and() == width;
    sess.checkpoint();
  }

#if INDEPENDENT_TRIPLES_SHORT
  // Do not print the expected abort text here: CTest requires the actual COT
  // stream to reject the insufficient budget, rather than this fallback.
  std::fprintf(stderr,
               "independent triples: underprovisioned prepared run completed\n");
  return 1;
#else
  std::printf("agmpc_independent_triples[%s,party=%d]: %s\n",
              INDEPENDENT_TRIPLES_PREPARED ? "prepared" : "direct", party,
              ok ? "GOOD" : "BAD");
  return ok ? 0 : 1;
#endif
}
