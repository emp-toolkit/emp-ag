// Fault injection through the offline-prepared path. Corrupted stored rows must
// remain latent until the online c_gamma check, staged input equivocation must
// be rejected even by a zero-AND circuit, and a forged externally authenticated
// bundle must fail its soldering open before evaluation.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "../test_options.h"
#include <iostream>
#include <string>

using namespace emp;
namespace cf = emp::frontend;

#ifndef CHEAT_NP
#define CHEAT_NP 2
#endif
constexpr int nP = CHEAT_NP;
static_assert(ag::kTestHooks, "a fault-injection test needs a hooks build (EMP_AG_TEST_HOOKS)");

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));
  const TestArgs args(argc, argv, {"prepare-only", TEST_OPTION_ARGS});
  AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool, test_options(args));
  using Bit = Bit_T<typename AGMPCSession<nP>::ctx_t>;

  if (ag::hooks().corrupt_adopted_share) {
    // The adopted-share fault injection targets one peer slot.
    expecting(nP == 2, "agmpc_prepared_cheat: corrupt_adopted_share runs at nP = 2");
    const bool source_clear = party == 2;
    auto source = sess.protocol().process_input(&source_clear, 1, 2);
    if (party == 2)
      source.wire_bundle[0].mac(0) ^= makeBlock(0, 2);  // preserve share bit
    auto circuit = cf::compile_linear<rec::Bit>([](auto x) { return x; });
    auto prepared = sess.prepare(circuit);
    auto adopted =
        sess.adopt_authenticated_input<Bit>(source.wire_bundle.data());
    auto out = sess.run(std::move(prepared), adopted);
    (void)sess.reveal(out, PUBLIC);
  } else {
    // A zero-AND circuit under flip_input_lambda, so that only the input echo can catch
    // the equivocation; one AND gate otherwise.
    // Returns false after the offline phase alone (prepare-only).
    auto run = [&](auto circuit) {
      auto prepared = sess.prepare(circuit);
      if (args.has("prepare-only")) return false;
      auto x = sess.input<Bit>(1, party == 1);
      auto y = sess.input<Bit>(2, party == 2);
      auto out = sess.run(std::move(prepared), x, y);
      (void)sess.reveal(out, PUBLIC);
      return true;
    };
    const bool ran =
        ag::hooks().flip_input_lambda
            ? run(cf::compile_linear<rec::Bit, rec::Bit>([](auto x, auto y) { return x ^ y; }))
            : run(cf::compile_linear<rec::Bit, rec::Bit>([](auto x, auto y) { return x & y; }));
    if (!ran) {
      std::cout << "prepared offline phase completed\n";
      return 0;
    }
  }

  std::cout << "agmpc_prepared_cheat[np=" << nP
            << "]: BAD! injected fault was not detected\n";
  return 1;
}
