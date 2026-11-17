// Fault injection through the offline-prepared path. Corrupted stored rows must
// remain latent until the online c_gamma check, staged input equivocation must
// be rejected even by a zero-AND circuit, and a forged externally authenticated
// bundle must fail its soldering open before evaluation.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <iostream>
#include <string>

using namespace emp;
namespace cf = emp::frontend;

#ifndef CHEAT_NP
#define CHEAT_NP 2
#endif
constexpr int nP = CHEAT_NP;

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool);
  using Bit = Bit_T<typename AGMPCSession<nP>::ctx_t>;

#ifdef EMP_AG_TEST_CORRUPT_ADOPTED_SHARE
  static_assert(nP == 2,
                "the adopted-share fault injection targets one peer slot");
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
#else
#ifdef EMP_AG_TEST_FLIP_INPUT_LAMBDA
  auto circuit = cf::compile_linear<rec::Bit, rec::Bit>(
      [](auto x, auto y) { return x ^ y; });
#else
  auto circuit = cf::compile_linear<rec::Bit, rec::Bit>(
      [](auto x, auto y) { return x & y; });
#endif
  auto prepared = sess.prepare(circuit);
  if (argc >= 3 && std::string(argv[2]) == "prepare-only") {
    std::cout << "prepared offline phase completed\n";
    return 0;
  }
  auto x = sess.input<Bit>(1, party == 1);
  auto y = sess.input<Bit>(2, party == 2);
  auto out = sess.run(std::move(prepared), x, y);
  (void)sess.reveal(out, PUBLIC);
#endif

  std::cout << "agmpc_prepared_cheat[np=" << nP
            << "]: BAD! injected fault was not detected\n";
  return 1;
}
