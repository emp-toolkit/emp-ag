// The README usage example, kept compiling: three parties jointly add two 32-bit
// inputs and reveal the sum to party 1 over AGMPCSession (malicious security;
// party 1 = evaluator, parties 2..n = garblers). Run from the repo root on localhost:
//
//   ./runN 3 build/bin/example_add
//
// Registered as a ctest smoke test, so this file cannot drift from the library API.
#include <emp-ag/emp-ag.h>
#include <cstdio>
using namespace emp;

constexpr int nP = 3;                            // nP == 2 for two-party
int main(int argc, char **argv) {
  int party = parse_party(argv, nP);             // argv[1]; party in [1, nP]
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(),      // port from $EMP_PORT (default 12345)
                        /*ip table*/ nullptr,    // nullptr = localhost for all parties
                        &pool);

  using Ctx    = AGMPCSession<nP>::ctx_t;
  using UInt32 = UInt_T<Ctx, 32>;
  uint32_t x = 20, y = 22;
  auto a = sess.input<UInt32>(/*owner*/ 1, party == 1 ? x : 0);  // each party feeds its own input
  auto b = sess.input<UInt32>(/*owner*/ 2, party == 2 ? y : 0);
  auto sum = sess.reveal(a + b, /*recipient*/ 1);  // std::optional<uint32_t>: engaged at
                                                   // party 1, std::nullopt elsewhere
  if (party == 1) {
    printf("x + y = %u\n", sum.value());
    return sum.value() == x + y ? 0 : 1;           // the ctest verdict
  }
  return 0;
}
