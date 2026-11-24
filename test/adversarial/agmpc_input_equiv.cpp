// Adversarial: input-Lambda equivocation.
//
// Run with the flip_input_lambda test hook (backend/garble/input_auth.h): a malicious OWNER broadcasts a DIFFERENT input Lambda to one peer.
// The circuit is PURE-LINEAR (c = a ^ b, no AND gate), so the c_gamma MACCheck has nothing to
// bind -- ONLY the input-Lambda echo agreement can catch the split, and every honest party must
// abort with "input Lambda equivocation" (fired inside process_inputs, before the circuit).
// Without that agreement the split goes UNDETECTED: the victim's output is silently wrong and
// main() reaches the "BAD" line. nP >= 3 (at nP == 2 each owner has exactly one recipient, so
// no equivocation is possible).
//
// expecting() prints and exits nonzero, so this is ctest-gated with
// PASS_REGULAR_EXPRESSION "input Lambda equivocation": PASSES iff the abort fires.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <optional>
using namespace std;
using namespace emp;

#ifndef EQUIV_NP
#define EQUIV_NP 3
#endif
const static int nP = EQUIV_NP;
static_assert(ag::kTestHooks, "a fault-injection test needs a hooks build (EMP_AG_TEST_HOOKS)");

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool);
  using U32 = UInt_T<typename AGMPCSession<nP>::ctx_t, 32>;

  // Party 1 owns a, party 2 owns b; the hook makes owner 1 equivocate a's Lambda across peers.
  auto a = sess.input<U32>(1, party == 1 ? 0xa5c3f00du : 0);   // aborts here (in process_inputs)
  auto b = sess.input<U32>(2, party == 2 ? 0x1234abcdu : 0);
  auto c = a ^ b;                        // pure-linear: no AND for the c_gamma MACCheck to bind
  (void)sess.reveal(c, PUBLIC);

  cout << "agmpc_input_equiv[np=" << nP << ",party=" << party
       << "]: BAD! equivocation NOT detected" << endl;
  return 1;
}
