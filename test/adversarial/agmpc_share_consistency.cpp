// Adversarial: the aShare consistency check (check2) at nP >= 3, on a circuit with no AND.
//
// Built with ONE of the production-guarded hooks in backend/ashare/ashare_gen.h:
//   EMP_AG_TEST_SPLIT_CHOICE -- party 2 holds different bits toward party 3 than toward
//     everyone else, so its shares disagree across peers while every MAC stays valid.
//     Party 3's check of party 2's tag aborts at the input draw.
//   EMP_AG_TEST_FLIP_BW -- party 2 sends party 3 a different consistency value bw than it
//     sends everyone else. Party 3's check of party 2's tag aborts at the input draw.
//   EMP_AG_TEST_TWO_WORLD (with SPLIT_CHOICE) -- party 2 sends each peer the bw its bits
//     toward that peer give, and opens each input mask to its owner with the bit it holds
//     toward that owner. Every tag and every MAC check passes, so without the agreement on
//     the views two honest parties would reveal different outputs.
// The circuit is PURE-LINEAR (c = a ^ b), so no triple is generated and no open check runs:
// the consistency views are still pending at the reveal, where settle_check2() must agree on
// them, so every honest party aborts with "cheat aShare" there or at the tag check. No fault
// here touches anything the other checks see (the COTs are valid, the input Lambda echo
// agrees, and there is no AND for the c_gamma MACCheck), so reaching the end of main()
// means it went undetected.
//
// expecting() prints and exits nonzero, so this is ctest-gated with
// PASS_REGULAR_EXPRESSION "cheat aShare": it PASSES iff the abort fires.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
using namespace std;
using namespace emp;
#ifndef CONSISTENCY_NP
#define CONSISTENCY_NP 3
#endif
const static int nP = CONSISTENCY_NP;
int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool);
  using U32 = UInt_T<typename AGMPCSession<nP>::ctx_t, 32>;
  auto a = sess.input<U32>(1, party == 1 ? 0xa5c3f00du : 0);
  auto b = sess.input<U32>(2, party == 2 ? 0x1234abcdu : 0);
  auto c = a ^ b;   // pure-linear: no triples, no open check
  (void)sess.reveal(c, PUBLIC);   // aborts here (settle_check2 before the reveal)
  cout << "agmpc_share_consistency[np=" << nP << ",party=" << party
       << "]: BAD! inconsistent shares NOT detected" << endl;
  return 1;
}
