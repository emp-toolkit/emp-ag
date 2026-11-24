// The AND gates' protocol a session is given (ag::AndPrepFactory): a supplied protocol
// needs an id, which the session binds into its session id, and an id needs a protocol.
// The session refuses either alone before it sends anything.
//
// case=1 (test_args.h): an id without a protocol. case=2: a protocol without an id.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "test_args.h"
using namespace emp;

constexpr int nP = 2;

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  const int port = peer_port();
  if (party > nP) return 0;
  const int and_prep_case = (int)TestArgs(argc, argv, {"case"}).num("case", 1);

  ag::AndPrepFactory<nP> prep;
  if (and_prep_case == 1) prep.id = "test:no-protocol";
  else prep.make = ag::leaky_and_prep<nP>().make;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(&io, &pool, party, 40, nullptr, makeBlock(1, 2), BaseOtKind::CSW, -1, -1,
                        prep);
  return 1;   // unreachable: the session refuses the factory
}
