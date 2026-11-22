// AGMPCSession's session id. Left empty, the parties agree on a fresh id at
// setup: both hold the same one, it is not zero, and two sessions get
// different ids. A given id is used as is, bound to the session's options when they
// are not the defaults (ag::bind_garble_config). The sessions share one mesh, as the
// golden-snapshot cases do.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdio>
using namespace std;
using namespace emp;

const static int nP = 2;

// Each party sends its id to the other; both must hold the same one.
static block agreed(NetIOMP<nP> &io, int party, const block &mine) {
  const int peer = 3 - party;
  block theirs;
  if (party == 1) {
    io.send_data(peer, &mine, sizeof(block));
    io.flush(peer);
    io.recv_data(peer, &theirs, sizeof(block));
  } else {
    io.recv_data(peer, &theirs, sizeof(block));
    io.send_data(peer, &mine, sizeof(block));
    io.flush(peer);
  }
  expecting(cmpBlock(&mine, &theirs, 1),
            "agmpc_session_id: the parties hold different session ids");
  return mine;
}

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(ag::default_pool_size(nP));
  block ids[2];
  for (block &id : ids) {
    AGMPCSession<nP> sess(&io, &pool, party);
    id = agreed(io, party, sess.protocol().session_id);
  }
  const block zero = zero_block;
  expecting(!cmpBlock(&ids[0], &zero, 1), "agmpc_session_id: an agreed id is zero");
  expecting(!cmpBlock(&ids[0], &ids[1], 1),
            "agmpc_session_id: two sessions agreed on the same id");

  const block given = makeBlock(0x73657373696f6eULL, 0x6964ULL);
  {
    AGMPCSession<nP> sess(&io, &pool, party, 40, nullptr, given);
    const block kept = sess.protocol().session_id;
    const block want = ag::bind_garble_config<nP, ag::GarbleConfig<>>(given);
    expecting(cmpBlock(&kept, &want, 1), "agmpc_session_id: a given id was replaced");
  }
  if (party == 1) printf("agmpc_session_id: OK\n");
  return 0;
}
