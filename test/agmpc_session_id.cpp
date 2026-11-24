// AGMPCSession's session id. Left empty, the parties agree on a fresh id at
// setup: both hold the same one, it is not zero, and two sessions get
// different ids. A given id is used as is, bound to the session's options when they
// are not the defaults (ag::bind_garble_config, ag::bind_build_options) and to its
// protocol for the AND gates unless that is the leaky ANDs (ag::bind_and_prep).
// SilentFerret's LPN set binds the id only when it is not the default, and only on
// SilentFerret streams. The sessions share one mesh, as the golden-snapshot cases do.
//
// With an option other than the default (test_options.h; CMake runs a variant with
// open_check=symmetric), ag::bind_build_options must change the id; otherwise it must
// keep it.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "test_options.h"
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
  const TestArgs args(argc, argv, {TEST_OPTION_ARGS});
  const ag::ProtocolOptions opts = test_options(args);

  NetIOMP<nP> io(party, port);
  ThreadPool pool(ag::default_pool_size(nP));
  block ids[2];
  for (block &id : ids) {
    AGMPCSession<nP> sess(&io, &pool, party, opts);
    id = agreed(io, party, sess.protocol().session_id);
  }
  const block zero = zero_block;
  expecting(!cmpBlock(&ids[0], &zero, 1), "agmpc_session_id: an agreed id is zero");
  expecting(!cmpBlock(&ids[0], &ids[1], 1),
            "agmpc_session_id: two sessions agreed on the same id");

  const block given = makeBlock(0x73657373696f6eULL, 0x6964ULL);
  {
    AGMPCSession<nP> sess(&io, &pool, party, opts, 40, nullptr, given);
    const block kept = sess.protocol().session_id;
    const block options = ag::bind_build_options<nP, ag::GarbleConfig<>>(
        ag::bind_garble_config<nP, ag::GarbleConfig<>>(given), opts);
    if (args.has("open_check")) {
      expecting(!cmpBlock(&options, &given, 1), "agmpc_session_id: an option left the id as it was");
    } else {
      const block config_only = ag::bind_garble_config<nP, ag::GarbleConfig<>>(given);
      expecting(cmpBlock(&options, &config_only, 1), "agmpc_session_id: the default options changed the id");
    }
    const block want = ag::bind_and_prep(options, ag::default_and_prep<nP>(opts).id);
    expecting(cmpBlock(&kept, &want, 1), "agmpc_session_id: a given id was replaced");
  }
  {
    // The leaky ANDs keep the id; cut-and-choose triples bind theirs. One session at a
    // time, as a process holds one chunk recorder.
    const block base = ag::bind_build_options<nP, ag::GarbleConfig<>>(
        ag::bind_garble_config<nP, ag::GarbleConfig<>>(given), opts);
    block kept, bound;
    {
      AGMPCSession<nP> leaky(&io, &pool, party, opts, 40, nullptr, given, BaseOtKind::CSW, -1, -1,
                             ag::leaky_and_prep<nP>());
      kept = leaky.protocol().session_id;
    }
    {
      AGMPCSession<nP> cnc(&io, &pool, party, opts, 40, nullptr, given, BaseOtKind::CSW, -1, -1,
                           ag::cut_and_choose_prep<nP>(1024));
      bound = cnc.protocol().session_id;
    }
    expecting(cmpBlock(&kept, &base, 1), "agmpc_session_id: the leaky ANDs changed the id");
    const block want = ag::bind_and_prep(base, ag::cut_and_choose_prep<nP>(1024).id);
    expecting(cmpBlock(&bound, &want, 1) && !cmpBlock(&bound, &base, 1),
              "agmpc_session_id: cut-and-choose triples did not bind the id");
    expecting(ag::cut_and_choose_prep<nP>(1024, 4).id != ag::cut_and_choose_prep<nP>(1024).id,
              "agmpc_session_id: a declared batch count is not in the protocol's id");
  }
  {
    // SilentFerret's LPN set: B13 binds the id beyond what SilentFerret itself binds, and
    // SoftSpoken streams ignore it.
    using Ferret12 = ag::GarbleConfig<ag::Auth::KRRW, ag::Delivery::RING, ag::Cot::SilentFerret>;
    using Ferret13 = ag::GarbleConfig<ag::Auth::KRRW, ag::Delivery::RING, ag::Cot::SilentFerret,
                                      ag::FerretLpn::B13>;
    using Soft13 = ag::GarbleConfig<ag::Auth::KRRW, ag::Delivery::RING, ag::Cot::SoftSpoken,
                                    ag::FerretLpn::B13>;
    const block f12 = ag::bind_garble_config<nP, Ferret12>(given);
    const block f13 = ag::bind_garble_config<nP, Ferret13>(given);
    const block s13 = ag::bind_garble_config<nP, Soft13>(given);
    expecting(!cmpBlock(&f12, &given, 1) && !cmpBlock(&f13, &f12, 1) && !cmpBlock(&f13, &given, 1),
              "agmpc_session_id: SilentFerret's LPN set did not bind the id");
    expecting(cmpBlock(&s13, &given, 1), "agmpc_session_id: an LPN set changed a SoftSpoken id");
  }
  if (party == 1) printf("agmpc_session_id: OK\n");
  return 0;
}
