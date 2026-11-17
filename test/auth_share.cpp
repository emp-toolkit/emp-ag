// Isolation test for AuthSharePool — the per-call authenticated-share generator
// that TriplePool::compute_and_shares and AGMPCProtocol::process_inputs build on. It
// mints aShares at the lengths the protocol uses and checks the authenticated
// relation MAC = KEY ⊕ x · Δ.
//
// AuthSharePool::compute is the full Π_aShare protocol: rcot extension + the check2
// universal-hash MAC-consistency check + an EchoBC sync. check_MAC at each length
// confirms the relation holds.
#include "emp-ag/backend/preproc/auth_share_pool.h"
using namespace std;
using namespace emp;
using namespace emp::ag;  // white-box test: reaches into the backend (AuthSharePool, check_MAC)

const static int nP = 3;
int party, port;

static void test_compute(NetIOMP<nP> *io, AuthSharePool<nP> *ap, int length) {
  if (party == 1) cout << "=== compute(" << length << ") ===" << endl;
  BlockVec MAC[nP + 1], KEY[nP + 1];
  ap->compute(MAC, KEY, length);
  check_MAC<nP>(io, MAC, KEY, ap->Delta, length, party);
  if (party == 1) cout << "  OK" << endl;
}

int main(int argc, char **argv) {
  party = parse_party(argv, nP);
  port = peer_port();
  if (party > nP) return 0;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(ag::default_pool_size(nP));

  AuthSharePool<nP> ap(&io, &pool, party);
  io.flush();

  // Lengths span small to large aShare batch sizes the protocol uses.

  test_compute(&io, &ap, 128);
  test_compute(&io, &ap, 37200);
  test_compute(&io, &ap, 81600);
  test_compute(&io, &ap, 393216);
  if (party == 1) cout << "compute: ALL PASS" << endl;

  return 0;
}
