// 3-party concurrent pairwise IKNP.
//
// Exercises only the IKNP setup + bulk-rcot loop of auth_share_pool. Each
// party constructs 2*(nP-1) IKNP instances (one sender + one receiver
// against each peer). IKNP setup is lazy: the base-OT exchange happens
// inside the first rcot call (setup_done flips on first use), so this
// exercises the per-pair base-OT-then-extend pipeline running concurrently
// across all (party, peer) pairs. A failure here ("OT Extension check
// failed" or a hang) points at emp-ot's IKNP, not at emp-ag protocol code.
//
// Knobs:
//   nP   — number of parties (3)
//   LEN  — random COTs per pair (default 1<<14 = 16K, big enough to
//          exercise the malicious-check chi-fold over many chunks)

#include "emp-ag/backend/netmp.h"
#include "emp-ag/backend/crypto/protocols.h"   // check_MAC (EMP_AG_DEBUG_CHECKS-gated COT correlation check)
#include "emp-ot/ot_extension/iknp.h"
#include <future>
#include <memory>
using namespace std;
using namespace emp;
using namespace emp::ag;   // check_MAC

const int nP = 3;
const int LEN = 1 << 14;

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(ag::default_pool_size(nP));

  // IKNP has no default ctor — store unique_ptrs and construct
  // per-peer once the IO channel is known.
  std::unique_ptr<IKNP> abit1[nP + 1];
  std::unique_ptr<IKNP> abit2[nP + 1];

  bool delta[128];
  PRG prg;
  prg.random_bool(delta, 128);
  delta[0] = true;  // bit-0(Δ)=1 invariant

  // Wire IO + role at construction. Mirrors preproc/auth_share_pool.h.
  for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
    bool me_smaller = party < peer;
    abit1[peer] = std::make_unique<IKNP>(
        ALICE, io.get(peer, me_smaller ? false : true));
    abit2[peer] = std::make_unique<IKNP>(
        BOB, io.get(peer, me_smaller ? true : false));
  }

  // Install Δ_me on every sender. The base-OT round-trip happens lazily
  // in the first rcot call below.
  for (int peer = 1; peer <= nP; ++peer) if (peer != party)
    abit1[peer]->set_delta(delta);

  // Shared choice seed across all abit2[peer] receivers
  block choice_seed;
  prg.random_block(&choice_seed, 1);
  for (int peer = 1; peer <= nP; ++peer) if (peer != party)
    abit2[peer]->choice_prg.reseed(&choice_seed);

  // Bulk RCOT phase: parallel across peers. First call on each
  // instance triggers the lazy base-OT bootstrap; subsequent
  // chunks within the same rcot call stream the extension.
  BlockVec K[nP + 1], M[nP + 1];
  for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
    K[peer].resize(LEN);
    M[peer].resize(LEN);
  }

  {
    vector<future<void>> res;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
      res.push_back(pool.enqueue([&, peer]() {
        bool me_smaller = party < peer;
        abit1[peer]->rcot(K[peer].data(), LEN);
        io.get(peer, me_smaller ? false : true)->flush();
      }));
      res.push_back(pool.enqueue([&, peer]() {
        bool me_smaller = party < peer;
        abit2[peer]->rcot(M[peer].data(), LEN);
        io.get(peer, me_smaller ? true : false)->flush();
      }));
    }
    for (auto &f : res) f.get();
  }

  // Correctness (not just "did not crash / hang"): verify the COT correlation
  // M[peer] = K_peer[me] ^ x*Delta_peer for every pair. Reuses the white-box check_MAC
  // (which broadcasts Delta in the clear -- fine for a test, so this TU is built with
  // EMP_AG_DEBUG_CHECKS); it derives x from bit0(M) under the delta[0]=1 pinning and
  // aborts via expecting() on any mismatch at any party (runN then fails ctest).
  check_MAC<nP>(&io, M, K, abit1[party == 1 ? 2 : 1]->Delta, LEN, party);
  cout << "P" << party << " COT correlation check — OK\n" << flush;
  return 0;
}
