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
#include "emp-ag/backend/runtime.h"   // default_pool_size
#include "emp-ot/ot_extension/iknp.h"
#include "emp-tool/emp-tool.h"
#include <future>
#include <memory>
using namespace std;
using namespace emp;
using namespace emp::ag;

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
  // M = K ^ r*Delta for the pair (i, j) with i < j, where i is the sender and r is
  // j's choice bits toward i. Each receiver draws its own choices, so r is read per
  // pair from bit0(M) under the delta[0]=1 pinning. White-box: i sends j its Delta and
  // keys in the clear (fine for a test), and any mismatch aborts via expecting() (runN
  // then fails ctest).
  for (int i = 1; i <= nP; ++i)
    for (int j = i + 1; j <= nP; ++j) {
      if (party == i) {
        const block D = abit1[j]->Delta;
        io.send_data(j, &D, sizeof(block));
        io.send_data(j, K[j].data(), sizeof(block) * LEN);
        io.flush(j);
      } else if (party == j) {
        block D;
        BlockVec expect(LEN);
        io.recv_data(i, &D, sizeof(block));
        io.recv_data(i, expect.data(), sizeof(block) * LEN);
        for (int k = 0; k < LEN; ++k)
          if (getLSB(M[i][k])) expect[k] = expect[k] ^ D;
        expecting(cmpBlock(M[i].data(), expect.data(), LEN),
                  "three_party_iknp: COT correlation check failed");
      }
    }
  cout << "P" << party << " COT correlation check — OK\n" << flush;
  return 0;
}
