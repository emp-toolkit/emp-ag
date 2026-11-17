// Round check: many input feeds across owners batched into a SINGLE
// process_inputs round via sess.input_batch(), not one round per value or per
// owner. With K+1 party-1 feeds + one party-2 feed + a public sentinel, the
// batch must issue exactly one process_input_calls.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <vector>
using namespace std;
using namespace emp;

const static int nP = 3;

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool);
  using Ctx = AGMPCSession<nP>::ctx_t;
  using Bit = Bit_T<Ctx>;

  const int K = 32;
  Bit zero = sess.input<Bit>(PUBLIC, false);   // public sentinel (no OT)

  // ONE batch for every secret input across both owners.
  auto batch = sess.input_batch();
  Bit y = batch.add<Bit>(2, party == 2);
  std::vector<Bit> xs;
  for (int i = 0; i <= K; ++i)
    xs.push_back(batch.add<Bit>(1, (party == 1) ? ((i & 1) != 0) : false));
  batch.finish();

  Bit acc = zero;
  for (int i = 0; i < K; ++i) acc = acc ^ xs[i];
  Bit bit0b = (acc & xs[K]) ^ y;                // one AND + party-2 input
  std::optional<bool> bit0 = sess.reveal(bit0b, 1);

  int calls = sess.process_input_calls();
  if (party == 1) {
    cout << "agmpc_rounds: K=" << K << " mixed-owner inputs -> process_input_calls="
         << calls << "  " << (calls == 1 ? "GOOD! (batched)" : "BAD! (per-input)")
         << "  (out bit0=" << bit0.value_or(false) << ")" << endl;
    return calls == 1 ? 0 : 1;
  }
  return 0;
}
