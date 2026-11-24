// Chain AES twice, C2 = aes128(K2, aes128(K1, P)), with a mid-stream checkpoint
// between the two run_artifact calls. The checkpoint settles the first AES,
// keeps C1 + K2 live as authenticated wires, and drops the rest. Oracle: the
// same two-step chain on the ClearCtx, run on the SAME "aes128" builtin.
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/builtins.h"
#include "emp-ag/emp-ag.h"
#include "test_options.h"
#include "clear_oracle.h"
#include <array>
using namespace std;
using namespace emp;

const static int nP = 3;

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool,
                        test_options(TestArgs(argc, argv, {TEST_OPTION_ARGS})));
  using Ctx = AGMPCSession<nP>::ctx_t;
  using BV128 = BitVec_T<Ctx, 128>;

  const circuit::BooleanProgram &aes = circuit::builtin_circuit("aes128");

  array<bool, 128> k1{}, k2{}, pt{};
  for (int i = 0; i < 128; ++i) {
    k1[i] = ((i * 7 + 3) % 5) == 0;
    k2[i] = ((i * 5 + 2) % 3) == 0;
    pt[i] = ((i * 3 + 1) % 4) == 0;
  }

  // P owned by party 2; K1, K2 owned by party 1. aes128 input order is pt || key.
  auto P  = sess.input<BV128>(2, party == 2 ? pt : array<bool, 128>{});
  auto K1 = sess.input<BV128>(1, party == 1 ? k1 : array<bool, 128>{});
  auto K2 = sess.input<BV128>(1, party == 1 ? k2 : array<bool, 128>{});

  auto C1 = sess.run_artifact<BV128>(aes, P, K1);
  sess.checkpoint(C1, K2);                       // settle AES #1; keep C1 + K2
  auto C2 = sess.run_artifact<BV128>(aes, C1, K2);
  auto out = sess.reveal(C2, 1);

  if (party == 1) {
    auto cat = [](const array<bool, 128> &x, const array<bool, 128> &y) {
      vector<uint8_t> v(256);
      for (int i = 0; i < 128; ++i) v[i] = x[i];
      for (int i = 0; i < 128; ++i) v[128 + i] = y[i];
      return v;
    };
    auto c1_ref = agmpc_test::clear_eval(aes, cat(pt, k1));   // 128
    array<bool, 128> c1a{};
    for (int i = 0; i < 128; ++i) c1a[i] = c1_ref[i];
    auto c2_ref = agmpc_test::clear_eval(aes, cat(c1a, k2));  // 128
    bool ok = out.has_value() && (int)c2_ref.size() == 128;
    for (int i = 0; i < 128 && ok; ++i) ok = (out.value()[i] == c2_ref[i]);
    cout << "agmpc_chain (aes128 x2 with mid checkpoint) vs ClearCtx: " << (ok ? "GOOD!" : "BAD!") << endl;
    return ok ? 0 : 1;
  }
  return 0;
}
