// A PURE-LINEAR circuit (zero AND gates) revealed to a GARBLER. A garbler propagates its
// fabric MASK ONLY inside the output-check walk (MaskWitnessPass), which must run even
// when num_ands==0; otherwise a garbler-decoded XOR output would carry MASK 0 instead of
// Λ_a ⊕ Λ_b. Checks reveal-to-a-garbler AND reveal-PUBLIC of a ^ b against the cleartext,
// at every party count (party 1 = evaluator, 2..n = garblers).
// One source, party count via LIN_NP (runN 2 = 2 parties, ./run = 3). (The adversarial input-Lambda
// equivocation on this same pure-linear shape lives in ../adversarial/agmpc_input_equiv.cpp.)
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "test_options.h"
#include <optional>
using namespace std;
using namespace emp;

#ifndef LIN_NP
#define LIN_NP 2
#endif
const static int nP = LIN_NP;

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool, test_options(TestArgs(argc, argv, {TEST_OPTION_ARGS})));
  using U32 = UInt_T<typename AGMPCSession<nP>::ctx_t, 32>;

  const uint32_t XA = 0xa5c3f00du, XB = 0x1234abcdu;
  const uint32_t expect = XA ^ XB;
  auto a = sess.input<U32>(1, party == 1 ? XA : 0);
  auto b = sess.input<U32>(2, party == 2 ? XB : 0);
  auto c = a ^ b;                 // PURE LINEAR: zero AND gates
  bool ok = true;

  // reveal to party 2 (a GARBLER) -- the regression target; others get nullopt.
  auto r2 = sess.reveal(c, 2);
  if (party == 2) ok &= (r2.has_value() && (uint32_t)r2.value() == expect);
  else            ok &= !r2.has_value();

  // reveal to PUBLIC: every party (incl. garblers) reconstructs.
  uint32_t rp = (uint32_t)sess.reveal(c, PUBLIC).value_or(0);
  ok &= (rp == expect);

  cout << "agmpc_linear[np=" << nP << ",party=" << party << "]: "
       << (ok ? "GOOD" : "BAD") << endl;
  return ok ? 0 : 1;
}
