// Stored-builtin artifacts (aes128, sha256_256) replayed over
// AGMPCSession::run_artifact and checked against a ClearCtx oracle on the SAME
// program (so each builtin's bit convention cancels). Both cases run on ONE
// session built through the production OWNING ctor (session-owned meshes +
// lanes) — the regime the golden matrix's adopting-ctor session does not
// exercise. Party 2 owns every input; results reveal to party 1.
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/builtins.h"
#include "emp-ag/emp-ag.h"
#include "test_options.h"
#include "clear_oracle.h"
#include <array>
using namespace std;
using namespace emp;

const static int nP = 3;
using Ctx = AGMPCSession<nP>::ctx_t;

// One builtin case: NI input bits filled with ((i*mul + add) % mod) == 0,
// NO output bits, dimensions gated before the run.
template <int NI, int NO>
static bool artifact_case(AGMPCSession<nP> &sess, int party, const char *name,
                          int mul, int add, int mod) {
  const circuit::BooleanProgram &prog = circuit::builtin_circuit(name);
  expecting((int)prog.num_inputs == NI && (int)prog.outputs.size() == NO,
            "agmpc_artifact: builtin dimensions != expected");

  array<bool, NI> in_bits{};
  for (int i = 0; i < NI; ++i) in_bits[i] = ((i * mul + add) % mod) == 0;

  auto in = sess.input<BitVec_T<Ctx, NI>>(2, party == 2 ? in_bits : array<bool, NI>{});
  auto out = sess.reveal(sess.run_artifact<BitVec_T<Ctx, NO>>(prog, in), 1);

  if (party != 1) return true;
  auto oracle = agmpc_test::clear_eval(prog, vector<uint8_t>(in_bits.begin(), in_bits.end()));
  bool ok = out.has_value() && (int)oracle.size() == NO;
  for (int i = 0; i < NO && ok; ++i) ok = (out.value()[i] == oracle[i]);
  cout << "agmpc_artifact[" << name << "] vs ClearCtx oracle: "
       << (ok ? "GOOD!" : "BAD!") << endl;
  return ok;
}

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  if (party > nP) return 0;

  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool, test_options(TestArgs(argc, argv, {TEST_OPTION_ARGS})));

  bool ok = artifact_case<256, 128>(sess, party, "aes128", 7, 3, 5);
  ok &= artifact_case<256, 256>(sess, party, "sha256_256", 3, 1, 4);
  return (party == 1 && !ok) ? 1 : 0;
}
