// Adversarial test for the input/output integrity checks.
//
// Each variant defines ONE corruption hook (compiled in ONLY for that TU):
//   EMP_AG_TEST_FLIP_LAMBDA -- a malicious P1 flips one broadcast AND-output Lambda
//     (open_and_masks). Exercises the certify-ALL property: every honest party aborts, and
//     at nP=3 the two GARBLERS (not just the evaluator) catch a P1 flip.
//   EMP_AG_TEST_FLIP_AGG (nP>=3) -- the garbler-row-aggregation ring tail corrupts one
//     aggregate row (passes/garble.h) -> wrong Lambda_gamma. Confirms ring corruption is caught.
//   EMP_AG_TEST_FLIP_AGG_MID (nP>=4) -- a MIDDLE ring node corrupts a row (not just the tail).
//   EMP_AG_TEST_FLIP_B (nP==2) -- a malicious garbler flips one transmitted designated bit b
//     -> wrong Lambda_gamma; c_gamma is the sole 2-party malicious-garbler guard.
//   EMP_AG_TEST_FLIP_LAAND -- a malicious party corrupts a derived two-party leaky-AND
//     value, or every row party 2 ships to party 1 at nP>=3 -> the consistency check aborts
//     during PREPROCESSING (abort message contains "LaAND").
//   EMP_AG_TEST_FLIP_LAAND_HIGH -- corrupt the highest retained check coordinate,
//     including the final partial byte at ssp=39/40. Must abort in preprocessing.
//   EMP_AG_TEST_FLIP_D / EMP_AG_TEST_FLIP_XY -- a malicious party 2 flips its share of one
//     opened bucket d-bit / Beaver x and sends it to everyone, keeping it itself, so every
//     party computes from the same wrong value; the open check must abort in preprocessing
//     (abort message contains "open check"). Built with the default open checker and,
//     via EMP_AG_OPEN_CHECK_PAIRWISE / _SYMMETRIC, with the other one.
// A wrong public value -> the c_gamma MACCheck aborts (FLIP_LAAND aborts earlier, in preproc).
// (The input-Lambda equivocation hook EMP_AG_TEST_FLIP_INPUT_LAMBDA is exercised by the sibling
// agmpc_input_equiv.cpp.)
//
// expecting() prints the fail message and exits, so this test is
// registered with ctest PASS_REGULAR_EXPRESSION "cheat in c_gamma MACCheck": it PASSES iff
// the abort fires. Reaching the end of main() means the cheat went UNDETECTED -> BAD! and a
// nonzero return (and no "cheat" line), which fails the regex.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <optional>
#include <vector>
using namespace std;
using namespace emp;

#ifndef CHEAT_NP
#define CHEAT_NP 2
#endif
#ifndef CHEAT_SSP
#define CHEAT_SSP 40
#endif
const static int nP = CHEAT_NP;

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool, CHEAT_SSP);
  using Ctx = typename AGMPCSession<nP>::ctx_t;
  using Bit = Bit_T<Ctx>;

  // 8 AND gates a[i]&b[i]; the flip corrupts gate 0's output Lambda. XOR them so the
  // corrupted gate propagates into the revealed value (and the MACCheck covers it).
  auto batch = sess.input_batch();
  std::vector<Bit> a, b;
  for (int i = 0; i < 8; ++i) {
    a.push_back(batch.template add<Bit>(1, party == 1 ? ((i & 1) != 0) : false));
    b.push_back(batch.template add<Bit>(2, party == 2 ? ((i & 3) == 0) : false));
  }
  batch.finish();
  Bit acc = sess.template input<Bit>(PUBLIC, false);
  for (int i = 0; i < 8; ++i) acc = acc ^ (a[i] & b[i]);

  // Reveal to everyone: every honest party runs the MACCheck and must abort on the flip.
  std::optional<bool> out = sess.reveal(acc, PUBLIC);

  // Only reached if the cheat was NOT detected.
  cout << "agmpc_output_cheat[np=" << nP << "]: BAD! flip NOT detected (out="
       << out.value_or(false) << ")" << endl;
  return 1;
}
