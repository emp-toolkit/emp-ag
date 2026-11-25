// Adversarial test for the input/output integrity checks.
//
// Each variant turns on ONE corruption hook (backend/common/test_hooks.h):
//   flip_lambda -- a malicious P1 flips one broadcast AND-output Lambda
//     (open_and_masks). Exercises the certify-ALL property: every honest party aborts, and
//     at nP=3 the two GARBLERS (not just the evaluator) catch a P1 flip.
//   flip_agg (nP>=3) -- the garbler-row-aggregation ring tail corrupts one
//     aggregate row (garble/passes/garble.h) -> wrong Lambda_gamma. Confirms ring corruption is caught.
//   flip_agg_mid (nP>=4) -- a MIDDLE ring node corrupts a row (not just the tail).
//   flip_b (nP==2) -- a malicious garbler flips one transmitted designated bit b
//     -> wrong Lambda_gamma; c_gamma is the sole 2-party malicious-garbler guard.
//     With skip_cgamma_check the garbler also answers P1's check value without comparing
//     it, so the abort can only come from P1's own comparison.
//   flip_laand -- a malicious party corrupts a derived two-party leaky-AND
//     value, or every row party 2 ships to party 1 at nP>=3 -> the consistency check aborts
//     during PREPROCESSING (abort message contains "LaAND").
//   flip_laand_high -- corrupt the highest retained check coordinate,
//     including the final partial byte at ssp=39/40. Must abort in preprocessing.
//     With lanes=1 at nP==2, both leaky-AND hooks run on the single-lane row kernel
//     instead of the lane-split one.
//   flip_d / flip_xy -- a malicious party 2 flips its share of one
//     opened bucket d-bit / Beaver x and sends it to everyone, keeping it itself, so every
//     party computes from the same wrong value; the open check must abort in preprocessing
//     (abort message contains "open check"). Built with the default open checker and,
//     via open_check=pairwise / symmetric (test_options.h), with the other one.
//   flip_bw (nP>=3) -- party 2 sends party 3 a different aShare consistency
//     value bw than everyone else, with the tag on the right one. Party 3's check of the
//     tag aborts in preprocessing, under either open checker ("cheat aShare").
//   tamper_prefix -- party 1 flips one bit of the first correction it sends to
//     party 2 inside the 128-COT bootstrap prefix (backend/common/netmp.h's TamperNetIO). Party 2's
//     check of the prefix must abort during setup, before the reverse direction's base OTs
//     are derived from it ("SoftSpoken subspace VOLE check failed").
//   cnc_* (with cnc=<batch>) -- the cut-and-choose triple
//     generator: a wrong product correction (cnc_flip_product), z ^ r opening (cnc_flip_zr) or
//     sacrifice difference (cnc_flip_open), sent to everyone; a z ^ r opening (cnc_split_zr) or, as
//     a king, an opened value (cnc_king_split) sent to party 3 alone. Each must abort while the
//     triples are generated (backend/triple/cut_and_choose_triples.h).
// A wrong public value -> the c_gamma MACCheck aborts (flip_laand aborts earlier, in preproc).
// (The input-Lambda equivocation hook flip_input_lambda is exercised by the sibling
// agmpc_input_equiv.cpp; the aShare consistency check on a circuit with no AND, by
// agmpc_share_consistency.cpp.)
//
// expecting() prints the fail message and exits, so this test is
// registered with ctest PASS_REGULAR_EXPRESSION "cheat in c_gamma MACCheck": it PASSES iff
// the abort fires. Reaching the end of main() means the cheat went UNDETECTED -> BAD! and a
// nonzero return (and no "cheat" line), which fails the regex.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "../test_options.h"
#include <optional>
#include <vector>
using namespace std;
using namespace emp;

#ifndef CHEAT_NP
#define CHEAT_NP 2
#endif
const static int nP = CHEAT_NP;
static_assert(ag::kTestHooks, "a fault-injection test needs a hooks build (EMP_AG_TEST_HOOKS)");

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  if (party > nP) return 0;
  const TestArgs args(argc, argv, {"ssp", "depth2", "lanes", TEST_OPTION_ARGS});
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool, test_options(args),
                        (int)args.num("ssp", 40), (int)args.num("lanes", -1));
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
  if (args.has("depth2")) {
    // Depth 2: a second AND reads each first one's output, so under Auth::WRK a label P1
    // recovers wrong at the first is caught by P1's own check of the second, not only when
    // P1 hands the garblers the output's Lambda.
    for (int i = 0; i < 8; ++i) acc = acc ^ ((a[i] & b[i]) & a[(i + 1) % 8]);
  } else {
    for (int i = 0; i < 8; ++i) acc = acc ^ (a[i] & b[i]);
  }

  // Reveal to everyone: every honest party runs the MACCheck and must abort on the flip.
  std::optional<bool> out = sess.reveal(acc, PUBLIC);

  // Only reached if the cheat was NOT detected.
  cout << "agmpc_output_cheat[np=" << nP << "]: BAD! flip NOT detected (out="
       << out.value_or(false) << ")" << endl;
  return 1;
}
