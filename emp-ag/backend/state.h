#ifndef EMP_AG_BACKEND_STATE_H__
#define EMP_AG_BACKEND_STATE_H__
//
// ComputeCtx<nP> — the per-call scratch context shared across the protocol-step
// methods and the gate passes (garble / evaluate / output-check). It lives outside
// AGMPCProtocol<nP> so the passes and the step-method bodies can live in their own
// phase files (passes/garble.h / passes/evaluate.h / ...) while still naming one
// context type; AGMPCProtocol re-exports it as `AGMPCProtocol<nP>::ComputeCtx`.
//
#include "emp-ag/backend/shares.h"            // AShareBundle, AShareBundleVec (-> block, BlockVec)
#include "emp-ag/backend/crypto/halfgate.h"   // HalfGateHash (MITCCRH + its gid layout)
#include <vector>

namespace emp::ag {

// Per-call scratch shared across the protocol-step methods. The heavy arrays size to
// num_slots (slot-reuse, see passes/liveness.h), not num_wire; WIRE / LABEL / EVAL
// hide the wire-id -> slot indirection.
template <int nP>
struct ComputeCtx {
  int num_in = 0, num_ands = 0, num_slots = 0;
  int num_wires = 0;   // wid-space width; set by AGMPCEngine run_trust_
  // Collapse repeated constants to one Const0 + one Const1 wire (c0_/c1_ in each
  // pass), exactly as emp-tool's RecordCtx does at compile time. Set true ONLY on
  // the live body path (AGMPCEngine::run_source): a re-executed body calls
  // public_bit once per constant *occurrence*, so without this the live wid space
  // would diverge from compile-then-run.
  // The program path already carries the compiled program's deduped id space and
  // compose carries the plan's, so both keep this false.
  bool dedup_consts = false;
  // All three source paths (program / compose / body) feed the passes the same
  // way: an id space mapped to physical slots by phys[]. Compose runs in the
  // SAME single slot space as the dense trust path (ids ARE slots, phys identity)
  // via the shared lowered replay. mask_input is slot-indexed (via MASK()) like
  // the other per-wire arrays; fabric masks are re-propagated per pass.
  std::vector<int> phys;                  // logical wire id -> physical slot
  // Trust/compose path: ids ARE slots (phys is the identity map). The accessors
  // below then skip the phys[] load entirely: that load sits in the
  // ADDRESS-DEPENDENCY chain of every slot access (load int -> shift -> dependent
  // load). The flag is a perfectly-predicted branch; only the dense/liveness path
  // (real slot reuse) pays the indirection.
  bool phys_identity = false;
  std::vector<unsigned char> mask_input;  // Λ_w, indexed by SLOT (via MASK()/phys[])
  AShareBundleVec<nP> wire_slot;          // share bundles, indexed by slot
  BlockVec label_slot;                    // m_{w,0} at Pi (i>=2), by slot
  BlockVec eval_slot[nP + 1];             // m_{w,Λ} at P1, by slot
  AShareBundleVec<nP> sigma;              // Beaver-corrected AND shares
  // P1-only per-AND eval records, produced by draw_and_seed (the DrawBeaverPass
  // fused capture + the sigma sweep) and consumed by stream_evaluate, so the
  // eval walk never touches the WIRE bundle fabric. Both are Lambda-affine
  // bases (Lambda_alpha/Lambda_beta unknown until eval; 3 basis blocks each):
  //   ev_tg[3(nP-1)ai + 3(i-2) + {0,1,2}] = (A_i, B_i, C_i): the tgamma row
  //     Mr(1,i) = C_i ^ La?A_i ^ Lb?B_i  (A = M_i[lam_in1], B = M_i[lam_in0],
  //     C = M_i[lam_sig] ^ M_i[lam_out]).
  //   ev_mu[3ai + {0,1,2}] = (s0, s1, s2): P1's c_gamma witness in the record
  //     form the garblers already stash (collapse_cgamma_from_records).
  // They live HERE, not on AGMPCProtocol: they are per-chunk state crossing the
  // produce_/consume_ seam.
  BlockVec ev_tg, ev_mu;
  // Execution-local output-check state.  These records cross either the
  // garble/evaluate -> MACCheck seam or, for prepared execution, the offline ->
  // online seam, so they belong to the job rather than the long-lived protocol.
  std::vector<unsigned char> Lambda_AND;
  BlockVec cgamma_mu;                  // P1: finalized per-AND witness
  BlockVec cgamma_s0, cgamma_s1, cgamma_s2;  // garblers: Lambda-affine records
  int SLOT(int w) const { return phys_identity ? w : phys[w]; }
  HalfGateHash<nP> mitc;                  // half-gate hash (garble / evaluate); gids per crypto/halfgate.h
  AShareBundle<nP> &WIRE(int w) { return wire_slot[SLOT(w)]; }
  block &LABEL(int w) { return label_slot[SLOT(w)]; }
  block &EVAL(int j, int w) { return eval_slot[j][SLOT(w)]; }
  unsigned char &MASK(int w) { return mask_input[SLOT(w)]; }
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_STATE_H__
