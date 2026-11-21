#ifndef EMP_AG_BACKEND_GARBLE_PROTOCOL_H__
#define EMP_AG_BACKEND_GARBLE_PROTOCOL_H__
#include "emp-ag/backend/common/protocols.h"   // sampleRandom
#include "emp-ag/backend/garble/garble_config.h"      // GarbleConfig, bind_garble_config
#include "emp-ag/backend/ashare/auth_share_pool.h"
#include "emp-ag/backend/triple/triple_pool.h"
#include "emp-ag/backend/garble/state.h"            // emp::ag::ComputeCtx<nP>
#include "emp-ag/backend/garble/material.h"         // PreparedInputBinding
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/garble/wires.h"
#include "emp-ag/backend/garble/passes/liveness.h"
#include "emp-ag/backend/common/profiling.h"
#include "emp-ag/backend/garble/passes/pass.h"       // emp::ag::run_pass + SlotGateMixin (shared)
#include "emp-ag/backend/garble/passes/replay.h"     // emp::ag::LoweredUnit / replay_lowered (shared compose lowering)
#include "emp-tool/ir/execute.h"   // execute_program, ProgramWorkspace, BooleanContext
#include "emp-tool/ir/context/compose.h"  // ComposePlan / ComposeInstance / ComposeEvent
#include <algorithm>
#include <array>
#include <cstdint>
#include <optional>
#include <thread>
#include <utility>
#include <vector>

namespace emp::ag {

template <int nP> struct EvalChunk;

// The engine; friended for ComputeCtx + per-step access.
template <int nP, class Cfg = GarbleConfig<>> class AGMPCEngine;

// Multi-party authenticated garbling protocol Π_MPC. The half-gate construction:
// every Pi (i ≥ 2) sends 2 ciphertexts G_{γ,0/1}^i and 3 ciphertexts
// per cross peer S_{γ,0/1/2}^{i,j}. Cfg (backend/garble/garble_config.h) picks how P1's Λ_γ is
// authenticated. KRRW: P2 additionally sends b_γ, P1 recovers
// Λ_γ = b_γ ⊕ LSB1(m_{γ,Λ_γ}^2), and a check after evaluation certifies it. WRK: every
// Pi also sends 3 truncated ciphertexts toward P1, from which P1 decodes and checks
// Λ_γ at the gate. The bit-1 Δ convention
// is set in ashare/auth_share_pool.h: bit1(Δ_j) = 1 for j ≠ 1 and
// bit1(Δ_1) = nP mod 2. Bit 0 is reserved for share-value encoding.
//
// API:
//   process_inputs(owners, bits_per_owner) → SecureWires[]  // authenticated inputs, batched
//   process_input(bits, n, owner)          → SecureWires    // single-owner wrapper
//   decode(wires, recipient)               → vector<bool>   // output decode
//
// Circuit execution is owned by the AGMPCEngine<nP> (backend/garble/engine.h), which
// consumes emp-tool's canonical BooleanProgram and drives the private step helpers
// below in protocol order. process_input() and the engine's circuit walks draw
// aShares/triples on demand from TriplePool and its inner AuthSharePool, which
// mint fresh material per call (neither keeps a pool).

template <int nP, class Cfg = GarbleConfig<>>
class AGMPCProtocol {
  static_assert(nP >= 2, "AGMPC requires at least 2 parties");
public:
  // Long-lived setup, constructed once per session and reused across all input,
  // circuit-run and decode calls: the share pool (COT mesh + Δ + aShares,
  // ashare/auth_share_pool.h) and the triple pool over it (triple/triple_pool.h).
  AuthSharePool<nP> *abit = nullptr;
  TriplePool<nP> *fpre = nullptr;
  NetIOMP<nP> *io;
  ThreadPool *pool;
  int party;
  block session_id;
  block Delta;
  PRG prg;

  // Reused per-chunk pass scratch (grow-only; persists across chunks via this
  // long-lived protocol object).
  // DrawBeaverPass: every AND's operand mask shares -- the share bits, and the MACs and
  // keys per peer or the mu_i blocks, as the open check needs (garble/passes/draw_beaver.h).
  std::vector<unsigned char> bp_abit_, bp_bbit_;
  BlockVec bp_amac_[nP + 1], bp_akey_[nP + 1], bp_bmac_[nP + 1], bp_bkey_[nP + 1];
  BlockVec bp_amu_, bp_bmu_;
  // The ordinary fused path swaps these grow-only buffers into its stack
  // ComputeCtx and back at the call boundary. Prepared jobs keep their own
  // context-resident copies across phases. This keeps the fused path's steady
  // state allocation-free without putting prepared state on the session.
  std::vector<unsigned char> normal_Lambda_AND_scratch_;
  BlockVec normal_cgamma_mu_scratch_;
  BlockVec normal_cgamma_s0_scratch_, normal_cgamma_s1_scratch_;
  BlockVec normal_cgamma_s2_scratch_;
  // Output goes to every party (F_MPC delivers y^i to each P_i): the symmetric SPDZ
  // c_gamma MACCheck (garble/passes/mask_witness.h) certifies every party under Auth::KRRW;
  // under Auth::WRK, P1 checks every gate and each garbler the outputs' Lambda against
  // its labels (garble_config.h). Either way decode is not gated on a declared recipient. `decode(wires, recipient)` only chooses who
  // reconstructs a given open; that is a delivery choice made at reveal time, not
  // security state.

  // grp (optional): a NetIOMPGroup (mesh(0) == io_) enabling lane-parallel COT;
  // null => single mesh. session_id_: used as given; empty => the
  // parties agree on a fresh one here (see AGMPCSession).
  AGMPCProtocol(NetIOMP<nP> *io_, ThreadPool *pool_, int party_, int ssp_ = 40,
                NetIOMPGroup<nP> *grp = nullptr,
                std::optional<block> session_id_ = std::nullopt,
                BaseOtKind base_ot_kind = BaseOtKind::CSW,
                int64_t planned_sender_cots = -1,
                int64_t planned_receiver_cots = -1)
      : io(io_), pool(pool_), party(party_) {
    ag::validate_protocol_runtime(pool_, party_, nP);
    (void)ag::checked_statistical_security(ssp_);
    expecting(io_ != nullptr, "AGMPCProtocol: NetIOMP must not be null");
    expecting(io_->party == party_,
              "AGMPCProtocol: NetIOMP party does not match protocol party");
    expecting(grp == nullptr || (grp->size() >= 1 && &grp->mesh(0) == io_),
              "AGMPCProtocol: group mesh(0) must equal the protocol NetIOMP");
    // Every party contributes to a fresh id through the commit-then-open coin,
    // so none of them picks it.
    session_id = session_id_ ? *session_id_ : sampleRandom<nP>(io_, &prg, pool_, party_);
    // Parties that disagree on the garbling options then disagree on the id, and setup fails.
    session_id = bind_garble_config<nP, Cfg>(session_id);
    // The share pool first (base OTs and COT setup), then the triple pool over it.
    abit = new AuthSharePool<nP>(io_, pool_, party_, grp, session_id, base_ot_kind,
                                 planned_sender_cots, planned_receiver_cots);
    fpre = new TriplePool<nP>(*abit, io_, pool_, party_, ssp_, grp, session_id);
    Delta = abit->Delta;
  }
  ~AGMPCProtocol() {
    delete fpre;
    delete abit;
  }

  // Owns abit and fpre (and borrows io/pool); non-copyable / non-movable so the raw
  // owning pointers are never double-deleted.
  AGMPCProtocol(const AGMPCProtocol &) = delete;
  AGMPCProtocol &operator=(const AGMPCProtocol &) = delete;
  AGMPCProtocol(AGMPCProtocol &&) = delete;
  AGMPCProtocol &operator=(AGMPCProtocol &&) = delete;

  // ---- Streaming garble transport ----
  // Garble rows are shipped garbler->P1 in fixed-size chunks so a garbler's
  // GarblePass compute overlaps its send (a drain thread ships each chunk while
  // the pass fills the next). A chunk carries up to garble_window_cap(num_ands)
  // ANDs: this garbler's 2 G rows per AND, its cross-peer S rows (one BlockVec
  // per dest j != party, 3 rows per AND), and by Auth one designated b bit per AND
  // (KRRW, P2 only) or 3 rows toward P1 per AND (WRK). Sender (garble_and_ship,
  // garble/passes/garble_transport.h) and receiver (StreamEvaluatePass) walk identical chunk
  // boundaries derived from garble_window_cap(num_ands) (garble/passes/wire_format.h).


  // ====== Public API ======

  // Input authentication, batched across any number of input owners.
  // owners[k] owns bits_per_owner[k]. At the owner, that vector must contain the
  // cleartext bits; non-owners pass same-width dummy bits. Internally one AuthSharePool
  // draw covers all owners; then λ_w is opened to each OWNING PARTY (never to the
  // evaluator), which forms Λ_w = λ_w ⊕ x_w and broadcasts it; the combined bundle is
  // sliced back into one SecureWires result per owner.
  std::vector<SecureWires<nP>> process_inputs(
      const std::vector<int> &owners,
      const std::vector<std::vector<bool>> &bits_per_owner);

  // Single-owner convenience wrapper.
  SecureWires<nP> process_input(const bool *inputs, int n, int owner);

  // Adopt externally-authenticated aShare bundles as input wires, reusing their
  // IT-MAC (the mask λ) with Λ=0 instead of a fresh COT authentication. Generic
  // reactive-input primitive (e.g. a value authenticated by another protocol under
  // this session's keys); see input_auth.h.
  SecureWires<nP> adopt_authenticated_input(const AShareBundle<nP> *bundles, int n);

  // Public constants, built locally (no OT, no communication): Λ = bit, zero
  // share-bundle, garblers' label0 = bit?Δ:0, the evaluator's eval_label = 0 —
  // byte-identical to what the engine produces for a CONST gate (see
  // gather_outputs / the garble+evaluate const handling). Lets a PUBLIC input be
  // materialized eagerly, exactly like a secret input's authenticated share.
  SecureWires<nP> public_wires(const std::vector<bool> &bits) {
    const int n = (int)bits.size();
    SecureWires<nP> sw;
    sw.Lambda.resize(n);
    sw.wire_bundle.assign(n, AShareBundle<nP>{});
    if (party != 1) sw.label0.resize(n);
    else for (int j = 2; j <= nP; ++j) sw.eval_label[j].resize(n);
    for (int i = 0; i < n; ++i) {
      sw.Lambda[i] = bits[i] ? 1 : 0;
      if (party != 1) sw.label0[i] = bits[i] ? Delta : zero_block;
      else for (int j = 2; j <= nP; ++j) sw.eval_label[j][i] = zero_block;
    }
    return sw;
  }

  // Output decode: all Pi ≠ recipient send λ_w^p to recipient;
  // recipient computes y_w = Λ_w ⊕ λ_w. Returns the n cleartext bits at
  // `recipient`; empty vector at non-recipients.
  std::vector<bool> decode(const SecureWires<nP> &wires, int recipient);

private:
  template <int, class> friend class AGMPCEngine;  // the engine drives ComputeCtx + the per-step methods

  // The per-call scratch context lives in backend/garble/state.h so the passes and
  // step-method bodies can live in their own phase files; this alias exposes it as
  // AGMPCProtocol<nP>::ComputeCtx for the friended AGMPCEngine and the method
  // signatures below.
  using ComputeCtx = emp::ag::ComputeCtx<nP>;

  // The half-gate hash seed is not drawn on a round of its own. It is piggybacked off
  // the per-chunk post-commitment triple coin: draw_and_seed squeezes one
  // domain-separated block from TriplePool::call_coin_ into ctx.halfgate_seed after
  // compute_and_shares. That coin is globally
  // agreed (FS pair at nP==2 / commit-reveal at nP>2), so the evaluator's re-hash matches
  // every garbler; being fresh per chunk, the hash's (start point, gid) -- one stream per
  // sender, garble/halfgate.h -- never repeats across chunks under the fixed long-lived
  // Delta.

  // The checked opening of ashare/open.h over this session's mesh and keys: targets[t]
  // (t in 1..nP) lists the wire indices into `base` to open to party t, in one round;
  // returns the bits for targets[self], and aborts on a share-MAC mismatch.
  // decode(PUBLIC) and process_inputs both open through it.
  std::vector<unsigned char> open_to_targets(const AShareBundle<nP> *base,
                                             const std::vector<std::vector<int>> &targets);

  // Input-label exchange, shared by process_inputs and
  // adopt_authenticated_input: garblers ship label0 ⊕ Λ·Δ to the evaluator.
  void exchange_input_labels_(SecureWires<nP> &sw, int n_total);

  // Prepared execution input seam.  make_prepared_inputs_ mints fresh target
  // masks/labels without assigning an owner or opening a mask.  The online
  // binder then either attaches staged clear bits or solders an existing
  // authenticated value onto those targets, in one flattened phase.
  SecureWires<nP> make_prepared_inputs_(int n);
  void bind_prepared_inputs_(SecureWires<nP> &target,
                             const PreparedInputBinding<nP> &binding);
  void broadcast_input_masks_(SecureWires<nP> &sw,
                              const std::vector<std::vector<int>> &wires_of);

  // Computation input seam, over the same prepared target masks.  Offline,
  // open_computation_input_masks_ opens each Party input's mask to its owner and
  // each Public input's (owner[w] == PUBLIC) to every party, and returns per
  // input wire the mask where it was opened to this party (0 elsewhere).
  // Online, bind_computation_inputs_ takes Lambda for the wires this party knows
  // (its own and the Public ones), broadcasts the owners' masked values and
  // exchanges the input labels.
  std::vector<unsigned char> open_computation_input_masks_(
      const SecureWires<nP> &target, const std::vector<int> &owner);
  void bind_computation_inputs_(SecureWires<nP> &target,
                                const std::vector<int> &owner,
                                const std::vector<unsigned char> &lambda);

  // One method per protocol phase over a shared ComputeCtx; AGMPCEngine<nP>
  // sequences them in protocol order.
  void load_inputs(ComputeCtx &ctx, const SecureWires<nP> *const *inputs,
                   int n_inputs);
  // The pass-running phases take the gate `source` (program / compose / body)
  // and drive their pass over it via ag::run_pass(pass, source).
  template <class Source> void draw_and_seed(ComputeCtx &ctx, Source &source);   // draw+seed+Beaver, one walk
  template <class Source> void garble_and_ship(ComputeCtx &ctx, Source &source); // garble + ship, Pi (i>=2)
  template <class Source> void stream_evaluate(ComputeCtx &ctx, Source &source); // recv + evaluate FUSED (P1, streaming)
  void receive_prepared_garbling(ComputeCtx &ctx, EvalChunk<nP> &rows);
  template <class Source>
  void evaluate_prepared(ComputeCtx &ctx, Source &source, EvalChunk<nP> &&rows);
  // Output check: open_and_masks is its own cheap walk so Lambda_AND is
  // broadcast EARLY (pipelining); the symmetric SPDZ c_gamma MACCheck is one walk in
  // output_check. See garble/passes/mask_witness.h.
  template <class Source> void open_and_masks(ComputeCtx &ctx, Source &source);   // Lambda_AND broadcast
  template <class Source> void output_check(ComputeCtx &ctx, Source &source);     // SPDZ c_gamma MACCheck
  SecureWires<nP> gather_outputs(ComputeCtx &ctx,
                                 const std::vector<int> &output_ids);
  // Auth::WRK only. P1 checks every gate while evaluating, but the garblers still need
  // the outputs' Lambda: with no AND gate they follow from the inputs (linear_masks_,
  // garble/passes/mask_witness.h, no traffic); otherwise P1 hands them over
  // (deliver_output_masks_, input_auth.h).
  template <class Source> void linear_masks_(ComputeCtx &ctx, Source &source);
  void deliver_output_masks_(SecureWires<nP> &out);
  // The general form: garbler i receives the outputs' Lambda at positions_of[i]
  // only, with a hash of its labels on them, and sets out.Lambda there.
  // deliver_output_masks_ lists every position for every garbler; a Computation
  // lists each garbler's own.
  void deliver_output_masks_to_(SecureWires<nP> &out,
                                const std::vector<std::vector<int>> &positions_of);

  // xor_share / zero_share are free templates in backend/ashare/share.h and SlotGateMixin in
  // backend/garble/passes/pass.h (so the passes can reach them without friendship);
  // the half-gate hash layout (HalfGateHash, one stream per sender) is in
  // backend/garble/halfgate.h.

  // The gate passes (DrawBeaverPass / GarblePass / StreamEvaluatePass and the output-check
  // MaskWitnessPass) and the step-method bodies live in the phase files tail-included
  // below: backend/garble/passes/draw_beaver.h (draw+seed+Beaver), backend/garble/passes/garble.h +
  // backend/garble/passes/evaluate.h (garble/evaluate), backend/garble/passes/mask_witness.h (Lambda_AND
  // open + SPDZ c_gamma MACCheck), backend/garble/input_auth.h (inputs, decode, gather_outputs).
  // They are BooleanContexts over ComputeCtx driven by emp::ag::run_pass; AGMPCEngine
  // sequences the step methods declared above in protocol order.
};

}  // namespace emp::ag
// Tail-included step-body phase files (each self-includes this header; the class
// is complete above, so their out-of-line member definitions resolve). Order is
// free — no phase file references another's symbols at parse time.
#include "emp-ag/backend/garble/input_auth.h"        // inputs, decode, gather_outputs
#include "emp-ag/backend/garble/passes/draw_beaver.h" // DrawBeaverPass + draw_and_seed
#include "emp-ag/backend/garble/passes/garble.h"      // garbler (GarblePass + garble_and_ship)
#include "emp-ag/backend/garble/passes/evaluate.h"    // P1 (StreamEvaluatePass + stream_evaluate)
#include "emp-ag/backend/garble/passes/mask_witness.h" // Lambda_AND open + SPDZ c_gamma MACCheck
#endif  // EMP_AG_BACKEND_GARBLE_PROTOCOL_H__
