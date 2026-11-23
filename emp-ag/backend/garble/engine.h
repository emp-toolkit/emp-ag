#ifndef EMP_AG_BACKEND_GARBLE_ENGINE_H__
#define EMP_AG_BACKEND_GARBLE_ENGINE_H__
//
// AGMPCEngine<nP> — the authenticated-garbling ENGINE. It drives the AGMPCProtocol<nP>
// passes over a single gate-stream SOURCE: the one place the pass sequence + inter-pass
// crypto order lives. Three SOURCE kinds feed it:
//   * a stored BooleanProgram (run_program), replayed via emp::execute_program;
//   * a ComposePlan (run_composed), each instance's Linear unit replayed on the fly;
//   * a pure circuit body replayed live (run_source + ag::body_replay), no materialized IR.
// Every pass is the SAME definition over the SAME gate stream, so the transcript is
// identical across passes AND across the three source kinds.
//
// finish_ runs the SAME walks at every nP (draw+seed -> garble/eval, then under Auth::KRRW
// open_and_masks -> output_check); there is no nP branch in the engine. The nP==2 specializations live
// INSIDE the passes/protocol as `if constexpr (nP == 2)` fast paths: the one-garbler garble
// path, no garbler-row aggregation ring (P1 receives garbler 2 directly), the streamlined
// two-party leaky-AND, and the c_gamma zero-check via symmetric F_eq instead of EchoBC.
//
// AGMPCEngine holds an AGMPCProtocol<nP>* (the crypto core) and works on SecureWires<nP>
// bundles; the typed-value <-> bundle gather/scatter lives in AGMPCSession, while its
// ctx_t (emp-tool's ChunkRecorderCtx) owns the wire-id bookkeeping. The engine reaches
// the protocol's private per-step methods + ComputeCtx via friendship (protocol.h).
//
#include "emp-tool/ir/context/context.h"          // execute_program, ProgramWorkspace
#include "emp-tool/ir/context/compose.h"          // ComposePlan / ComposeInstance / ComposeEvent
#include "emp-tool/ir/program.h"                    // BooleanProgram, Gate, Op, WireReuse
#include "emp-tool/ir/visit.h"                      // for_each_gate
#include "emp-tool/ir/validate.h"                   // circuit::validate_program
#include "emp-ag/backend/garble/protocol.h"                 // AGMPCProtocol<nP> (+ its ComputeCtx alias) + SecureWires<nP>
#include "emp-ag/backend/garble/passes/liveness.h"           // AGMPCLivenessPass (dense-path liveness)
#include "emp-ag/backend/garble/passes/pass.h"                 // emp::ag::run_pass
#include "emp-ag/backend/garble/passes/replay.h"           // emp::ag::LoweredUnit / replay_lowered
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <span>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace emp::ag {

// AND-gate count over a canonical program. int64_t: gate counts are not capped by the
// uint32_t wire-id space (Linear reuse recycles ids), so an int counter could wrap.
inline int64_t agmpc_count_ands(const circuit::BooleanProgram &p) {
  int64_t n = 0;
  for (const auto &g : p.gates)
    if (g.op == circuit::Op::And) ++n;
  return n;
}

// ===========================================================================
// AGMPCEngine<nP> — runs a BooleanProgram / ComposePlan / live body source through
// the authenticated-garbling passes over an AGMPCProtocol<nP>.
// ===========================================================================
template <int nP, class Cfg>
class AGMPCEngine {
 public:
  using ComputeCtx = typename AGMPCProtocol<nP, Cfg>::ComputeCtx;
  using Wires      = SecureWires<nP>;
  using Material   = PreparedMaterial<nP>;
  using Binding    = PreparedInputBinding<nP>;

  struct PreparedRunResult {
    Wires bound_inputs;
    Wires outputs;
  };

  AGMPCProtocol<nP, Cfg> *mpc = nullptr;
  uint64_t total_ands = 0;   // garbled ANDs across every run (post-DCE), all strategies

  explicit AGMPCEngine(AGMPCProtocol<nP, Cfg> *m) : mpc(m) {}

  // Owner/value-independent offline preparation for one immutable typed circuit.
  // The returned material is intentionally backend-only; AGMPCSession wraps it in
  // the typed move-only public handle that enforces same-session, one-use access.
  std::unique_ptr<Material> prepare_program(
      const std::shared_ptr<const circuit::BooleanProgram> &prog) {
    expecting(prog != nullptr, "prepare_program: null compiled program");
    expecting(prog->wire_reuse != circuit::WireReuse::Full,
              "prepare_program: WireReuse::Full is not supported");
    expecting(prog->num_inputs <= (uint32_t)INT_MAX,
              "prepare_program: circuit input width overflows int");

    auto material = std::make_unique<Material>();
    material->program = prog;
    material->linear = prog->wire_reuse == circuit::WireReuse::Linear;
    ComputeCtx &st = material->ctx;
    st.num_in = (int)prog->num_inputs;

    if (material->linear) {
      PreparedUnit &cached = prepare_once_(prog);
      expecting(prog->num_wires <= (uint32_t)INT_MAX &&
                    cached.num_ands <= (int64_t)INT_MAX,
                "prepare_program: circuit wire or AND count overflows int");
      material->lowered = cached.lowered;
      material->output_ids.assign(prog->outputs.begin(), prog->outputs.end());
      st.num_wires = (int)prog->num_wires;
      st.num_ands = (int)cached.num_ands;
      prepare_trust_layout_(st);
    } else {
      validate_raw_(*prog);
      const uint32_t num_inputs = prog->num_inputs;
      auto source = [&prog, num_inputs](auto &pass) -> std::vector<uint32_t> {
        using Pass = std::decay_t<decltype(pass)>;
        using W = typename Pass::Wire;
        std::vector<W> in((size_t)num_inputs);
        for (uint32_t i = 0; i < num_inputs; ++i) in[i] = (W)i;
        ProgramWorkspace<W> ws;
        const std::vector<W> &ow = emp::execute_program(
            pass, *prog, std::span<const W>(in.data(), in.size()), ws);
        return std::vector<uint32_t>(ow.begin(), ow.end());
      };
      material->output_ids = run_liveness_(st, source);
    }

    prepare_material_(*material);
    return material;
  }

  // The same for a composed program: its layout is built once, here, and every walk
  // replays it, so each distinct unit is lowered once however often it is called.
  std::unique_ptr<Material> prepare_composed(std::shared_ptr<const ComposePlan> plan) {
    expecting(plan != nullptr, "prepare_composed: null composed program");
    auto material = std::make_unique<Material>();
    auto layout = std::make_shared<const ComposedLayout>(build_composed_layout(std::move(plan)));
    expecting(layout->plan->num_inputs <= (uint32_t)INT_MAX &&
                  layout->num_wires <= (uint32_t)INT_MAX && layout->num_ands <= (int64_t)INT_MAX,
              "prepare_composed: the composition's inputs, slots or AND gates overflow int");
    ComputeCtx &st = material->ctx;
    st.num_in = (int)layout->plan->num_inputs;
    st.num_wires = (int)layout->num_wires;
    st.num_ands = (int)layout->num_ands;
    material->output_ids = layout->out_ids;
    material->composed = std::move(layout);
    material->linear = true;   // the layout's ids are the slots
    prepare_trust_layout_(st);
    prepare_material_(*material);
    return material;
  }

 private:
  // prepare_program / prepare_composed after the layout: the offline masks of the
  // inputs, every preprocessing walk, and the garbling (P1 stores the rows).
  void prepare_material_(Material &m) {
    ComputeCtx &st = m.ctx;
    Material *material = &m;
    material->target_inputs = mpc->make_prepared_inputs_(st.num_in);
    load_prepared_inputs_(st, material->target_inputs);
    with_prepared_source_(*material, [&](auto &source) {
      produce_(st, source);
      [[maybe_unused]] auto *io = mpc->io;
      [[maybe_unused]] int party = mpc->party;
      AG_PHASE_BEGIN();
      if (mpc->party == 1)
        mpc->receive_prepared_garbling(st, material->rows);
      else
        mpc->garble_and_ship(st, source);
      AG_PHASE("prepared-garble/store");
    });
    capture_prepared_outputs_(*material);
    // Evaluation and the garbler's mask-witness pass consume the compact
    // ev_*/cgamma records, never the authenticated WIRE fabric.  Retain only
    // input pads and authenticated outputs across the phase boundary.
    AShareBundleVec<nP>().swap(st.wire_slot);
    AShareBundleVec<nP>().swap(st.sigma);
    if (mpc->party != 1) BlockVec().swap(st.label_slot);

    // No correlation check, base OT, or triple traffic is allowed to leak into
    // the later online phase.  This is a no-op if the backend is already clean.
    mpc->abit->maybe_flush_cot_check();
    mpc->abit->settle_check2();
    total_ands += (uint64_t)st.num_ands;
  }

 public:
  PreparedRunResult run_prepared(Material &material, const Binding &binding) {
    expecting(material.live(), "run_prepared: prepared material was already consumed");
    expecting(binding.size() == (size_t)material.ctx.num_in,
              "run_prepared: argument width differs from prepared circuit input width");

    ComputeCtx &st = material.ctx;
    [[maybe_unused]] auto *io = mpc->io;
    [[maybe_unused]] int party = mpc->party;
    AG_PHASE_BEGIN();
    mpc->bind_prepared_inputs_(material.target_inputs, binding);
    AG_PHASE("prepared-bind");
    load_bound_prepared_inputs_(st, material.target_inputs);
    PreparedRunResult result;
    result.bound_inputs = std::move(material.target_inputs);
    result.outputs = evaluate_stored_(material, /*linear_masks=*/true);
    if constexpr (Cfg::auth == Auth::WRK) {
      if (st.num_ands > 0) mpc->deliver_output_masks_(result.outputs);
      AG_PHASE("deliver_output_masks");
    }
    material.consume();
    return result;
  }

  // ---- Computation (circuit mode): the same prepared material, with declared
  // owners and recipients.  `owner[w]` is the party that supplies input wire w,
  // or PUBLIC.  Offline, after prepare_program: open each Party input's mask to
  // its owner and each Public input's to every party.  Returns per input wire
  // the mask where it was opened to this party.
  std::vector<unsigned char> open_input_masks(const Material &material,
                                              const std::vector<int> &owner) {
    expecting(material.live(), "open_input_masks: prepared material was already consumed");
    expecting(owner.size() == (size_t)material.ctx.num_in,
              "open_input_masks: owner count differs from the circuit input width");
    return mpc->open_computation_input_masks_(material.target_inputs, owner);
  }

  // Online.  `lambda[w]` is Lambda for the input wires this party knows (its own
  // and the Public ones); `open_to[t]` lists the output positions party t
  // receives.  The inputs bind, P1 evaluates the stored rows, and every output
  // position opens to its recipients in one MAC-checked round: under KRRW after
  // the output check, under WRK in the first flight after the inputs are fixed,
  // so P1 decodes as soon as it has evaluated.  Under WRK, P1 then hands each
  // garbler the masked values of the positions it receives.  Returns per output
  // position this party's bit where it is a recipient, 0 elsewhere.
  // `source` and `from_source` (optional): input wires bound to authenticated sources
  // instead of their owners' broadcasts (AGMPCProtocol::bind_computation_inputs_).
  std::vector<unsigned char> run_computation(
      Material &material, const std::vector<int> &owner,
      const std::vector<unsigned char> &lambda,
      const std::vector<std::vector<int>> &open_to,
      const AShareBundle<nP> *source = nullptr,
      const std::vector<unsigned char> *from_source = nullptr) {
    expecting(material.live(), "run_computation: prepared material was already consumed");
    expecting(owner.size() == (size_t)material.ctx.num_in &&
                  lambda.size() == owner.size(),
              "run_computation: input width differs from the prepared circuit");
    expecting(open_to.size() == (size_t)nP + 1,
              "run_computation: open_to must have one list per party");
    const int party = mpc->party;
    const size_t n_out = material.output_ids.size();
    for (int t = 1; t <= nP; ++t)
      for (int pos : open_to[(size_t)t])
        expecting(pos >= 0 && (size_t)pos < n_out,
                  "run_computation: output position out of range");

    ComputeCtx &st = material.ctx;
    [[maybe_unused]] auto *io = mpc->io;
    AG_PHASE_BEGIN();
    mpc->bind_computation_inputs_(material.target_inputs, owner, lambda, source, from_source);
    AG_PHASE("computation-bind");
    load_bound_prepared_inputs_(st, material.target_inputs);

    std::vector<unsigned char> mask;   // this party's opened output masks, in open_to[party] order
    if constexpr (Cfg::auth == Auth::WRK)
      mask = open_output_masks_(material.output_static.wire_bundle, open_to);

    Wires out = evaluate_stored_(material, /*linear_masks=*/false);
    if constexpr (Cfg::auth == Auth::KRRW)
      mask = open_output_masks_(out.wire_bundle, open_to);
    if constexpr (Cfg::auth == Auth::WRK) {
      mpc->deliver_output_masks_to_(out, open_to);
      AG_PHASE("deliver_output_masks");
    }

    std::vector<unsigned char> bits(n_out, 0);
    const std::vector<int> &mine = open_to[(size_t)party];
    for (size_t j = 0; j < mine.size(); ++j)
      bits[(size_t)mine[j]] = (unsigned char)((mask[j] ^ out.Lambda[(size_t)mine[j]]) & 1);
    material.consume();
    return bits;
  }

  // ---- DENSE core: liveness -> input load -> slot/mask seed -> shared tail ----
  template <class Source>
  Wires run_source(const Wires &in_wires, Source &source) {
    expecting(in_wires.size() <= (size_t)INT_MAX,
              "run_source: input width overflows int -- split into chunks");
    ComputeCtx st;
    st.num_in = (int)in_wires.size();
    std::vector<uint32_t> out_ids = run_liveness_(st, source);
    load_inputs_(st, in_wires, /*trust=*/false);
    // Half-gate hash seed is set inside draw_and_seed, from the coin of the AND gates'
    // protocol.
    return finish_(st, source, out_ids);
  }

  // ---- ProgramSource: dispatch on wire-reuse level (Linear=trust, Full=reject,
  //      None=dense over execute_program). ----
  Wires run_program(const circuit::BooleanProgram &prog, const Wires &inputs) {
    if (prog.wire_reuse == circuit::WireReuse::Linear)
      return run_program_trust_(prog, inputs);
    expecting(prog.wire_reuse != circuit::WireReuse::Full,
              "agmpc: WireReuse::Full not supported (would clobber stored AND state); "
              "pack circuits Linear for the trust path");
    validate_raw_(prog);
    const uint32_t num_inputs = (uint32_t)inputs.size();
    expecting(num_inputs == prog.num_inputs,
              "run_program: input bundle width != program num_inputs");

    auto source = [&prog, num_inputs](auto &pass) -> std::vector<uint32_t> {
      using Pass = std::decay_t<decltype(pass)>;
      using W = typename Pass::Wire;
      std::vector<W> in((size_t)num_inputs);
      for (uint32_t i = 0; i < num_inputs; ++i) in[i] = (W)i;
      ProgramWorkspace<W> ws;
      const std::vector<W> &ow = emp::execute_program(
          pass, prog, std::span<const W>(in.data(), in.size()), ws);
      return std::vector<uint32_t>(ow.begin(), ow.end());
    };
    return run_source(inputs, source);
  }

  // Owner-bearing compiled circuit path. The shared pointer names an immutable,
  // constructor-validated frontend artifact, so its lowering and AND count can
  // be cached across calls without hashing or rescanning the gate stream.
  Wires run_program(const std::shared_ptr<const circuit::BooleanProgram> &prog,
                    const Wires &inputs) {
    expecting(prog != nullptr, "run_program: null compiled program");
    expecting(prog.use_count() > 0,
              "run_program: compiled program must have shared ownership");
    if (prog->wire_reuse == circuit::WireReuse::Linear)
      return run_program_trust_owned_(prog, inputs);
    return run_program(*prog, inputs);
  }

  // ---- ComposePlan: each instance's Linear unit replayed on the fly into a disjoint
  //      slot block via the trust path; glue inline. ----
  Wires run_composed(const ComposePlan &plan, const Wires &inputs) {
    expecting((uint32_t)inputs.size() == plan.num_inputs,
              "run_composed: input bundle width != plan num_inputs");
    // Validate + Full-reject each DISTINCT unit once per plan, not per instance. A
    // ComposePlan references units by pointer, so an N-fold chain is ONE unit x N
    // instances, and validate_program is a pure function of the unit -- re-checking
    // it per instance is pure overhead. Units built through the typed frontend are
    // already validated at construction (frontend::Circuit's ctor, per emp-tool's
    // validate.h contract: never inside the execution hot loop), but a BooleanProgram
    // carries no provenance token, so the backend keeps ONE check per distinct unit
    // per plan as its trust boundary -- the pass walks index slots unchecked, so
    // malformed IR would be UB. Dedup by unit pointer, exactly as the and_cache
    // below does for the AND count.
    std::unordered_set<const circuit::BooleanProgram *> checked_units;
    for (const ComposeInstance &inst : plan.instances) {
      if (!checked_units.insert(inst.unit.get()).second) continue;
      // A unit is replayed into a disjoint slot block on the assumption that its wire ids
      // ARE slots (Linear). A WireReuse::Full unit recycles ids, so the lowered-replay
      // slot map would clobber live AND state -- reject it, exactly as run_program does.
      expecting(inst.unit->wire_reuse != circuit::WireReuse::Full,
                "run_composed: WireReuse::Full composition unit not supported (would clobber "
                "stored AND state); compile composition units Linear");
      validate_(*inst.unit);
    }

    // The layout lives only in this call, so it borrows the plan.
    const ComposedLayout layout = build_composed_layout(
        std::shared_ptr<const ComposePlan>(std::shared_ptr<const ComposePlan>(), &plan));
    auto source = [&layout](auto &pass) -> std::vector<uint32_t> {
      replay_composed(layout, pass);
      return layout.out_ids;
    };
    return run_trust_(inputs, source, layout.num_wires, layout.num_ands, layout.out_ids);
  }

 private:
  struct PreparedUnit {
    std::weak_ptr<const circuit::BooleanProgram> owner;
    LoweredUnit lowered;
    int64_t num_ands = 0;
  };
  static constexpr size_t kPreparedUnitCacheCap = 8;
  std::unordered_map<const circuit::BooleanProgram *, PreparedUnit> unit_cache_;

  static bool same_owner_(const std::weak_ptr<const circuit::BooleanProgram> &cached,
                          const std::shared_ptr<const circuit::BooleanProgram> &owner) {
    return !cached.owner_before(owner) && !owner.owner_before(cached);
  }

  PreparedUnit &prepare_once_(
      const std::shared_ptr<const circuit::BooleanProgram> &owner) {
    auto found = unit_cache_.find(owner.get());
    if (found != unit_cache_.end() && same_owner_(found->second.owner, owner))
      return found->second;

    // A small bounded cache keeps both hits and misses O(1) and prevents a
    // stream of temporary compiled circuits from retaining every lowering.
    if (found == unit_cache_.end() &&
        unit_cache_.size() >= kPreparedUnitCacheCap)
      unit_cache_.erase(unit_cache_.begin());
    PreparedUnit prepared;
    prepared.owner = owner;
    if (!owner->gates.empty()) prepared.lowered.build(*owner);
    prepared.num_ands = agmpc_count_ands(*owner);
    return unit_cache_.insert_or_assign(owner.get(), std::move(prepared))
        .first->second;
  }

  // Rebuild a short-lived pass source around material-owned state.  Linear
  // artifacts replay their owned lowering; ordinary compiled programs use the
  // same execute_program source as the dense path.
  template <class F>
  void with_prepared_source_(Material &material, F &&f) {
    if (material.composed) {
      auto source = [&material](auto &pass) -> std::vector<uint32_t> {
        replay_composed(*material.composed, pass);
        return material.output_ids;
      };
      f(source);
      return;
    }
    const circuit::BooleanProgram &prog = *material.program;
    if (material.linear) {
      auto source = [&material](auto &pass) -> std::vector<uint32_t> {
        ag::replay_lowered(material.lowered, pass, /*base=*/0, /*I=*/0,
                           nullptr);
        return material.output_ids;
      };
      f(source);
    } else {
      const uint32_t num_inputs = prog.num_inputs;
      auto source = [&prog, num_inputs](auto &pass) -> std::vector<uint32_t> {
        using Pass = std::decay_t<decltype(pass)>;
        using W = typename Pass::Wire;
        std::vector<W> in((size_t)num_inputs);
        for (uint32_t i = 0; i < num_inputs; ++i) in[i] = (W)i;
        ProgramWorkspace<W> ws;
        const std::vector<W> &ow = emp::execute_program(
            pass, prog, std::span<const W>(in.data(), in.size()), ws);
        return std::vector<uint32_t>(ow.begin(), ow.end());
      };
      f(source);
    }
  }

  void prepare_trust_layout_(ComputeCtx &st) {
    st.dedup_consts = false;
    st.num_slots = st.num_wires;
    st.phys_identity = true;
    st.phys.clear();
    size_slots_(st);
  }

  void load_prepared_inputs_(ComputeCtx &st, const Wires &inputs) {
    const Wires *ptr = &inputs;
    mpc->load_inputs(st, &ptr, 1);
  }

  // The offline walks already populated the share/garbler-label fabric.  Online
  // binding updates only the public input masks and, at P1, the selected target
  // labels; re-running load_inputs would overwrite offline-produced slots.
  void load_bound_prepared_inputs_(ComputeCtx &st, const Wires &inputs) {
    expecting(inputs.size() == (size_t)st.num_in,
              "run_prepared: bound input width mismatch");
    if (st.num_in == 0) return;
    memcpy(st.mask_input.data(), inputs.Lambda.data(), (size_t)st.num_in);
    if (mpc->party == 1)
      for (int j = 2; j <= nP; ++j)
        memcpy(st.eval_slot[j].data(), inputs.eval_label[j].data(),
               (size_t)st.num_in * sizeof(block));
  }

  void capture_prepared_outputs_(Material &material) {
    ComputeCtx &st = material.ctx;
    const size_t n = material.output_ids.size();
    Wires &out = material.output_static;
    out.Lambda.assign(n, 0);
    out.wire_bundle.resize(n);
    if (mpc->party != 1) out.label0.resize(n);
    for (size_t i = 0; i < n; ++i) {
      const int w = (int)material.output_ids[i];
      out.wire_bundle[i] = st.WIRE(w);
      if (mpc->party != 1) out.label0[i] = st.LABEL(w);
    }
  }

  Wires gather_prepared_outputs_(Material &material) {
    ComputeCtx &st = material.ctx;
    Wires out = std::move(material.output_static);
    const size_t n = material.output_ids.size();
    for (size_t i = 0; i < n; ++i)
      out.Lambda[i] = st.MASK((int)material.output_ids[i]);
    if (mpc->party == 1) {
      for (int j = 2; j <= nP; ++j) {
        out.eval_label[j].resize(n);
        for (size_t i = 0; i < n; ++i)
          out.eval_label[j][i] =
              st.EVAL(j, (int)material.output_ids[i]);
      }
    }
    return out;
  }

  // The evaluation half shared by the prepared paths: P1 evaluates the stored
  // rows, the KRRW output check follows, and the outputs are gathered (P1: masked
  // values and labels; garblers: labels, plus the masked values the KRRW check
  // gave them). `linear_masks`: under WRK with no AND gate, the garblers walk the
  // outputs' masked values forward, as the direct paths do; a Computation never
  // does, and hands them over instead.
  Wires evaluate_stored_(Material &material, bool linear_masks) {
    ComputeCtx &st = material.ctx;
    [[maybe_unused]] auto *io = mpc->io;
    [[maybe_unused]] int party = mpc->party;
    AG_PHASE_BEGIN();
    Wires out;
    with_prepared_source_(material, [&](auto &source) {
      if (mpc->party == 1)
        mpc->evaluate_prepared(st, source, std::move(material.rows));
      AG_PHASE("prepared-eval");
      if constexpr (Cfg::auth == Auth::KRRW) {
        mpc->open_and_masks(st, source);
        AG_PHASE("open_and_masks");
        mpc->output_check(st, source);
        AG_PHASE("output_check[SPDZ]");
      }
      if constexpr (Cfg::auth == Auth::WRK)   // P1 checked every gate during evaluation
        if (linear_masks && st.num_ands == 0) mpc->linear_masks_(st, source);
      out = gather_prepared_outputs_(material);
      AG_PHASE("gather_outputs");
    });
    return out;
  }

  // One MAC-checked round that opens output masks to their recipients
  // (open_to[t] = the output positions party t receives).  Every share a party
  // receives is checked against its own keys before use, whoever sent it.
  std::vector<unsigned char> open_output_masks_(
      const AShareBundleVec<nP> &bundles,
      const std::vector<std::vector<int>> &open_to) {
    mpc->abit->maybe_flush_cot_check();
    mpc->abit->settle_check2();
#ifdef EMP_AG_TEST_FLIP_OUTPUT_SHARE
    // TEST-ONLY (never in production): the last party flips its share of the
    // first output position, keeping its MACs. Every recipient must abort.
    if (mpc->party == nP && !bundles.empty()) {
      AShareBundleVec<nP> bad = bundles;
      bad[0].mac(0) = bad[0].mac(0) ^ makeBlock(0, 1);
      return mpc->open_to_targets(bad.data(), open_to);
    }
#endif
    return mpc->open_to_targets(bundles.data(), open_to);
  }

  // Raw BooleanProgram references have no immutable lifetime identity. They are
  // the trusted escape hatch: validated fully in debug builds (or with
  // EMP_AG_DEBUG_CHECKS); release builds skip the scan, so exercise a raw
  // program in a debug build first.
  static void validate_raw_(const circuit::BooleanProgram &p) {
#if !defined(NDEBUG) || defined(EMP_AG_DEBUG_CHECKS)
    validate_(p);
#else
    (void)p;
#endif
  }
  static void validate_(const circuit::BooleanProgram &p) {
    try { emp::circuit::validate_program(p); }
    catch (const std::exception &e) { expecting(false, e.what()); }
  }

  // Raw WireReuse::Linear program: lower per call because a mutable reference has
  // no sound cross-call cache identity.
  Wires run_program_trust_(const circuit::BooleanProgram &prog, const Wires &inputs) {
    validate_raw_(prog);
    expecting((uint32_t)inputs.size() == prog.num_inputs,
              "run_program: input bundle width != program num_inputs");
    std::vector<uint32_t> out_ids(prog.outputs.begin(), prog.outputs.end());
    LoweredUnit lu;
    if (!prog.gates.empty()) lu.build(prog);
    auto source = [&prog, &lu](auto &pass) -> std::vector<uint32_t> {
      ag::replay_lowered(lu, pass, /*base=*/0, /*I=*/0, nullptr);
      return std::vector<uint32_t>(prog.outputs.begin(), prog.outputs.end());
    };
    return run_trust_(inputs, source, prog.num_wires, agmpc_count_ands(prog), out_ids);
  }

  // Immutable compiled WireReuse::Linear program: prepare once per owning
  // Circuit artifact, then replay with O(1) cache-hit overhead.
  Wires run_program_trust_owned_(
      const std::shared_ptr<const circuit::BooleanProgram> &owner,
      const Wires &inputs) {
    const circuit::BooleanProgram &prog = *owner;
    expecting((uint32_t)inputs.size() == prog.num_inputs,
              "run_program: input bundle width != program num_inputs");
    PreparedUnit &prepared = prepare_once_(owner);
    std::vector<uint32_t> out_ids(prog.outputs.begin(), prog.outputs.end());
    auto source = [&prog, &prepared](auto &pass) -> std::vector<uint32_t> {
      ag::replay_lowered(prepared.lowered, pass, /*base=*/0, /*I=*/0, nullptr);
      return std::vector<uint32_t>(prog.outputs.begin(), prog.outputs.end());
    };
    return run_trust_(inputs, source, prog.num_wires, prepared.num_ands, out_ids);
  }

  // TRUST core: skip liveness, take sizes from the packed program (ids ARE slots).
  // The ONE choke point where 64-bit AND/wire totals narrow into ComputeCtx's int
  // fields: reject what does not fit instead of silently wrapping (a compose plan or
  // program can exceed int even though each unit's wire-id space is uint32_t).
  template <class Source>
  Wires run_trust_(const Wires &in_wires, Source &source, uint32_t num_wires,
                   int64_t num_ands, const std::vector<uint32_t> &out_ids) {
    expecting(in_wires.size() <= (size_t)INT_MAX &&
                  num_wires <= (uint32_t)INT_MAX &&
                  num_ands <= (int64_t)INT_MAX,
              "run: circuit too large (input, wire, or AND count overflows int) -- split into chunks");
    ComputeCtx st;
    st.num_in = (int)in_wires.size();
    st.num_wires = (int)num_wires;
    st.num_ands = (int)num_ands;
    load_inputs_(st, in_wires, /*trust=*/true);
    // Half-gate hash seed is set inside draw_and_seed, from the coin of the AND gates'
    // protocol.
    return finish_(st, source, out_ids);
  }

  // Dense liveness: the two-replay AGMPCLivenessPass derives persist/last_use + out_ids
  // (phase 1), then assigns the slot-reuse freelist -> phys (phase 2). The crypto passes
  // re-execute the same source and must dedup constants into the SAME wid space, so
  // dedup_consts is set (idempotent on an already-deduped program, required for a live
  // body). Sizes the per-run slot arrays.
  std::vector<uint32_t> run_liveness_(ComputeCtx &st, auto &source) {
    AGMPCLivenessPass lp(st.num_in);
    std::vector<uint32_t> out_ids = source(lp);   // phase 1
    expecting(lp.last_use.size() <= (size_t)INT_MAX,
              "run_source: live body wire count overflows int -- split into chunks");
    const uint32_t phase1_wid = lp.wid;
    const int phase1_gi = lp.gi;
    lp.start_phase2(out_ids);
    std::vector<uint32_t> out_ids2 = source(lp);  // phase 2
    expecting(lp.wid == phase1_wid && lp.gi == phase1_gi,
              "run_source: live body changed gate/wire count between liveness replays");
    expecting(out_ids2 == out_ids,
              "run_source: live body changed outputs between liveness replays");
    st.dedup_consts = true;
    st.num_ands = lp.num_ands;
    st.num_wires = (int)lp.last_use.size();
    st.num_slots = lp.next_slot;
    st.phys = std::move(lp.phys);
    size_slots_(st);
    return out_ids;
  }

  // Trust sets identity phys + sizes; both seed input slots [0, num_in) via the protocol.
  void load_inputs_(ComputeCtx &st, const Wires &in, bool trust) {
    if (trust) {
      // run_trust_ skipped liveness: ids ARE slots (the lowered replay drives the
      // passes by slot id), so the id -> slot map is the identity. phys_identity makes the
      // ComputeCtx accessors index slots directly — no phys[] table is materialized and,
      // more importantly, no phys[] load sits in the address chain of every slot access
      // on this (the production) path. Only the dense/liveness path carries a real table.
      st.dedup_consts = false;
      st.num_slots = st.num_wires;
      st.phys_identity = true;
      st.phys.clear();
      size_slots_(st);
    }
    const Wires *ptr = &in;
    mpc->load_inputs(st, &ptr, 1);   // memcpy-seed slots [0, num_in)
  }

  // Size the per-run slot arrays to num_slots. Garbler Pi (i>=2) keeps label_slot; P1
  // keeps eval_slot[j] per garbler.
  void size_slots_(ComputeCtx &st) {
    st.mask_input.assign((size_t)st.num_slots, 0);
    st.wire_slot.resize((size_t)st.num_slots);
    if (mpc->party != 1) {
      st.label_slot.resize((size_t)st.num_slots);
    } else {
      for (int j = 2; j <= nP; ++j) st.eval_slot[j].resize((size_t)st.num_slots);
    }
  }

  // The shared tail is split at the preprocessing/online seam into two
  // independently-callable halves, produce_ (preprocessing) and consume_ (online);
  // finish_ calls them back-to-back.
  //
  // produce_ = draw_and_seed: the COT / leaky-AND / bucketing preprocessing that
  // writes ctx.sigma. Data-independent of any prior chunk's consume_.
  template <class Source>
  void produce_(ComputeCtx &st, Source &source) {
    [[maybe_unused]] auto *io = mpc->io;      // AG_PHASE macro reads io->count() + party
    [[maybe_unused]] int party = mpc->party;
    AG_PHASE_BEGIN();
    mpc->draw_and_seed(st, source);   // draw+seed+free-XOR+Beaver, one walk
    AG_PHASE("draw+seed");
  }

  // consume_ = the online phase (garble/evaluate, open Lambda_AND, the symmetric SPDZ
  // c_gamma MACCheck, gather). Consumes the triples produce_ wrote.
  template <class Source>
  Wires consume_(ComputeCtx &st, Source &source, const std::vector<uint32_t> &out_ids) {
    [[maybe_unused]] auto *io = mpc->io;      // AG_PHASE macro reads io->count() + party
    [[maybe_unused]] int party = mpc->party;
    AG_PHASE_BEGIN();
    if (mpc->party == 1) mpc->stream_evaluate(st, source);    // evaluator
    else                 mpc->garble_and_ship(st, source);    // garbler
    AG_PHASE("garble/eval");
    if constexpr (Cfg::auth == Auth::KRRW) {
      mpc->open_and_masks(st, source); // open + EARLY-broadcast Lambda_AND (pipelining)
      AG_PHASE("open_and_masks");
      mpc->output_check(st, source);   // symmetric SPDZ c_gamma MACCheck (garble/passes/mask_witness.h)
      AG_PHASE("output_check[SPDZ]");
    }
    std::vector<int> oi(out_ids.begin(), out_ids.end());
    if constexpr (Cfg::auth == Auth::WRK)   // P1 checked every gate during evaluation
      if (st.num_ands == 0) mpc->linear_masks_(st, source);
    Wires out = mpc->gather_outputs(st, oi);
    AG_PHASE("gather_outputs");
    if constexpr (Cfg::auth == Auth::WRK) {
      if (st.num_ands > 0) mpc->deliver_output_masks_(out);
      AG_PHASE("deliver_output_masks");
    }
    total_ands += (uint64_t)st.num_ands;
    return out;
  }

  template <class Source>
  Wires finish_(ComputeCtx &st, Source &source, const std::vector<uint32_t> &out_ids) {
    swap_normal_check_scratch_(st);
    produce_(st, source);
    Wires out = consume_(st, source, out_ids);
    swap_normal_check_scratch_(st);
    return out;
  }

  void swap_normal_check_scratch_(ComputeCtx &st) noexcept {
    st.Lambda_AND.swap(mpc->normal_Lambda_AND_scratch_);
    st.cgamma_mu.swap(mpc->normal_cgamma_mu_scratch_);
    st.cgamma_s0.swap(mpc->normal_cgamma_s0_scratch_);
    st.cgamma_s1.swap(mpc->normal_cgamma_s1_scratch_);
    st.cgamma_s2.swap(mpc->normal_cgamma_s2_scratch_);
  }
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_GARBLE_ENGINE_H__
