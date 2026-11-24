#ifndef EMP_AG_BACKEND_GARBLE_PASSES_REPLAY_H__
#define EMP_AG_BACKEND_GARBLE_PASSES_REPLAY_H__
//
// Canonical wire-id lowering for trust-mode and composition replay.
//
// A unit is LOWERED once per engine call (LoweredUnit) and replayed per instance
// (replay_lowered): the gate stream is pre-split into runs of consecutive same-op
// gates with the operands in flat SoA arrays, so a replay dispatches once per RUN
// instead of once per gate, streams 4-byte operand words instead of 16-byte Gate
// records, and gives each op a dedicated inner loop whose pass state stays in
// registers. Gate ORDER is exactly the unit's (runs are consecutive slices), so the
// emitted pass calls -- and therefore the transcript -- are byte-identical to
// for_each_gate over the unit. The replay depends ONLY on the Pass exposing the
// slot-explicit gate interface
//
//     and_at(out, a, b),  xor_at(out, a, b),  not_at(out, a),  const_at(out, value)
//
// so it is protocol-agnostic, and the id -> slot lowering is single-copy: a unit
// input wire (w < I) aliases the wired composition slot (in_slot[w]); any other
// unit wire maps to the instance's disjoint block (base + w, in uint32_t arithmetic,
// so a block that starts at slot s for the unit's first non-input id has
// base = s - I modulo 2^32), so every instance's And outputs land in distinct slots
// (multi-pass coexistence). Trust-mode replay of a whole WireReuse::Linear program is
// the I == 0, base == 0 special case (the program's own packed wire ids ARE the slots).
//
#include "emp-tool/ir/context/compose.h"   // ComposePlan
#include "emp-tool/ir/program.h"           // BooleanProgram, Gate, Op
#include "emp-tool/runtime/core/utils.h"   // expecting
#include <cstdint>
#include <memory>
#include <unordered_map>
#include <vector>

namespace emp::ag {

struct LoweredUnit {
  struct Run { circuit::Op op; uint32_t n; };
  std::vector<Run> runs;
  std::vector<uint32_t> out, a, b;   // SoA; b = in1 (And/Xor), const bit (Const*), unused (Not)
  void build(const circuit::BooleanProgram &p) {
    runs.clear(); out.clear(); a.clear(); b.clear();
    out.reserve(p.gates.size()); a.reserve(p.gates.size()); b.reserve(p.gates.size());
    for (const circuit::Gate &g : p.gates) {
      if (runs.empty() || runs.back().op != g.op) runs.push_back({g.op, 0});
      ++runs.back().n;
      out.push_back(g.out);
      a.push_back(g.in0);
      b.push_back(g.op == circuit::Op::Const1 ? 1u
                : g.op == circuit::Op::Const0 ? 0u
                                              : g.in1);
    }
  }
};

// Replay ONE instance of a lowered unit over `pass` (see the header comment for the
// id -> slot map). I == 0 (with base == 0) degenerates to the trust-mode identity.
template <class Pass>
inline void replay_lowered(const LoweredUnit &lu, Pass &pass, uint32_t base,
                           uint32_t I, const uint32_t *in_slot) {
  const uint32_t *po = lu.out.data(), *pa = lu.a.data(), *pb = lu.b.data();
  auto map = [&](uint32_t w) { return w < I ? in_slot[w] : base + w; };
  size_t g = 0;
  for (const LoweredUnit::Run &r : lu.runs) {
    const size_t e = g + r.n;
    switch (r.op) {
      case circuit::Op::Xor:
        for (; g < e; ++g) pass.xor_at(map(po[g]), map(pa[g]), map(pb[g]));
        break;
      case circuit::Op::And:
        for (; g < e; ++g) pass.and_at(map(po[g]), map(pa[g]), map(pb[g]));
        break;
      case circuit::Op::Not:
        for (; g < e; ++g) pass.not_at(map(po[g]), map(pa[g]));
        break;
      case circuit::Op::Const0:
      case circuit::Op::Const1:
        for (; g < e; ++g) pass.const_at(map(po[g]), pb[g] != 0);
        break;
    }
  }
}

// A composition laid out for replay: each distinct unit lowered once; a slot for every
// glue gate in emission order; for each unit call a block with a slot per unit wire
// that is not an input (base), the call's inputs being read from the slots that
// produce them. Every call's And outputs land in distinct slots, so a walk replays the
// events in order with the slot-explicit pass interface and no materialized program.
// Each unit must be WireReuse::Linear or dense (its ids are its slots): a
// WireReuse::Full unit recycles ids, and its block would clobber live AND state.
struct ComposedLayout {
  std::shared_ptr<const ComposePlan> plan;
  std::unordered_map<const circuit::BooleanProgram *, LoweredUnit> lowered;
  std::vector<uint32_t> slot;                    // composition wire -> slot
  std::vector<uint32_t> base;                    // per call: its block's start - I (mod 2^32)
  std::vector<std::vector<uint32_t>> in_slots;   // per call: its inputs' slots
  std::vector<uint32_t> out_ids;                 // the plan's outputs' slots
  uint32_t num_wires = 0;
  int64_t num_ands = 0;
};

inline ComposedLayout build_composed_layout(std::shared_ptr<const ComposePlan> plan) {
  expecting(plan != nullptr, "build_composed_layout: null plan");
  ComposedLayout L;
  L.plan = std::move(plan);
  const ComposePlan &P = *L.plan;
  std::unordered_map<const circuit::BooleanProgram *, int64_t> unit_ands;
  for (const ComposeInstance &inst : P.instances) {
    expecting(inst.unit != nullptr, "build_composed_layout: a call of a null unit");
    expecting(inst.unit->wire_reuse != circuit::WireReuse::Full,
              "build_composed_layout: WireReuse::Full composition unit not supported (would "
              "clobber stored AND state); compile composition units Linear");
    LoweredUnit &lu = L.lowered[inst.unit.get()];
    if (lu.out.empty() && !inst.unit->gates.empty()) lu.build(*inst.unit);
    if (unit_ands.count(inst.unit.get()) == 0) {
      int64_t n = 0;
      for (const circuit::Gate &g : inst.unit->gates) n += g.op == circuit::Op::And;
      unit_ands.emplace(inst.unit.get(), n);
    }
  }
  L.slot.assign(P.num_wires, 0);
  for (uint32_t c = 0; c < P.num_inputs; ++c) L.slot[c] = c;
  uint64_t next = P.num_inputs;
  L.base.assign(P.instances.size(), 0);
  L.in_slots.resize(P.instances.size());
  for (const ComposeEvent &ev : P.events) {
    if (ev.instance < 0) {
      L.slot[ev.gate.out] = (uint32_t)next++;
      if (ev.gate.op == circuit::Op::And) ++L.num_ands;
    } else {
      const ComposeInstance &inst = P.instances[(size_t)ev.instance];
      const circuit::BooleanProgram &U = *inst.unit;
      const uint32_t I = U.num_inputs;
      std::vector<uint32_t> &is = L.in_slots[(size_t)ev.instance];
      is.resize(I);
      for (uint32_t j = 0; j < I; ++j) is[j] = L.slot[inst.in_ids[j]];
      // The block holds the unit's wires I .. num_wires-1; its inputs are the caller's.
      const uint32_t base = (uint32_t)(next - I);
      L.base[(size_t)ev.instance] = base;
      next += U.num_wires - I;
      expecting(next <= UINT32_MAX, "build_composed_layout: the composition's slots overflow uint32_t");
      for (size_t k = 0; k < U.outputs.size(); ++k) {
        const uint32_t w = U.outputs[k];
        L.slot[inst.out_ids[k]] = (w < I) ? is[w] : base + w;
      }
      L.num_ands += unit_ands.find(&U)->second;
    }
  }
  L.num_wires = (uint32_t)next;
  L.out_ids.resize(P.outputs.size());
  for (size_t i = 0; i < P.outputs.size(); ++i) L.out_ids[i] = L.slot[P.outputs[i]];
  return L;
}

// One walk of a laid-out composition over `pass`, in emission order.
template <class Pass>
inline void replay_composed(const ComposedLayout &L, Pass &pass) {
  const ComposePlan &P = *L.plan;
  const uint32_t *slot = L.slot.data();
  for (const ComposeEvent &ev : P.events) {
    if (ev.instance < 0) {
      const circuit::Gate &g = ev.gate;
      switch (g.op) {
        case circuit::Op::And:    pass.and_at(slot[g.out], slot[g.in0], slot[g.in1]); break;
        case circuit::Op::Xor:    pass.xor_at(slot[g.out], slot[g.in0], slot[g.in1]); break;
        case circuit::Op::Not:    pass.not_at(slot[g.out], slot[g.in0]); break;
        case circuit::Op::Const0: pass.const_at(slot[g.out], false); break;
        case circuit::Op::Const1: pass.const_at(slot[g.out], true); break;
      }
    } else {
      const ComposeInstance &inst = P.instances[(size_t)ev.instance];
      replay_lowered(L.lowered.find(inst.unit.get())->second, pass, L.base[(size_t)ev.instance],
                     inst.unit->num_inputs, L.in_slots[(size_t)ev.instance].data());
    }
  }
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_GARBLE_PASSES_REPLAY_H__
