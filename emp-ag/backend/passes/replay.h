#ifndef EMP_AG_BACKEND_PASSES_REPLAY_H__
#define EMP_AG_BACKEND_PASSES_REPLAY_H__
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
// unit wire maps to the instance's disjoint block (base + w), so every instance's
// And outputs land in distinct slots (multi-pass coexistence). Trust-mode replay of
// a whole WireReuse::Linear program is the I == 0, base == 0 special case (the
// program's own packed wire ids ARE the slots).
//
#include "emp-tool/ir/program.h"   // BooleanProgram, Gate, Op
#include <cstdint>
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

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_PASSES_REPLAY_H__
