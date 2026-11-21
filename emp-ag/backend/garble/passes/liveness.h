#ifndef EMP_AG_BACKEND_GARBLE_PASSES_LIVENESS_H__
#define EMP_AG_BACKEND_GARBLE_PASSES_LIVENESS_H__

#include "emp-tool/ir/program.h"
#include <cstdint>
#include <utility>
#include <vector>

namespace emp::ag {

// Live liveness/layout: derive the slot-reuse layout from a re-executed circuit body,
// with NO materialized BooleanProgram. It is a BooleanContext replayed TWICE over the
// body source: phase 1 records persist / last_use / num_ands / the wire count; phase 2
// applies the persist+freelist slot recycling (inputs / AND-outputs / declared outputs
// persist; XOR/NOT fabric wires recycle freed slots) to produce phys / num_slots.
// public_bit DEDUPS constants to one
// Const0 + one Const1 wire (c0_/c1_), exactly as emp-tool's RecordCtx does at compile
// time and as the crypto passes do under ctx.dedup_consts on this (body) path — so
// the live wid space and slot layout equal compile-then-run
// (the dedup is reset between the two replays in start_phase2). Only the O(num_wires)
// layout arrays live here (freed before the crypto passes re-execute the body), so no
// gate list is ever stored. Used only on the live body path (run_source); program /
// compose carry their own (already deduped) id space and never instantiate this pass.
struct AGMPCLivenessPass {
  using Wire = uint32_t;
  int num_in;
  bool phase2 = false;
  uint32_t wid;
  int gi = 0;
  int num_ands = 0;
  std::vector<int> last_use;           // wire -> last reading gate index (phase 1)
  std::vector<char> persist;           // wire persists: input / AND-out / output (phase 1)
  std::vector<int> phys;               // wire -> slot (phase 2)
  std::vector<int> freelist;           // recycled slots (phase 2)
  int next_slot = 0;
  int c0_ = -1, c1_ = -1;              // const dedup; reset per replay in start_phase2

  explicit AGMPCLivenessPass(int ni) : num_in(ni), wid((uint32_t)ni) {
    last_use.assign(ni, -1);
    persist.assign(ni, 1);             // inputs persist
  }
  int num_wires() const { return (int)last_use.size(); }

  // Pin declared outputs, then re-init for the phase-2 (freelist) replay.
  void start_phase2(const std::vector<uint32_t> &outs) {
    for (uint32_t id : outs) {
      expecting(id < last_use.size(),
                "AGMPC liveness: body returned an unallocated output wire");
      persist[id] = 1;
    }
    phase2 = true;
    wid = (uint32_t)num_in;
    gi = 0;
    phys.assign((size_t)num_wires(), -1);
    for (int w = 0; w < num_in; ++w) phys[w] = w;
    next_slot = num_in;
    freelist.clear();
    c0_ = c1_ = -1;                     // re-dedup from scratch on the phase-2 replay
  }

  // Dedup the two constants exactly as the crypto passes (ctx.dedup_consts) and
  // RecordCtx do, so the body's repeated public_bit() calls collapse to one wire
  // each and the wid space matches compile-then-run.
  Wire public_bit(bool v) {
    int &c = v ? c1_ : c0_;
    if (c >= 0) return (Wire)c;
    uint32_t id = wid;
    record_(/*is_const=*/true, false, 0, 0);
    c = (int)id;
    return (Wire)id;
  }
  Wire and_gate(Wire a, Wire b) { uint32_t id = wid; record_(false, true, (int)a, (int)b); return id; }
  Wire xor_gate(Wire a, Wire b) { uint32_t id = wid; record_(false, false, (int)a, (int)b); return id; }
  Wire not_gate(Wire a)         { uint32_t id = wid; record_(false, false, (int)a, -1);     return id; }

 private:
  // One gate: out == wid (incremented here). b < 0 marks a NOT (one input).
  void record_(bool is_const, bool is_and, int a, int b) {
    const bool is_not = (!is_const && b < 0);
    const uint32_t id = wid++;
    if (!phase2) {
      last_use.push_back(-1);
      persist.push_back(is_and ? 1 : 0);
      if (!is_const) { last_use[a] = gi; if (!is_not) last_use[b] = gi; }
      if (is_and) ++num_ands;
    } else {
      if (persist[id]) phys[id] = next_slot++;
      else if (!freelist.empty()) { phys[id] = freelist.back(); freelist.pop_back(); }
      else phys[id] = next_slot++;
      if (!is_const) {
        if (!persist[a] && last_use[a] == gi) freelist.push_back(phys[a]);
        if (!is_not && b != a && !persist[b] && last_use[b] == gi) freelist.push_back(phys[b]);
      }
    }
    ++gi;
  }
};

}  // namespace emp::ag

#endif  // EMP_AG_BACKEND_GARBLE_PASSES_LIVENESS_H__
