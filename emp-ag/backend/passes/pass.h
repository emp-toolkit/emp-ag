#ifndef EMP_AG_BACKEND_PASSES_PASS_H__
#define EMP_AG_BACKEND_PASSES_PASS_H__
//
// Pass driver — a shared execution-infra primitive.
//
// Run one protocol pass over a gate `source`: call pass.begin()/pass.end() (each
// only if present) around source(pass), with an EndGuard so end() runs on the way
// out (normal OR exception). The SAME pass definition driven over the SAME source
// yields an identical gate stream, hence an identical transcript.
//
// Protocol-agnostic; one copy, driven by every protocol pass.
//
#include "emp-tool/runtime/core/error.h"
#include <cstdint>
#include <vector>

namespace emp::ag {

template <class Pass, class Source>
inline std::vector<uint32_t> run_pass(Pass &pass, Source &source) {
  if constexpr (requires { pass.begin(); }) pass.begin();
  struct EndGuard {
    Pass &p;
    ~EndGuard() { if constexpr (requires { p.end(); }) p.end(); }
  } guard{pass};
  std::vector<uint32_t> outputs = source(pass);
  // Scalar checks once per whole pass, never per gate. AND count is meaningful
  // on every source. Sequential wire count is meaningful on live replay only;
  // lowered Linear/compose replay writes explicit slots and may finish on a slot
  // below the allocation high-water mark.
  if constexpr (requires { pass.ai; pass.ctx.num_ands; })
    expecting(pass.ai == pass.ctx.num_ands,
              "AGMPC pass replay emitted a different AND count");
  if constexpr (requires { pass.wid; pass.ctx.num_wires; pass.ctx.dedup_consts; })
    expecting(!pass.ctx.dedup_consts ||
                  pass.wid == (uint32_t)pass.ctx.num_wires,
              "AGMPC live replay emitted a different wire count");
  return outputs;  // EndGuard::~EndGuard() runs p.end() on the way out
}

// Slot-explicit gate interface (and_at/xor_at/not_at/const_at) shared by every pass
// driven on a compose source: the shared lowered replay (ag::replay_lowered) and the glue gates
// (AGMPCEngine::run_composed) call these with PRE-RESOLVED slot ids. Each pass already
// addresses state by a `wid` it increments per gate (id = wid++), so setting wid = o
// before the wid-incrementing method writes exactly slot o. One CRTP definition for all
// passes; the dense/body paths drive the same passes via execute_program / body_replay
// and never touch these.
template <class D>
struct SlotGateMixin {
  D &self_() { return *static_cast<D *>(this); }
  // Const dedup shared by every pass (each keeps its own c0_/c1_ cache: constant 0 / 1 ->
  // slot id). On the body path (ctx.dedup_consts) repeated public_bit(v) collapses to one
  // wire per constant, matching compile-then-run. dedup_hit returns the cached slot for v
  // (or -1: dedup off, or not yet made); dedup_note records the freshly-made slot.
  int dedup_hit(bool v) { return self_().ctx.dedup_consts ? (v ? self_().c1_ : self_().c0_) : -1; }
  void dedup_note(bool v, uint32_t id) { if (self_().ctx.dedup_consts) (v ? self_().c1_ : self_().c0_) = (int)id; }
  void and_at(uint32_t o, uint32_t a, uint32_t b) { self_().wid = o; (void)self_().and_gate(a, b); }
  void xor_at(uint32_t o, uint32_t a, uint32_t b) { self_().wid = o; (void)self_().xor_gate(a, b); }
  void not_at(uint32_t o, uint32_t a)             { self_().wid = o; (void)self_().not_gate(a); }
  void const_at(uint32_t o, bool v)               { self_().wid = o; (void)self_().public_bit(v); }
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_PASSES_PASS_H__
