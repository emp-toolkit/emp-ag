#ifndef EMP_AG_BACKEND_PASSES_GARBLE_H__
#define EMP_AG_BACKEND_PASSES_GARBLE_H__
//
// The garble-sender phase (Pi for i >= 2): the per-party
// GarblePass<nP, Party, Cfg> and the AGMPCProtocol<nP, Cfg> method body that drives it
// (garble_and_ship); how the rows reach P1 is passes/garble_transport.h. The
// on-wire byte-order contract this pass produces is defined in
// passes/wire_format.h (kGarbleChunk / garble_window_cap / agg_row_index /
// GarbleChunk) and crypto/halfgate.h (the half-gate hash streams); the evaluator
// that consumes it is passes/evaluate.h. Tail-included by protocol.h.
//
#include "emp-ag/backend/protocol.h"
#include "emp-ag/backend/passes/wire_format.h"   // GarbleChunk, garble_window_cap, agg_row_index
#include "emp-ag/backend/crypto/halfgate.h"      // self_halfgate_row, HalfGateHash
#include "emp-ag/backend/crypto/spdz.h"          // spdz_mac_share
#include "emp-ag/backend/runtime.h"              // chunk_pipe
#include "emp-ag/backend/passes/garble_transport.h"  // ship_garbling
#include <thread>

namespace emp::ag {

// Dispatch a runtime party id in [1, nP] to a compile-time template argument: invokes
// f.operator()<P>() for the P equal to `party`. Lets GarblePass be instantiated for the
// running party without a hand-written switch. (Sole user: garble_and_ship, below.)
template <int nP, class F>
inline void dispatch_party(int party, F &&f) {
  [&]<int... I>(std::integer_sequence<int, I...>) {
    (void)((party == I + 1 ? (f.template operator()<I + 1>(), true) : false) || ...);
  }(std::make_integer_sequence<int, nP>{});
}

// Garbler walk (sender Pi, i>=2): re-propagate the share + garbler-label fabric and,
// per AND, write the half-gate ciphertexts into the current chunk (G / S / b); the
// drain thread ships each chunk while the walk fills the next.
// Templated on the garbler's own party id so the per-AND self/cross split
// (d == Party) and the designated-bit role (Party == 2) fold at compile time;
// dispatched from garble_and_ship on the runtime party. This is the only pass
// with `party` in its per-gate hot loop.
template <int nP, int Party, class Cfg>
struct GarblePass : SlotGateMixin<GarblePass<nP, Party, Cfg>> {
  using Wire = uint32_t;
  AGMPCProtocol<nP, Cfg> *P;
  ComputeCtx<nP> &ctx;
  chunk_pipe<GarbleChunk> &pipe;
  int cap;                        // ANDs per chunk (== the slots' buffer cap)
  GarbleChunk *cur = nullptr;     // current producer chunk (lazily acquired)
  int loc = 0;                    // ANDs already written into cur
  uint32_t wid;
  int ai = 0;
  int c0_ = -1, c1_ = -1;         // const dedup (active iff ctx.dedup_consts)
  HalfGateHash<nP> hash_;         // this garbler's half-gate hash stream (crypto/halfgate.h)
  GarblePass(AGMPCProtocol<nP, Cfg> *p, ComputeCtx<nP> &c, chunk_pipe<GarbleChunk> &pp, int cap_)
      : P(p), ctx(c), pipe(pp), cap(cap_), wid((uint32_t)c.num_in) {
    hash_.setS(halfgate_stream_start(c.halfgate_seed, Party));
  }
#ifdef AG_PROFILE
  uint64_t g_bp_ns = 0;   // garble walk blocked on a full pipe (drain/ring behind)
#endif
  // Publish the filled chunk (if any) and acquire a fresh one.
  void next_chunk() {
    if (cur != nullptr) { cur->n = loc; pipe.producer_publish(); }
#ifdef AG_PROFILE
    uint64_t _t = agmpc_now_ns();
#endif
    cur = &pipe.producer_slot();
#ifdef AG_PROFILE
    g_bp_ns += agmpc_now_ns() - _t;
#endif
    loc = 0;
  }
  // Flush the trailing partial chunk and signal end-of-stream to the drain.
  void finish() {
    if (cur != nullptr) { cur->n = loc; pipe.producer_publish(); cur = nullptr; }
    pipe.producer_close();
#ifdef AG_PROFILE
    std::printf("[ag-gp] P%d garble-walk backpressure %8.1f ms\n", Party, g_bp_ns / 1e6);
    g_bp_ns = 0;
#endif
  }
  Wire public_bit(bool v) {
    int h = this->dedup_hit(v); if (h >= 0) return (Wire)h;
    uint32_t id = wid++;
    zero_share(ctx.WIRE(id));
    ctx.LABEL(id) = v ? P->Delta : zero_block;
    this->dedup_note(v, id);
    return id;
  }
  Wire not_gate(Wire i0) {
    uint32_t id = wid++;
    ctx.LABEL(id) = ctx.LABEL(i0) ^ P->Delta;
    ctx.WIRE(id) = ctx.WIRE(i0);
    return id;
  }
  Wire xor_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    ctx.LABEL(id) = ctx.LABEL(i0) ^ ctx.LABEL(i1);
    xor_share(ctx.WIRE(id), ctx.WIRE(i0), ctx.WIRE(i1));
    return id;
  }
  Wire and_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    int ai_ = ai++;
    if (cur == nullptr || loc == cap) next_chunk();
    int in0 = (int)i0, in1 = (int)i1, out = (int)id;
    block ml_a0 = ctx.LABEL(in0), ml_a1 = ml_a0 ^ P->Delta;
    block ml_b0 = ctx.LABEL(in1), ml_b1 = ml_b0 ^ P->Delta;
    constexpr int D = kHalfGateDests<nP, Cfg>;   // the garblers, then P1 under WRK
    block buf[D * 4];
    for (int k = 0; k < D; ++k) {
      buf[4 * k]     = ml_a0;
      buf[4 * k + 1] = ml_a1;
      buf[4 * k + 2] = ml_b0;
      buf[4 * k + 3] = ml_b1;
    }
    // Hash both halves of every destination, each half under the next gid of this
    // garbler's stream (crypto/halfgate.h). The evaluator advances its stream
    // for this garbler gate by gate in the same order, so the re-derived hashes match.
    halfgate_hash_garbler<nP, D>(hash_, buf);
    const AShareBundle<nP> &wb_in0 = ctx.WIRE(in0);
    const AShareBundle<nP> &wb_in1 = ctx.WIRE(in1);
    const AShareBundle<nP> &wb_out = ctx.WIRE(out);
    const AShareBundle<nP> &sb     = ctx.sigma[ai_];
    block H_a0_self = zero_block, H_a1_self = zero_block;
    block H_b0_self = zero_block, H_b1_self = zero_block;
    for (int d = 2; d <= nP; ++d) {
      int k = d - 2;
      if (d == Party) {
        H_a0_self = buf[4 * k];     H_a1_self = buf[4 * k + 1];
        H_b0_self = buf[4 * k + 2]; H_b1_self = buf[4 * k + 3];
      } else {
        ag::cross_rows(buf + 4 * k, wb_in0, wb_in1, sb, wb_out, peer_slot(Party, d),
                       &cur->S[d][3 * loc]);
      }
    }
    // WRK: the same three rows toward P1, under P1's key: P1 authenticates Lambda with them.
    if constexpr (Cfg::auth == Auth::WRK)
      ag::cross_rows(buf + 4 * (nP - 1), wb_in0, wb_in1, sb, wb_out, peer_slot(Party, 1),
                     &cur->T[3 * loc]);
    // Self half-gate row via the shared halfgate kernel. The
    // peer-slot StorageTraits accessors fold the K-loop in; the cross-garbler
    // S terms (above) stay here.
    block G0, G1, ml_g0;
    ag::self_halfgate_row(H_a0_self, H_a1_self, H_b0_self, H_b1_self, ml_a0,
                          wb_in0, wb_in1, sb, wb_out, P->Delta, G0, G1, ml_g0);
    ctx.LABEL(out) = ml_g0;
    cur->G[2 * loc]     = G0;
    cur->G[2 * loc + 1] = G1;
    if constexpr (Cfg::auth == Auth::KRRW) {
      if (Party == 2) cur->b[loc] = (unsigned char)(LSB1(ml_g0));
      // c_gamma witness records for the output check, taken while the four bundles
      // are already loaded. The check's per-AND witness is linear in the opened
      // masks (unknown until P1's Lambda broadcast):
      //   mu = ((La&Lb)^Lg)*Delta ^ La*S(in1) ^ Lb*S(in0) ^ S(sig)^S(out)
      // so these three SPDZ collapses are its complete gate-local coefficients —
      // the post-broadcast fold streams them (48 B/AND) instead of re-propagating
      // the WIRE bundle fabric through a second full walk.
      ctx.cgamma_s0[ai_] = ag::spdz_mac_share(sb, P->Delta) ^ ag::spdz_mac_share(wb_out, P->Delta);
      ctx.cgamma_s1[ai_] = ag::spdz_mac_share(wb_in1, P->Delta);
      ctx.cgamma_s2[ai_] = ag::spdz_mac_share(wb_in0, P->Delta);
    }
    ++loc;
    return id;
  }
};

// Sender Pi (i >= 2) garbles each AND gate and ships to P1. Per gate γ (chunk-local):
//   G[2γ..)     = (G_{γ,0}^i, G_{γ,1}^i)
//   S[j][3γ..)  = (S_{γ,0}^{i,j}, S_{γ,1}^{i,j}, S_{γ,2}^{i,j}), j∈[2,nP], j≠i
//   b[γ]        = LSB1(m_{γ,0}^2)  (KRRW, party 2 only)
//   T[3γ..)     = the same three rows toward P1, under P1's key (WRK)
// Half-gate hash: MITCCRH (eprint 2019/1168), one stream per sender i
// (crypto/halfgate.h) -- each gate takes the next gids of that stream, two per
// destination d (one per input), key start_point ⊕ (gid >> ReuseShift), tweak T(gid) in
// the cipher input. d == sender is the self pair feeding G_{γ,*}; d ≠ sender feeds
// S_{γ,*}^{sender,d}.
template <int nP, class Cfg>
template <class Source>
void AGMPCProtocol<nP, Cfg>::garble_and_ship(ComputeCtx &ctx, Source &source) {
  // Bounded ring of pre-sized chunk buffers overlapping garble-compute with delivery:
  // GarblePass fills the next chunk while the drain (ship_garbling,
  // passes/garble_transport.h) sends the current one; the evaluator reads the same
  // chunk boundaries.
  const int num_ands = ctx.num_ands;
  // Witness records the output check streams instead of re-walking the WIRE fabric
  // (grow-only, reused across chunks; filled per AND by GarblePass). KRRW only.
  if (Cfg::auth == Auth::KRRW && (int)ctx.cgamma_s0.size() < num_ands) {
    ctx.cgamma_s0.resize(num_ands);
    ctx.cgamma_s1.resize(num_ands);
    ctx.cgamma_s2.resize(num_ands);
  }
  // Clamp the ring-slot allocation to the circuit size (mirrors StreamEvaluatePass's cap_):
  // a small reactive flush allocates 3 slots of num_ands, not of kGarbleChunk. The wire
  // chunk size is c->n (the actual fill), so the clamp changes only memory, not the transcript.
  const int cap = garble_window_cap<nP>(num_ands);
  chunk_pipe<GarbleChunk> pipe(/*depth=*/3, [&](GarbleChunk &c) {
    c.G.resize(2 * cap);
    c.S.assign(nP + 1, BlockVec());
    for (int j = 2; j <= nP; ++j)
      if (j != party) c.S[j].resize(3 * cap);
    if constexpr (Cfg::auth == Auth::WRK) c.T.resize(3 * cap);
    else if (party == 2) c.b.resize(cap);
  });

  std::thread drain([&]() {
    ship_garbling<nP, Cfg>(io, party, pipe, num_ands, cap, laand_window_bits(fpre->ssp));
  });

  dispatch_party<nP>(party, [&]<int Party>() {
    GarblePass<nP, Party, Cfg> pass(this, ctx, pipe, cap);
    ag::run_pass(pass, source);
    pass.finish();
  });
  drain.join();
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_PASSES_GARBLE_H__
