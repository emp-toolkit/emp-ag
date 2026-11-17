#ifndef EMP_AG_BACKEND_PASSES_GARBLE_H__
#define EMP_AG_BACKEND_PASSES_GARBLE_H__
//
// The garble-sender phase (Pi for i >= 2): the per-party
// GarblePass<nP, Party> and the AGMPCProtocol<nP> method body that drives it
// (garble_and_ship), including the nP>=3 garbler-row aggregation ring. The
// on-wire byte-order contract this pass produces is defined in
// passes/wire_format.h (kGarbleChunk / garble_window_cap / agg_row_index /
// GarbleChunk) and crypto/halfgate.h (hash_gid); the evaluator that consumes it is
// passes/evaluate.h. Tail-included by protocol.h.
//
#include "emp-ag/backend/protocol.h"
#include "emp-ag/backend/passes/wire_format.h"   // GarbleChunk, garble_window_cap, agg_row_index
#include "emp-ag/backend/crypto/halfgate.h"      // self_halfgate_row, hash_gid
#include "emp-ag/backend/crypto/spdz.h"          // spdz_mac_share
#include "emp-ag/backend/runtime.h"              // chunk_pipe
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
template <int nP, int Party>
struct GarblePass : SlotGateMixin<GarblePass<nP, Party>> {
  using Wire = uint32_t;
  AGMPCProtocol<nP> *P;
  ComputeCtx<nP> &ctx;
  chunk_pipe<GarbleChunk> &pipe;
  int cap;                        // ANDs per chunk (== the slots' buffer cap)
  GarbleChunk *cur = nullptr;     // current producer chunk (lazily acquired)
  int loc = 0;                    // ANDs already written into cur
  uint32_t wid;
  int ai = 0;
  int c0_ = -1, c1_ = -1;         // const dedup (active iff ctx.dedup_consts)
  GarblePass(AGMPCProtocol<nP> *p, ComputeCtx<nP> &c, chunk_pipe<GarbleChunk> &pp, int cap_)
      : P(p), ctx(c), pipe(pp), cap(cap_), wid((uint32_t)c.num_in) {}
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
    block buf[(nP - 1) * 4];
    for (int d = 2; d <= nP; ++d) {
      int k = d - 2;
      buf[4 * k]     = ml_a0;
      buf[4 * k + 1] = ml_a1;
      buf[4 * k + 2] = ml_b0;
      buf[4 * k + 3] = ml_b1;
    }
    // The nP-1 destination hashes are the lanes of one call positioned at
    // hash_gid(Party, ai_): the class keys them by bucket, tweaks each by its gid and
    // re-expands the key schedule only when the bucket changes (crypto/halfgate.h).
    // The evaluator positions its per-source instance at the same gids, so the
    // re-derived hashes match.
    ctx.mitc.renew_ks(hash_gid<nP>(Party, ai_));
    ctx.mitc.template hash_cir<nP - 1, 4>(buf);
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
        int ds = peer_slot(Party, d);
        cur->S[d][3 * loc]     = buf[4 * k]     ^ buf[4 * k + 1] ^ wb_in1.mac(ds);
        cur->S[d][3 * loc + 1] = buf[4 * k + 2] ^ buf[4 * k + 3] ^ wb_in0.mac(ds);
        cur->S[d][3 * loc + 2] = buf[4 * k]     ^ buf[4 * k + 2]
                               ^ wb_out.mac(ds) ^ sb.mac(ds);
      }
    }
    // Self half-gate row via the shared halfgate kernel. The
    // peer-slot StorageTraits accessors fold the K-loop in; the cross-garbler
    // S terms (above) stay here.
    block G0, G1, ml_g0;
    ag::self_halfgate_row(H_a0_self, H_a1_self, H_b0_self, H_b1_self, ml_a0,
                          wb_in0, wb_in1, sb, wb_out, P->Delta, G0, G1, ml_g0);
    ctx.LABEL(out) = ml_g0;
    cur->G[2 * loc]     = G0;
    cur->G[2 * loc + 1] = G1;
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
    ++loc;
    return id;
  }
};

// Sender Pi (i >= 2) garbles each AND gate and ships to P1. Per gate γ (chunk-local):
//   G[2γ..)     = (G_{γ,0}^i, G_{γ,1}^i)
//   S[j][3γ..)  = (S_{γ,0}^{i,j}, S_{γ,1}^{i,j}, S_{γ,2}^{i,j}), j∈[2,nP], j≠i
//   b[γ]        = LSB1(m_{γ,0}^2)  (party 2 only)
// Half-gate hash: MITCCRH (eprint 2019/1168) over the gid lanes of crypto/halfgate.h
// -- lane d of gate γ from sender i hashes under gid hash_gid(i, γ) + (d-2), key
// start_point ⊕ (gid >> ReuseShift), tweak T(gid) in the cipher input. d == sender
// is the self lane feeding G_{γ,*}; d ≠ sender feeds S_{γ,*}^{sender,d}.
template <int nP>
template <class Source>
void AGMPCProtocol<nP>::garble_and_ship(ComputeCtx &ctx, Source &source) {
  // Bounded ring of pre-sized chunk buffers overlapping garble-compute with delivery.
  // nP==2: the drain ships each chunk (G, then P2's b) direct to P1. nP>=3: the drain runs
  // the garbler-row aggregation ring -- it co-aggregates
  // G+S into 3 rows/destination along 2->3->...->nP and the tail ships the aggregate to P1,
  // cutting P1's O(n^2) receive fan-in to O(n). Either way GarblePass fills the next chunk
  // while the drain moves the current one; the evaluator streams the same chunk boundaries.
  const int num_ands = ctx.num_ands;
  // Witness records the output check streams instead of re-walking the WIRE fabric
  // (grow-only, reused across chunks; filled per AND by GarblePass).
  if ((int)ctx.cgamma_s0.size() < num_ands) {
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
    if (party == 2) c.b.resize(cap);
  });

  std::thread drain([&]() {
    GarbleChunk *c;
    if constexpr (nP == 2) {
      // One garbler, no cross-terms: ship G (+ P2's b) straight to P1.
      while ((c = pipe.consumer_slot()) != nullptr) {
        io->send_data(1, c->G.data(), 2 * c->n * sizeof(block));
#ifdef EMP_AG_TEST_FLIP_B
        // TEST-ONLY (never in production): a malicious 2-party garbler flips one transmitted
        // designated bit b, so P1 derives a wrong Lambda_gamma. The symmetric c_gamma MACCheck
        // (the SOLE malicious-garbler guard at nP==2) must abort at every honest party.
        if (party == 2 && c->n > 0) c->b[0] ^= 1;
#endif
        if (party == 2) io->send_bool(1, (const bool *)c->b.data(), c->n);
        io->flush(1);  // push this chunk now so P1 receives it concurrently
        pipe.consumer_release();
      }
    } else {
      // Garbler-row aggregation: a per-chunk ring
      // 2 -> 3 -> ... -> nP -> P1 co-aggregates G+S into 3 rows per destination, so P1's
      // receive drops from O(n^2) to O(n). Each garbler XORs its OWN G into destination
      // slot `party` and its S into the other slots; head seeds, tail ships to P1. b (P2)
      // stays direct. Chain is acyclic (ids strictly increase) -> deadlock-free.
      const int nd = nP - 1;                          // destinations 2..nP
      const bool head = (party == 2);
      const int prev = party - 1;
      const int next = (party < nP) ? party + 1 : 1;  // tail (party==nP) sends to P1
      // Upstream double-buffer (middle/tail): a dedicated thread pulls window w+1's
      // running aggregate while this drain folds + sends window w, so the node's two
      // ring links run full-duplex and each hop costs max(recv, send) rather than
      // recv+send. Window sizes follow the producer's schedule (min(cap,
      // remaining)), the same independent derivation the P1 receiver uses, so the
      // recv thread needs nothing from the garble pipe. One sender thread and one
      // receiver thread per node, each in window order on disjoint sockets, keep the
      // per-channel byte streams (and the transcript) deterministic.
      const int na_ = ctx.num_ands;
      chunk_pipe<BlockVec> up_pipe(2, [&](BlockVec &b) {
        b.resize((size_t)3 * nd * cap);
      });
      std::thread up_recv;
      if (!head) up_recv = std::thread([&]() {
        int base = 0;
        while (base < na_) {
          const int cn = std::min(cap, na_ - base);
          BlockVec &a = up_pipe.producer_slot();
          io->recv_data(prev, a.data(), (size_t)3 * nd * cn * sizeof(block));
          up_pipe.producer_publish();
          base += cn;
        }
        up_pipe.producer_close();
      });
      BlockVec agg_head;                              // head-only fold target
#ifdef AG_PROFILE
      uint64_t _uw = 0, _fold = 0, _snd = 0, _pw = 0, _t;
#endif
      while (true) {
#ifdef AG_PROFILE
        _t = agmpc_now_ns();
#endif
        c = pipe.consumer_slot();
#ifdef AG_PROFILE
        _pw += agmpc_now_ns() - _t;
#endif
        if (c == nullptr) break;
        const int cn = c->n;
        const size_t sz = (size_t)3 * nd * cn;
        // The head has no predecessor, so it WRITES THROUGH (assign) instead of memset-0 then
        // XOR -- one write pass, not two. Middle/tail XOR their rows into the received aggregate
        // (already pulled by the upstream thread). Byte-identical (0 ^ x == x); head zeros the
        // one G-slot row the loop leaves unset.
        BlockVec *ap;
#ifdef AG_PROFILE
        _t = agmpc_now_ns();
#endif
        if (head) {
          agg_head.resize(sz);
          ap = &agg_head;
        } else {
          ap = up_pipe.consumer_slot();   // never null: window counts match the producer's
        }
#ifdef AG_PROFILE
        _uw += agmpc_now_ns() - _t;
        _t = agmpc_now_ns();
#endif
        BlockVec &agg = *ap;
        for (int loc = 0; loc < cn; ++loc)
          for (int i = 2; i <= nP; ++i) {
            block *dst = &agg[agg_row_index(nd, loc, i)];
            if (i == party) {                          // this garbler's own half-gate rows
              dst[0] = head ? c->G[2 * loc]     : dst[0] ^ c->G[2 * loc];
              dst[1] = head ? c->G[2 * loc + 1] : dst[1] ^ c->G[2 * loc + 1];
              if (head) dst[2] = zero_block;
            } else {                                   // its cross-terms to destination i
              dst[0] = head ? c->S[i][3 * loc]     : dst[0] ^ c->S[i][3 * loc];
              dst[1] = head ? c->S[i][3 * loc + 1] : dst[1] ^ c->S[i][3 * loc + 1];
              dst[2] = head ? c->S[i][3 * loc + 2] : dst[2] ^ c->S[i][3 * loc + 2];
            }
          }
#ifdef EMP_AG_TEST_FLIP_AGG
        // TEST-ONLY (never in production): the ring tail corrupts one aggregate row
        // (dest-2, gate-0, unconditional row -> flips bit1 = LSB1 of P1's recovered label,
        // hence Lambda_gamma). The symmetric SPDZ c_gamma MACCheck must abort at EVERY party.
        if (party == nP && sz >= 3) agg[2] = agg[2] ^ makeBlock(0, 2);
#endif
#ifdef EMP_AG_TEST_FLIP_AGG_MID
        // TEST-ONLY (nP>=4): a MIDDLE ring node (neither head=2 nor tail=nP) corrupts one
        // aggregate row; the tail forwards it -> wrong Lambda_gamma -> c_gamma MACCheck aborts.
        // Complements FLIP_AGG (tail-only): a mid-ring cheater must also be caught.
        if (party > 2 && party < nP && sz >= 3) agg[2] = agg[2] ^ makeBlock(0, 2);
#endif
#ifdef AG_PROFILE
        _fold += agmpc_now_ns() - _t;
        _t = agmpc_now_ns();
#endif
        io->send_data(next, agg.data(), sz * sizeof(block));
        if (party == 2) io->send_bool(1, (const bool *)c->b.data(), cn);
        io->flush(next);
        if (party == 2 && next != 1) io->flush(1);
#ifdef AG_PROFILE
        _snd += agmpc_now_ns() - _t;
#endif
        if (!head) up_pipe.consumer_release();
        pipe.consumer_release();
      }
      if (up_recv.joinable()) up_recv.join();
#ifdef AG_PROFILE
      std::printf("[ag-gd] P%d ring drain: chunk-wait %8.1f ms | upstream wait %8.1f ms | fold %8.1f ms | send+flush %8.1f ms\n",
                  party, _pw / 1e6, _uw / 1e6, _fold / 1e6, _snd / 1e6);
#endif
    }
  });

  dispatch_party<nP>(party, [&]<int Party>() {
    GarblePass<nP, Party> pass(this, ctx, pipe, cap);
    ag::run_pass(pass, source);
    pass.finish();
  });
  drain.join();
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_PASSES_GARBLE_H__
