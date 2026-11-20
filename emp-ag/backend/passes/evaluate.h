#ifndef EMP_AG_BACKEND_PASSES_EVALUATE_H__
#define EMP_AG_BACKEND_PASSES_EVALUATE_H__
//
// The streaming-evaluate phase (P1 for ALL nP): the
// StreamEvaluatePass<nP> that fuses garbled-row reception with evaluation, and
// the AGMPCProtocol<nP> method body that drives it (stream_evaluate). It
// consumes the byte stream whose contract is defined in passes/wire_format.h
// (EvalChunk / garble_window_cap / agg_row_index) and crypto/halfgate.h (the
// half-gate hash streams), produced
// by the garbler in passes/garble.h. Tail-included by protocol.h.
//
#include "emp-ag/backend/protocol.h"
#include "emp-ag/backend/passes/wire_format.h"   // EvalChunk, garble_window_cap, agg_row_index
#include "emp-ag/backend/crypto/halfgate.h"      // HalfGateHash, halfgate_stream_start
#include "emp-ag/backend/crypto/spdz.h"          // collapse_cgamma_from_records
#include "emp-ag/backend/runtime.h"              // chunk_pipe
#include "emp-ag/backend/passes/garble_transport.h"  // recv_garbling_window

namespace emp::ag {

// Streaming evaluator (P1) for ALL nP: fuses garbled-row reception and evaluation
// so the eval pass consumes each window as the next arrives, overlapping eval-compute
// with reception (the garbler already streams via garble_and_ship's chunk_pipe).
// The num_ands-sized garbling cubes (G_{γ,*} / S_{γ,*} / b_γ or the rows toward P1) never
// materialize: a depth-2 ring of kGarbleChunk-sized windows carries them (and_gate reads
// only the current ai_, strictly increasing). begin() launches ONE receiver, which reads
// each window through recv_garbling_window (passes/garble_transport.h); end() joins it.
template <int nP, class Cfg>
struct StreamEvaluatePass : SlotGateMixin<StreamEvaluatePass<nP, Cfg>> {
  using Wire = uint32_t;
  ComputeCtx<nP> &ctx;
  block Delta_;        // P1's Delta_1: the c_gamma witness stash (KRRW), delta_w_ (WRK)
  // Per-AND records precomputed by draw_and_seed's P1 capture+sweep (state.h): the
  // tgamma basis (A,B,C per dest) and, by Auth, the c_gamma witness records (KRRW) or
  // P1's keys and own bits on Lambda's share (WRK). With them the walk touches labels,
  // masks, the pinned window, and these contiguous streams, never the share fabric.
  const block *tg_rec_;
  // KRRW: c_gamma witness records in; per-AND SPDZ witness and Lambda_AND out (the
  // caller sizes both to num_ands).
  const block *mu_rec_;
  block *mu_;
  unsigned char *lam_out_;
  // WRK: P1's key sums (3 per AND) and own share bits, and the truncation window of the
  // rows toward P1 with Delta_1 cut to it.
  const block *auth_rec_;
  const unsigned char *auth_bits_;
  int bits_;
  block window_, delta_w_;
  uint32_t wid;
  int ai = 0;
  int c0_ = -1, c1_ = -1;
  ThreadPool *pool;
  NetIOMP<nP> *io;
  int cap_;
  chunk_pipe<EvalChunk<nP>> pipe;
  std::future<void> recv_fut;
  EvalChunk<nP> *cur = nullptr;
  bool stored_ = false;
  int loc = 0;
  BlockVec mr_;   // (nP+1)^2 per-gate witness scratch (heap: quadratic in nP)
  // One half-gate hash stream per SOURCE (crypto/halfgate.h): stream s-2 mirrors
  // garbler s's own stream (same start point, same gids, advanced gate by gate in the
  // same order), so the hashes are the garblers'.
  HalfGateHash<nP> mitc_src_[nP - 1];
#ifdef AG_PROFILE
  // Stage decomposition of the eval span: walk-starve (gate walk blocked on window
  // arrival), receiver ingest (bytes off the wire), receiver backpressure (pipe full
  // = the walk is the slower stage). serve = phase wall - starve.
  uint64_t ev_wait_ns = 0, ev_recv_ns = 0, ev_bp_ns = 0;
#endif

  StreamEvaluatePass(ComputeCtx<nP> &c, ThreadPool *pl, NetIOMP<nP> *netio,
                     block Delta, int ssp, EvalChunk<nP> *stored = nullptr)
      : ctx(c), Delta_(Delta), tg_rec_(c.ev_tg.data()), mu_rec_(c.ev_mu.data()),
        mu_(c.cgamma_mu.data()), lam_out_(c.Lambda_AND.data()),
        auth_rec_(c.ev_auth.data()), auth_bits_(c.ev_auth_bits.data()),
        bits_(laand_window_bits(ssp)), window_(laand_window_mask(ssp)),
        delta_w_(Delta & laand_window_mask(ssp)),
        wid((uint32_t)c.num_in), pool(pl), io(netio),
        cap_(garble_window_cap<nP>(c.num_ands)),
        mr_((size_t)(nP + 1) * (nP + 1)),
        pipe(stored == nullptr ? 2 : 0,
             [this](EvalChunk<nP> &ch) { size_eval_chunk<nP, Cfg>(ch, cap_); }) {
    if (stored != nullptr) {
      expecting(stored->n == c.num_ands,
                "prepared evaluator row count differs from circuit AND count");
      stored_ = true;
      cur = stored;
    }
    // Each source's stream starts where that garbler's does: the chunk's half-gate seed
    // (set by draw_and_seed before this pass is constructed) with the sender folded in.
    for (int s = 2; s <= nP; ++s)
      mitc_src_[s - 2].setS(halfgate_stream_start(ctx.halfgate_seed, s));
  }

  // begin(): launch the receiver coordinator (the SINGLE producer -> the chunk_pipe
  // stays SPSC); recv_garbling_window (passes/garble_transport.h) reads each window as
  // the delivery delivers it. run_pass auto-calls begin()/end() around the gate walk.
  void begin() {
    if (stored_) return;
    recv_fut = pool->enqueue([this] {
      const int na = ctx.num_ands;
      int base = 0;
      while (base < na) {
#ifdef AG_PROFILE
        uint64_t _t = agmpc_now_ns();
#endif
        EvalChunk<nP> &slot = pipe.producer_slot();
#ifdef AG_PROFILE
        ev_bp_ns += agmpc_now_ns() - _t;
        _t = agmpc_now_ns();
#endif
        slot.n = std::min(cap_, na - base);
        recv_garbling_window<nP, Cfg>(io, slot, 0, slot.n, bits_);
#ifdef AG_PROFILE
        ev_recv_ns += agmpc_now_ns() - _t;
#endif
        pipe.producer_publish();
        base += slot.n;
      }
      pipe.producer_close();
    });
  }
  void end() {
    if (stored_) return;
    if (cur != nullptr) pipe.consumer_release();
    recv_fut.get();
#ifdef AG_PROFILE
    std::printf("[ag-ev] P1 walk-starve %8.1f ms | recv ingest %8.1f ms | recv-backpressure %8.1f ms\n",
                ev_wait_ns / 1e6, ev_recv_ns / 1e6, ev_bp_ns / 1e6);
    ev_wait_ns = ev_recv_ns = ev_bp_ns = 0;
#endif
  }

  // XOR / NOT / public_bit: label/mask re-propagation only. This pass never touches
  // the WIRE bundle fabric: the bundle-derived per-AND terms were precomputed into
  // ctx.ev_tg/ev_mu by draw_and_seed's P1 capture+sweep, and the fabric that later steps read
  // (the output decode) persists from DrawBeaverPass's walk, whose output
  // slots liveness pins to the end.
  Wire public_bit(bool v) {
    int h = this->dedup_hit(v); if (h >= 0) { ctx.MASK(h) = (unsigned char)v; return (Wire)h; }
    uint32_t id = wid++;
    ctx.MASK(id) = (unsigned char)v;
    for (int j = 2; j <= nP; ++j) ctx.EVAL(j, id) = zero_block;
    this->dedup_note(v, id);
    return id;
  }
  Wire not_gate(Wire i0) {
    uint32_t id = wid++;
    ctx.MASK(id) = ctx.MASK(i0) ^ 1;
    for (int j = 2; j <= nP; ++j) ctx.EVAL(j, id) = ctx.EVAL(j, i0);
    return id;
  }
  Wire xor_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    for (int j = 2; j <= nP; ++j) ctx.EVAL(j, id) = ctx.EVAL(j, i0) ^ ctx.EVAL(j, i1);
    ctx.MASK(id) = ctx.MASK(i0) ^ ctx.MASK(i1);
    return id;
  }
  // and_gate: the per-AND eval-label recovery, with the three garbling reads
  // redirected to the pinned window (cur->{G,S,b}[loc]) + the lazy pull. Fabric/
  // witness stay in ctx.
  Wire and_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    int ai_ = ai++;
    if (cur == nullptr || loc == cur->n) {
      expecting(!stored_,
                "prepared evaluator consumed more rows than the circuit declared");
      if (cur != nullptr) pipe.consumer_release();
#ifdef AG_PROFILE
      uint64_t _t = agmpc_now_ns();
#endif
      cur = pipe.consumer_slot();
#ifdef AG_PROFILE
      ev_wait_ns += agmpc_now_ns() - _t;
#endif
      loc = 0;
    }
    int in0 = (int)i0, in1 = (int)i1, out = (int)id;
    bool La = ctx.MASK(in0), Lb = ctx.MASK(in1);
    const block mLa = select_mask[La], mLb = select_mask[Lb];
    // P1's own self-MAC row (the t_gamma witness) is assembled from the draw-time
    // records instead of the live share bundles: value-identical to
    // tgamma_witness_garbler over the bundles (the records ARE its Lambda-affine
    // basis; see draw_beaver.h's in-walk capture and sigma sweep), with no fabric
    // loads on the hot path.
    // Mr lives in pass-owned heap scratch, NOT a local array: (nP+1)^2 blocks is
    // 266 KB per gate call at nP=128 -- a quadratic stack frame on the hot path.
    const auto Mr = [this](int a, int b) -> block & { return mr_[(size_t)a * (nP + 1) + b]; };
    const block *tgr = tg_rec_ + (size_t)3 * (nP - 1) * ai_;
    for (int i = 2; i <= nP; ++i) {
      const block *r = tgr + 3 * (i - 2);
      Mr(1, i) = r[2] ^ (r[0] & mLa) ^ (r[1] & mLb);
    }
    // Per source, hash P1's two active labels for every destination under the next
    // gids of that source's stream -- the gids the garbler hashed them under, so the
    // re-derived hashes match (crypto/halfgate.h).
    constexpr int D = kHalfGateDests<nP, Cfg>;   // the garblers, then P1 under WRK
    block self_Ha[nP + 1], self_Hb[nP + 1];
    block p1_pad = zero_block;   // WRK: the sources' hashes on P1's lanes, summed
    for (int s = 2; s <= nP; ++s) {
      block buf[D * 2];
      for (int k = 0; k < D; ++k) {
        buf[2 * k]     = ctx.EVAL(s, in0);
        buf[2 * k + 1] = ctx.EVAL(s, in1);
      }
      halfgate_hash_evaluator<nP, D>(mitc_src_[s - 2], buf);
      for (int d = 2; d <= nP; ++d) {
        int k = d - 2;
        if (d == s) {
          self_Ha[s] = buf[2 * k];
          self_Hb[s] = buf[2 * k + 1];
        } else {
          Mr(s, d) = buf[2 * k] ^ buf[2 * k + 1];   // P1-local hash; the S term is folded into Agg
        }
      }
      if constexpr (Cfg::auth == Auth::WRK)
        p1_pad = p1_pad ^ buf[2 * (nP - 1)] ^ buf[2 * (nP - 1) + 1];
    }
    // mLa/mLb (hoisted above the record fold): branchless masks for the two public
    // selectors La/Lb (equivalent to branching on them); the gated addends are
    // cache-hot (the pinned G/Agg window + P1's own EVAL slot).
    for (int i = 2; i <= nP; ++i) {
      block t = self_Ha[i] ^ self_Hb[i];
      for (int s = 1; s <= nP; ++s) if (s != i)
        t = t ^ Mr(s, i);
      t = t ^ (ctx.EVAL(i, in0) & mLb);        // P1-local input label (Lb-gated)
      if constexpr (nP == 2) {                 // the single garbler's own G rows (i==2)
        t = t ^ (cur->G[2 * loc] & mLa) ^ (cur->G[2 * loc + 1] & mLb);
      } else {                                 // the co-aggregated G+S for dest i (one read)
        const block *a = &cur->Agg[agg_row_index(nP - 1, loc, i)];
        t = t ^ a[2] ^ (a[0] & mLa) ^ (a[1] & mLb);
      }
      ctx.EVAL(i, out) = t;
    }
    if constexpr (Cfg::auth == Auth::KRRW) {
      ctx.MASK(out) =
          (unsigned char)(cur->b[loc] ^ LSB1(ctx.EVAL(2, out)));
      // P1 knows every opened mask DURING eval: stash the Lambda_AND broadcast value
      // and the finalized c_gamma SPDZ witness here. The witness uses the SAME record
      // form the garblers stash (s0/s1/s2 precomputed by draw_and_seed) —
      // value-identical to the bundle-form collapse, per collapse_cgamma_from_records'
      // contract. open_and_masks then just sends the buffer (no collect walk), and the
      // output check folds mu with chi (drawn only after that broadcast), so P1 never
      // re-walks the fabric.
      lam_out_[ai_] = ctx.MASK(out);
      mu_[ai_] = ag::collapse_cgamma_from_records(La, Lb, ctx.MASK(out) != 0,
                                                  mu_rec_[3 * ai_ + 0], mu_rec_[3 * ai_ + 1],
                                                  mu_rec_[3 * ai_ + 2], Delta_);
    } else {
      // The rows toward P1 leave the garblers' MACs under Delta_1 on their summed share
      // u of Lambda ^ La Lb (crypto/halfgate.h, cross_rows); minus P1's keys on it they
      // are u * Delta_1 within the window, or a garbler cheated. bit 0 of Delta_1 is 1
      // and of every key 0, so bit 0 of that difference is u.
      const block *t = &cur->T[3 * loc];
      const block *k = auth_rec_ + 3 * ai_;
      const block v = (p1_pad ^ t[2] ^ (t[0] & mLa) ^ (t[1] & mLb) ^
                       k[2] ^ (k[0] & mLa) ^ (k[1] & mLb)) & window_;
      const bool u = getLSB(v);
      const block expect = select_mask[u] & delta_w_;
      expecting(cmpBlock(&v, &expect, 1), "WRK: a garbled gate failed P1's check");
      // P1's own share of Lambda ^ La Lb, from its bits on lambda_beta, lambda_alpha and
      // lambda_gamma ^ sigma (draw_and_seed).
      const unsigned r = auth_bits_[ai_];
      const unsigned own = (La & r) ^ (Lb & (r >> 1)) ^ (r >> 2);
      ctx.MASK(out) = (unsigned char)(((La & Lb) ^ own ^ u) & 1);
    }
    ++loc;
    return id;
  }
};

// Receive + evaluate fused at P1 for ALL nP: stream the garbled rows and evaluate each
// window as the next arrives. ctx.G/ctx.S are NOT materialized -- the windowed ring
// inside StreamEvaluatePass<nP> holds only kGarbleChunk ANDs at a time. run_pass drives
// begin() (launch the single receiver) -> the gate walk -> end() (join). At nP>2 the
// receiver reads one co-aggregate window from the aggregation ring tail (not n-1 streams).
template <int nP, class Cfg>
template <class Source>
void AGMPCProtocol<nP, Cfg>::stream_evaluate(ComputeCtx &ctx, Source &source) {
  // P1's c_gamma witness + Lambda_AND broadcast buffers (grow-only, reused across
  // chunks), both finalized inside the eval walk — see StreamEvaluatePass.
  if (Cfg::auth == Auth::KRRW) {
    if ((int)ctx.cgamma_mu.size() < ctx.num_ands) ctx.cgamma_mu.resize(ctx.num_ands);
    if ((int)ctx.Lambda_AND.size() < ctx.num_ands) ctx.Lambda_AND.resize(ctx.num_ands);
  }
  StreamEvaluatePass<nP, Cfg> pass(ctx, pool, io, Delta, fpre->ssp);
  ag::run_pass(pass, source);
}

// Offline P1 sink for the exact stream emitted by garble_and_ship.  Chunk
// boundaries must be preserved for recv_bool because every window has its own
// packed tail byte; decoded rows are flattened into one direct-access chunk for
// the later evaluator walk.
template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::receive_prepared_garbling(
    ComputeCtx &ctx, EvalChunk<nP> &rows) {
  const int num_ands = ctx.num_ands;
  const int cap = garble_window_cap<nP>(num_ands);
  rows.n = num_ands;
  size_eval_chunk<nP, Cfg>(rows, num_ands);
  for (int base = 0; base < num_ands; base += cap)
    recv_garbling_window<nP, Cfg>(io, rows, (size_t)base, std::min(cap, num_ands - base),
                                laand_window_bits(fpre->ssp));
}

// Online P1 source for stored rows.  `cur` starts at the one full-circuit
// EvalChunk, so and_gate takes the same fast path: no feeder, allocation,
// memory copy, network receive, or per-gate mode branch.
template <int nP, class Cfg>
template <class Source>
void AGMPCProtocol<nP, Cfg>::evaluate_prepared(
    ComputeCtx &ctx, Source &source, EvalChunk<nP> &&rows) {
  if (Cfg::auth == Auth::KRRW) {
    if ((int)ctx.cgamma_mu.size() < ctx.num_ands) ctx.cgamma_mu.resize(ctx.num_ands);
    if ((int)ctx.Lambda_AND.size() < ctx.num_ands) ctx.Lambda_AND.resize(ctx.num_ands);
  }
  StreamEvaluatePass<nP, Cfg> pass(ctx, pool, io, Delta, fpre->ssp, &rows);
  ag::run_pass(pass, source);
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_PASSES_EVALUATE_H__
