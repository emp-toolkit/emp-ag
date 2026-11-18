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

namespace emp::ag {

// Streaming evaluator (P1) for ALL nP: fuses garbled-row reception and evaluation
// so the eval pass consumes each window as the next arrives, overlapping eval-compute
// with reception (the garbler already streams via garble_and_ship's chunk_pipe).
// The three num_ands-sized garbling cubes (G_{γ,*} / S_{γ,*} / b_γ) never materialize:
// a depth-2 ring of kGarbleChunk-sized windows carries them (and_gate reads only the current ai_,
// strictly increasing). begin() launches ONE receiver: at nP==2 a direct stream from garbler 2,
// at nP>=3 a single co-aggregate window from the garbler-row aggregation ring's tail (garbler nP)
// plus the b-bit from P2, so P1 receives O(n) rows/gate; end() joins the receiver.
template <int nP>
struct StreamEvaluatePass : SlotGateMixin<StreamEvaluatePass<nP>> {
  using Wire = uint32_t;
  ComputeCtx<nP> &ctx;
  block Delta_;        // P1's Delta_1, for the c_gamma witness stash
  block *mu_;          // per-AND SPDZ witness out (sized num_ands by the caller)
  unsigned char *lam_out_;   // per-AND opened mask out (the Lambda_AND broadcast buffer)
  // Per-AND records precomputed by draw_and_seed's P1 capture+sweep (state.h
  // ev_tg/ev_mu): the tgamma basis (A,B,C per dest) and the c_gamma witness
  // records (s0,s1,s2). With them the walk touches labels, masks, the pinned
  // window, and these two contiguous streams, never the share fabric.
  const block *tg_rec_;
  const block *mu_rec_;
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
                     block Delta, block *mu, unsigned char *lam_out,
                     const block *tg_rec, const block *mu_rec,
                     EvalChunk<nP> *stored = nullptr)
      : ctx(c), Delta_(Delta), mu_(mu), lam_out_(lam_out),
        tg_rec_(tg_rec), mu_rec_(mu_rec),
        wid((uint32_t)c.num_in), pool(pl), io(netio),
        cap_(garble_window_cap<nP>(c.num_ands)),
        mr_((size_t)(nP + 1) * (nP + 1)),
        pipe(stored == nullptr ? 2 : 0, [this](EvalChunk<nP> &ch) {
          if constexpr (nP == 2) ch.G.resize((size_t)2 * cap_);
          else ch.Agg.resize((size_t)3 * (nP - 1) * cap_);
          ch.b.resize((size_t)cap_);
        }) {
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
  // stays SPSC). nP==2 is one direct stream (garbler 2's G, then b). nP>=3: the garblers
  // pre-aggregate G+S over a ring (garble_and_ship), so per window P1 receives ONE
  // co-aggregate from the ring tail (garbler nP) plus the designated bit b from P2, so
  // P1's per-window receive is O(n). run_pass auto-calls begin()/end() around the gate walk.
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
        const int n = slot.n;
        if constexpr (nP == 2) {
          io->recv_data(2, slot.G.data(), (size_t)2 * n * sizeof(block));
          io->recv_bool(2, (bool *)slot.b.data(), n);
        } else {
          // The garblers already co-aggregated G+S into 3 rows/dest via the ring
          // (garble_and_ship), so P1 receives ONE window from the ring tail (garbler nP)
          // instead of the n-1 per-garbler G/S streams. The designated bit b is direct
          // from P2.
          io->recv_data(nP, slot.Agg.data(), (size_t)3 * (nP - 1) * n * sizeof(block));
          io->recv_bool(2, (bool *)slot.b.data(), n);
        }
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
    block self_Ha[nP + 1], self_Hb[nP + 1];
    for (int s = 2; s <= nP; ++s) {
      block buf[(nP - 1) * 2];
      for (int d = 2; d <= nP; ++d) {
        int k = d - 2;
        buf[2 * k]     = ctx.EVAL(s, in0);
        buf[2 * k + 1] = ctx.EVAL(s, in1);
      }
      halfgate_hash_evaluator<nP>(mitc_src_[s - 2], buf);
      for (int d = 2; d <= nP; ++d) {
        int k = d - 2;
        if (d == s) {
          self_Ha[s] = buf[2 * k];
          self_Hb[s] = buf[2 * k + 1];
        } else {
          Mr(s, d) = buf[2 * k] ^ buf[2 * k + 1];   // P1-local hash; the S term is folded into Agg
        }
      }
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
    ++loc;
    return id;
  }
};

// Receive + evaluate fused at P1 for ALL nP: stream the garbled rows and evaluate each
// window as the next arrives. ctx.G/ctx.S are NOT materialized -- the windowed ring
// inside StreamEvaluatePass<nP> holds only kGarbleChunk ANDs at a time. run_pass drives
// begin() (launch the single receiver) -> the gate walk -> end() (join). At nP>2 the
// receiver reads one co-aggregate window from the aggregation ring tail (not n-1 streams).
template <int nP>
template <class Source>
void AGMPCProtocol<nP>::stream_evaluate(ComputeCtx &ctx, Source &source) {
  // P1's c_gamma witness + Lambda_AND broadcast buffers (grow-only, reused across
  // chunks), both finalized inside the eval walk — see StreamEvaluatePass.
  if ((int)ctx.cgamma_mu.size() < ctx.num_ands) ctx.cgamma_mu.resize(ctx.num_ands);
  if ((int)ctx.Lambda_AND.size() < ctx.num_ands) ctx.Lambda_AND.resize(ctx.num_ands);
  StreamEvaluatePass<nP> pass(ctx, pool, io, Delta, ctx.cgamma_mu.data(),
                              ctx.Lambda_AND.data(), ctx.ev_tg.data(), ctx.ev_mu.data());
  ag::run_pass(pass, source);
}

// Offline P1 sink for the exact stream emitted by garble_and_ship.  Chunk
// boundaries must be preserved for recv_bool because every window has its own
// packed tail byte; decoded rows are flattened into one direct-access chunk for
// the later evaluator walk.
template <int nP>
void AGMPCProtocol<nP>::receive_prepared_garbling(
    ComputeCtx &ctx, EvalChunk<nP> &rows) {
  const int num_ands = ctx.num_ands;
  const int cap = garble_window_cap<nP>(num_ands);
  rows.n = num_ands;
  rows.b.resize((size_t)num_ands);
  if constexpr (nP == 2)
    rows.G.resize((size_t)2 * num_ands);
  else
    rows.Agg.resize((size_t)3 * (nP - 1) * num_ands);

  for (int base = 0; base < num_ands; base += cap) {
    const int n = std::min(cap, num_ands - base);
    if constexpr (nP == 2) {
      io->recv_data(2, rows.G.data() + (size_t)2 * base,
                    (size_t)2 * n * sizeof(block));
      io->recv_bool(2, (bool *)(rows.b.data() + base), n);
    } else {
      io->recv_data(nP, rows.Agg.data() + (size_t)3 * (nP - 1) * base,
                    (size_t)3 * (nP - 1) * n * sizeof(block));
      io->recv_bool(2, (bool *)(rows.b.data() + base), n);
    }
  }
}

// Online P1 source for stored rows.  `cur` starts at the one full-circuit
// EvalChunk, so and_gate takes the same fast path: no feeder, allocation,
// memory copy, network receive, or per-gate mode branch.
template <int nP>
template <class Source>
void AGMPCProtocol<nP>::evaluate_prepared(
    ComputeCtx &ctx, Source &source, EvalChunk<nP> &&rows) {
  if ((int)ctx.cgamma_mu.size() < ctx.num_ands) ctx.cgamma_mu.resize(ctx.num_ands);
  if ((int)ctx.Lambda_AND.size() < ctx.num_ands) ctx.Lambda_AND.resize(ctx.num_ands);
  StreamEvaluatePass<nP> pass(ctx, pool, io, Delta, ctx.cgamma_mu.data(),
                              ctx.Lambda_AND.data(), ctx.ev_tg.data(),
                              ctx.ev_mu.data(), &rows);
  ag::run_pass(pass, source);
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_PASSES_EVALUATE_H__
