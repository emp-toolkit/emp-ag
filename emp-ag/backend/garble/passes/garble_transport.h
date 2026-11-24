#ifndef EMP_AG_BACKEND_GARBLE_PASSES_GARBLE_TRANSPORT_H__
#define EMP_AG_BACKEND_GARBLE_PASSES_GARBLE_TRANSPORT_H__
//
// How the garblers' rows reach P1, both ends: the garbler's drain (ship_garbling,
// which sends what GarblePass fills, chunk by chunk) and P1's reader
// (recv_garbling_window, used by the streaming evaluator and by prepared runs). The
// delivery option (ProtocolOptions::delivery, backend/garble/garble_config.h) is read only
// here, once per call; the row layouts are in garble/passes/wire_format.h.
//
// Per AND gate a garbler produces its half-gate rows G, three rows S toward every
// other garbler, and then by Auth: KRRW, P2's bit b; WRK, three rows T toward P1. The
// T rows travel as their low `bits` bits (common/laand_window.h: rho random bits above
// the two pinned low bits of Delta_1), packed back to back. Packing is XOR-linear, so
// the T rows of several garblers sum in packed form.
//
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/garble/garble_config.h"
#include "emp-ag/backend/common/profiling.h"
#include "emp-ag/backend/common/runtime.h"              // chunk_pipe
#include "emp-ag/backend/common/laand_window.h"  // pack/unpack of truncated rows
#include "emp-ag/backend/garble/passes/wire_format.h"   // GarbleChunk, EvalChunk, agg_row_index
#include <algorithm>
#include <cstring>
#include <thread>
#include <vector>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

// WRK: pack n rows toward P1 to their low `bits` bits, and back.
inline void pack_p1_rows(unsigned char *dst, const block *rows, int64_t n, int bits) {
  pack_laand_blocks(dst, rows, n, bits);
}
inline void unpack_p1_rows(block *rows, const unsigned char *src, int64_t n, int bits) {
  expecting(unpack_laand_blocks(rows, src, n, bits),
            "WRK: a garbled row toward P1 has nonzero padding");
}

// Bytes of one window's T rows on the wire (0 under KRRW).
template <class Cfg>
inline size_t p1_row_bytes(int n, int bits) {
  return Cfg::auth == Auth::WRK ? (size_t)laand_row_wire_bytes((int64_t)3 * n, bits) : 0;
}

// Garbler drain: ship every chunk the garble pass publishes on `pipe`, in order, until it
// closes.
//   DIRECT (and every nP = 2 run, whose single garbler has no one to sum with): the
//           garbler sends P1 its own rows: G, then its S rows toward every other garbler
//           in id order, then b (KRRW, P2) or T (WRK). P1 sums them
//           (recv_garbling_window).
//   RING    (nP >= 3) the chunk's rows join a running sum along 2 -> 3 -> ... -> nP,
//           which sends P1 three rows per destination garbler (and, under WRK, the
//           summed T rows), so P1 receives O(n) rows per gate instead of O(n^2); P2's
//           b goes to P1 directly.
template <int nP, class Cfg>
void ship_garbling(NetIOMP<nP> *io, int party, chunk_pipe<GarbleChunk> &pipe,
                   int num_ands, int cap, int bits, Delivery delivery) {
  constexpr bool wrk = Cfg::auth == Auth::WRK;
  std::vector<unsigned char> tpk(p1_row_bytes<Cfg>(cap, bits));   // this garbler's packed T
  auto pack_t = [&](GarbleChunk *c) {
    if constexpr (kTestHooks) {
      // TEST-ONLY (hook flip_p1_row): a garbler (test_flip_party) flips a bit of its
      // unconditional row toward P1 at the chunk's first gate. P1's check of that gate
      // must fail.
      if (hooks().flip_p1_row && party == test_flip_party(nP) && c->n > 0)
        c->T[2] = c->T[2] ^ makeBlock(0, 4);
    }
    pack_p1_rows(tpk.data(), c->T.data(), (int64_t)3 * c->n, bits);
  };
  GarbleChunk *c;
  if (nP == 2 || delivery == Delivery::DIRECT) {
    // The garbler sends P1 its own rows: G, then its S rows toward every other garbler in
    // id order (none at nP = 2), then b (KRRW, P2 only) or T (WRK).
    while ((c = pipe.consumer_slot()) != nullptr) {
      const size_t cn = (size_t)c->n;
      if constexpr (kTestHooks) {
        // TEST-ONLY (hook flip_g): a garbler (test_flip_party) flips every half-gate row
        // of the chunk, each by a different bit, so the labels P1 recovers are wrong unless
        // every gate's masked inputs are both 0 (probability 4^-n), and the errors cannot
        // cancel in an XOR of outputs.
        if (hooks().flip_g && party == test_flip_party(nP))
          for (size_t i = 0; i < 2 * cn; ++i) c->G[i] = c->G[i] ^ makeBlock(0, 4ULL << (i % 60));
        // TEST-ONLY (hook flip_direct): a garbler (test_flip_party) other than 2 corrupts
        // the unconditional row it sends toward garbler 2 at the chunk's first gate, which
        // flips bit 1 of the label P1 recovers for garbler 2, hence (KRRW) P1's Lambda. The
        // check must abort.
        if constexpr (nP >= 3)
          if (hooks().flip_direct && party == test_flip_party(nP) && party != 2 && cn > 0)
            c->S[2][2] = c->S[2][2] ^ makeBlock(0, 2);
      }
      io->send_data(1, c->G.data(), 2 * cn * sizeof(block));
      for (int d = 2; d <= nP; ++d)
        if (d != party) io->send_data(1, c->S[d].data(), 3 * cn * sizeof(block));
      if constexpr (wrk) {
        pack_t(c);
        io->send_data(1, tpk.data(), p1_row_bytes<Cfg>(c->n, bits));
      } else if (party == 2) {
        if constexpr (kTestHooks) {
          // TEST-ONLY (hook flip_b): a malicious 2-party garbler flips one transmitted
          // designated bit b, so P1 derives a wrong Lambda_gamma. The symmetric c_gamma
          // MACCheck (the SOLE malicious-garbler guard at nP==2) must abort at every honest
          // party.
          if (hooks().flip_b && cn > 0) c->b[0] ^= 1;
        }
        io->send_bool(1, (const bool *)c->b.data(), (int64_t)cn);
      }
      io->flush(1);  // push this chunk now so P1 receives it concurrently
      pipe.consumer_release();
    }
  } else {
    // Garbler-row aggregation: a per-chunk ring
    // 2 -> 3 -> ... -> nP -> P1 co-aggregates G+S into 3 rows per destination, so P1's
    // receive drops from O(n^2) to O(n). Each garbler XORs its OWN G into destination
    // slot `party` and its S into the other slots; head seeds, tail ships to P1. b (P2)
    // stays direct; under WRK the packed T rows ride after the block rows and are summed
    // the same way. Chain is acyclic (ids strictly increase) -> deadlock-free.
    const int nd = nP - 1;                          // destinations 2..nP
    const bool head = (party == 2);
    const int prev = party - 1;
    const int next = (party < nP) ? party + 1 : 1;  // tail (party==nP) sends to P1
    // One window's running sum: 3 nd cn blocks, then (WRK) its packed T bytes in the
    // blocks after them.
    auto window_bytes = [&](int cn) {
      return (size_t)3 * nd * cn * sizeof(block) + p1_row_bytes<Cfg>(cn, bits);
    };
    const size_t cap_blocks =
        (size_t)3 * nd * cap + (p1_row_bytes<Cfg>(cap, bits) + sizeof(block) - 1) / sizeof(block);
    // Upstream double-buffer (middle/tail): a dedicated thread pulls window w+1's
    // running aggregate while this drain folds + sends window w, so the node's two
    // ring links run full-duplex and each hop costs max(recv, send) rather than
    // recv+send. Window sizes follow the producer's schedule (min(cap,
    // remaining)), the same independent derivation the P1 receiver uses, so the
    // recv thread needs nothing from the garble pipe. One sender thread and one
    // receiver thread per node, each in window order on disjoint sockets, keep the
    // per-channel byte streams (and the transcript) deterministic.
    const int na_ = num_ands;
    chunk_pipe<BlockVec> up_pipe(2, [&](BlockVec &b) { b.resize(cap_blocks); });
    std::thread up_recv;
    if (!head) up_recv = std::thread([&]() {
      int base = 0;
      while (base < na_) {
        const int cn = std::min(cap, na_ - base);
        BlockVec &a = up_pipe.producer_slot();
        io->recv_data(prev, a.data(), window_bytes(cn));
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
        agg_head.resize(cap_blocks);
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
      if constexpr (wrk) {                         // the packed T rows, summed the same way
        pack_t(c);
        unsigned char *t = (unsigned char *)(agg.data() + sz);
        const size_t tb = p1_row_bytes<Cfg>(cn, bits);
        if (head) std::memcpy(t, tpk.data(), tb);
        else for (size_t i = 0; i < tb; ++i) t[i] ^= tpk[i];
      }
      if constexpr (kTestHooks) {
        // TEST-ONLY (hook flip_agg): the ring tail corrupts one aggregate row (dest-2,
        // gate-0, unconditional row -> flips bit1 = LSB1 of P1's recovered label, hence
        // Lambda_gamma). The symmetric SPDZ c_gamma MACCheck must abort at EVERY party.
        if (hooks().flip_agg && party == nP && sz >= 3) agg[2] = agg[2] ^ makeBlock(0, 2);
        // TEST-ONLY (hook flip_agg_mid, nP>=4): a MIDDLE ring node (neither head=2 nor
        // tail=nP) corrupts one aggregate row; the tail forwards it -> wrong Lambda_gamma ->
        // c_gamma MACCheck aborts. Complements flip_agg (tail-only): a mid-ring cheater
        // must also be caught.
        if (hooks().flip_agg_mid && party > 2 && party < nP && sz >= 3)
          agg[2] = agg[2] ^ makeBlock(0, 2);
      }
#ifdef AG_PROFILE
      _fold += agmpc_now_ns() - _t;
      _t = agmpc_now_ns();
#endif
      io->send_data(next, agg.data(), window_bytes(cn));
      if (!wrk && party == 2) io->send_bool(1, (const bool *)c->b.data(), cn);
      io->flush(next);
      if (!wrk && party == 2 && next != 1) io->flush(1);
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
}

// Size an EvalChunk to hold n ANDs of garbled rows.
template <int nP, class Cfg>
void size_eval_chunk(EvalChunk<nP> &rows, int n) {
  if constexpr (nP == 2) rows.G.resize((size_t)2 * n);
  else rows.Agg.resize((size_t)3 * (nP - 1) * n);
  if constexpr (Cfg::auth == Auth::WRK) rows.T.resize((size_t)3 * n);
  else rows.b.resize((size_t)n);
}

// P1: receive one window of n ANDs into `rows` at AND offset `base` -- the mirror of
// ship_garbling. nP == 2: garbler 2's G rows, then its b or T. nP >= 3, RING: the
// running sum from the ring's tail (garbler nP), then b from P2 (KRRW). DIRECT: every
// garbler's own rows, summed here into the same rows the ring delivers.
template <int nP, class Cfg>
void recv_garbling_window(NetIOMP<nP> *io, EvalChunk<nP> &rows, size_t base, int n,
                          int bits, Delivery delivery) {
  constexpr bool wrk = Cfg::auth == Auth::WRK;
  const size_t tb = p1_row_bytes<Cfg>(n, bits);
  // Per-thread scratch, reused across windows: the packed T rows (summed, under DIRECT)
  // and DIRECT's per-garbler receive buffers.
  static thread_local std::vector<unsigned char> tpk, tin;
  static thread_local BlockVec buf;
  tpk.assign(tb, 0);
  if constexpr (nP == 2) {
    io->recv_data(2, rows.G.data() + 2 * base, (size_t)2 * n * sizeof(block));
    if constexpr (wrk) io->recv_data(2, tpk.data(), tb);
    else io->recv_bool(2, (bool *)(rows.b.data() + base), n);
  } else if (delivery == Delivery::DIRECT) {
    constexpr int nd = nP - 1;
    block *agg = rows.Agg.data() + (size_t)3 * nd * base;
    std::fill(agg, agg + (size_t)3 * nd * n, zero_block);
    if (buf.size() < (size_t)3 * n) buf.resize((size_t)3 * n);
    tin.resize(tb);
    for (int s = 2; s <= nP; ++s) {
      io->recv_data(s, buf.data(), (size_t)2 * n * sizeof(block));   // s's own G rows
      for (int loc = 0; loc < n; ++loc) {
        block *dst = agg + agg_row_index(nd, loc, s);
        dst[0] = dst[0] ^ buf[2 * loc];
        dst[1] = dst[1] ^ buf[2 * loc + 1];
      }
      for (int d = 2; d <= nP; ++d) if (d != s) {               // s's S rows toward d
        io->recv_data(s, buf.data(), (size_t)3 * n * sizeof(block));
        for (int loc = 0; loc < n; ++loc) {
          block *dst = agg + agg_row_index(nd, loc, d);
          dst[0] = dst[0] ^ buf[3 * loc];
          dst[1] = dst[1] ^ buf[3 * loc + 1];
          dst[2] = dst[2] ^ buf[3 * loc + 2];
        }
      }
      if constexpr (wrk) {                                         // s's T rows
        io->recv_data(s, tin.data(), tb);
        for (size_t i = 0; i < tb; ++i) tpk[i] ^= tin[i];
      } else if (s == 2) {
        io->recv_bool(2, (bool *)(rows.b.data() + base), n);
      }
    }
  } else {
    io->recv_data(nP, rows.Agg.data() + (size_t)3 * (nP - 1) * base,
                  (size_t)3 * (nP - 1) * n * sizeof(block));
    if constexpr (wrk) io->recv_data(nP, tpk.data(), tb);
    else io->recv_bool(2, (bool *)(rows.b.data() + base), n);
  }
  if constexpr (wrk) unpack_p1_rows(rows.T.data() + 3 * base, tpk.data(), (int64_t)3 * n, bits);
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_GARBLE_PASSES_GARBLE_TRANSPORT_H__
