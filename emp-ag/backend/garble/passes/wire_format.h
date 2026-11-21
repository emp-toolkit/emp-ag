#ifndef EMP_AG_BACKEND_GARBLE_PASSES_WIRE_FORMAT_H__
#define EMP_AG_BACKEND_GARBLE_PASSES_WIRE_FORMAT_H__
//
// The garbler <-> evaluator BYTE CONTRACT — the single source of every quantity the
// two ends of the streaming garble transport must derive identically: the
// streaming-window chunking (kGarbleChunk / garble_window_cap), the row indexing of
// the aggregated eval
// buffer (agg_row_index), and the chunk record layouts (GarbleChunk / EvalChunk).
// The on-wire byte stream is fully determined by these definitions plus the gate
// stream: garble_and_ship (garble/passes/garble.h) produces it and StreamEvaluatePass
// (garble/passes/evaluate.h) consumes it.
//
#include "emp-tool/runtime/core/block_vector.h"   // block, BlockVec
#include <cstddef>
#include <vector>

namespace emp::ag {

constexpr int kGarbleChunk = 1 << 16;

// Streaming-window cap in ANDs, shared by garble_and_ship and StreamEvaluatePass —
// both ends MUST derive identical chunk boundaries (the wire byte stream is the
// same either way; only flush points move). Per-slot rows scale with (nP-1) (the
// S rows / the co-aggregate), so past 9 parties the cap shrinks to hold the
// per-slot footprint roughly constant instead of letting the pipe grow linearly
// in n (at nP=128 an uncapped slot is ~390 MB). At nP <= 9 this is exactly
// kGarbleChunk.
template <int nP>
constexpr int garble_window_cap(int num_ands) {
  constexpr int cap0 = kGarbleChunk * 8 / (nP - 1 > 8 ? nP - 1 : 8);
  const int hi = cap0 < 1 ? 1 : cap0;
  return num_ands < 1 ? 1 : (num_ands < hi ? num_ands : hi);
}

// The half-gate hash's layout -- which (seed, gid) each (sender, gate, destination,
// input) hashes under, hence its keys and tweaks -- is the other half of this
// contract; it lives with its kernel in garble/halfgate.h (HalfGateHash).

// Flat index of row 0 of the 3-row (G/S) record for destination `dest` (in [2, nP])
// at window-local gate `loc` in the aggregated eval buffer (EvalChunk::Agg and the
// drain's ring aggregate). Producer (the drain fold in garble_and_ship) and consumer
// (StreamEvaluatePass::and_gate) index through this one definition.
inline int agg_row_index(int n_dests, int loc, int dest) {
  return (int)(3 * ((size_t)n_dests * loc + (dest - 2)));
}

struct GarbleChunk {
  int n = 0;                     // ANDs in this chunk
  BlockVec G;                    // 2*n G rows
  std::vector<BlockVec> S;       // S[j] = 3*n rows, for j in [2,nP], j != party
  std::vector<unsigned char> b;  // KRRW: n designated bits (party 2 only)
  BlockVec T;                    // WRK: 3*n rows toward P1, sent truncated
};

// A kGarbleChunk-sized window of the evaluator's garbled input. nP==2: the single
// garbler's half-gate rows G. nP>=3: the co-aggregated G+S vector Agg (garbler-row
// aggregation) -- garbler i's G and every s!=i garbler's
// S pre-XORed by the garblers into 3 rows per destination, so the O(n^2) S-cube collapses
// to O(n) here. Plus the designated bit b (from P2). The streaming evaluator's receiver
// fills these; the eval pass reads the pinned window at local offset loc.
template <int nP>
struct EvalChunk {
  int n = 0;
  BlockVec G;     // nP==2 only: the single garbler's 2 half-gate rows/AND, flat [2*loc + {0:La,1:Lb}]
  BlockVec Agg;   // nP>=3: 3 rows/dest, indexed [agg_row_index(nP-1, loc, i) + r], i in [2,nP], r in [0,2]
  std::vector<unsigned char> b;   // KRRW: [cap]
  BlockVec T;     // WRK: the garblers' rows toward P1, summed and truncated, flat [3*loc + r]
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_GARBLE_PASSES_WIRE_FORMAT_H__
