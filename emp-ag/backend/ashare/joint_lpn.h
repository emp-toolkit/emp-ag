#ifndef EMP_AG_BACKEND_ASHARE_JOINT_LPN_H__
#define EMP_AG_BACKEND_ASHARE_JOINT_LPN_H__
//
// The LPN step of several Ferret streams at once, over one public matrix A (see
// silent_ferret_mint.h). Each stream's COTs are E + A·S: its cGGM leaves E plus A times
// its LPN secret S. With A shared, a party keeps every stream's S in one table, row i
// holding S_s[i] for every stream s, so each index of A reads one row for all streams.
//
#include "emp-tool/emp-tool.h"
#include <cstdint>

namespace emp::ag {

// A table row's stride in blocks for K streams: K, padded to whole 64-byte lines once a
// row passes one line, so no row straddles a line it does not need.
template <int K>
inline constexpr int lpn_row_blocks = (K <= 4) ? K : ((K + 3) / 4) * 4;

// The index words of one tree's output rows: the bpc blocks at position G·bpc of the PRG
// keyed by `seed`, where G = round·t + tree. Output row j of the tree reads words
// [10j, 10j + 10), each masked to [0, k): the layout of emp-ot's Lpn<AuthValueFerret, 10>,
// whose compute_slice over the tree consumes the same blocks.
inline void lpn_tree_words(const block &seed, uint64_t G, uint64_t bpc, block *words) {
	PRG prg(&seed);
	prg.seek(G * bpc);
	prg.random_block(words, (int64_t)bpc);
}

// Touch every 64-byte line of one table row ahead of its use.
template <int kRow>
inline void lpn_prefetch_row(const block *row) {
	for (int b = 0; b < kRow; b += 4) __builtin_prefetch(row + b, 0, 3);
}

// The joint fold: for each output row j < n_rows and every stream s < K,
// o[s][j] ^= XOR_{l < 10} table[(w[10j + l] & mask) * kRow + s].
template <int K, int kRow>
inline void lpn_fold_rows(block *const o[K], const uint32_t *w, int64_t n_rows,
                          const block *table, uint32_t mask) {
	constexpr int d = 10;       // indices per output row, as emp-ot's Ferret LPN
	constexpr int kAhead = 8;   // prefetch distance, in output rows
	for (int64_t j = 0; j < n_rows; ++j) {
		if (j + kAhead < n_rows) {
			const uint32_t *wa = w + (j + kAhead) * d;
			for (int l = 0; l < d; ++l)
				lpn_prefetch_row<kRow>(table + (size_t)(wa[l] & mask) * kRow);
		}
		block acc[K];
		for (int s = 0; s < K; ++s) acc[s] = o[s][j];
		const uint32_t *wj = w + j * d;
		for (int l = 0; l < d; ++l) {
			const block *row = table + (size_t)(wj[l] & mask) * kRow;
			for (int s = 0; s < K; ++s) acc[s] = acc[s] ^ row[s];
		}
		for (int s = 0; s < K; ++s) o[s][j] = acc[s];
	}
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_ASHARE_JOINT_LPN_H__
