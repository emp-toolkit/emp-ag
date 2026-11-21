// The SilentFerret mint's joint fold (backend/ashare/joint_lpn.h) against
// emp-ot's Lpn: for random leaves and LPN secrets of every stream a party holds, folding
// them all at once over the transposed table must give, stream by stream, what
// Lpn<AuthValueFerret, 10>::compute_slice gives for the same tree position of the same
// seed. That is what lets both ends of a stream agree on the user trees' matrix. Local;
// no parties.
#include "emp-ag/backend/ashare/joint_lpn.h"
#include "emp-ot/common/lpn.h"
#include "emp-ot/ot_extension/ferret/ferret.h"   // AuthValueFerret
#include <cstdio>
#include <cstring>
#include <vector>
using namespace emp;

template <int nP>
static void check(int64_t k, int64_t chunk, uint64_t G) {
	constexpr int K = 2 * (nP - 1);   // the streams a party holds
	constexpr int kRow = ag::lpn_row_blocks<K>;
	PRG prg;
	std::vector<BlockVec> S(K), E(K), ref(K);
	for (int s = 0; s < K; ++s) {
		S[s].resize((size_t)k);
		E[s].resize((size_t)chunk);
		prg.random_block(S[s].data(), k);
		prg.random_block(E[s].data(), chunk);
		ref[s] = E[s];
	}
	BlockVec table((size_t)k * kRow);
	for (int64_t i = 0; i < k; ++i)
		for (int s = 0; s < K; ++s) table[(size_t)i * kRow + s] = S[s][(size_t)i];
	block seed;
	prg.random_block(&seed, 1);

	Lpn<AuthValueFerret, 10> lpn((int)k);
	const uint64_t bpc = lpn.blocks_per_chunk(chunk);
	BlockVec words((size_t)bpc);
	ag::lpn_tree_words(seed, G, bpc, words.data());
	block *o[K];
	for (int s = 0; s < K; ++s) o[s] = E[s].data();
	ag::lpn_fold_rows<K, kRow>(o, reinterpret_cast<const uint32_t *>(words.data()), chunk,
	                           table.data(), (uint32_t)(k - 1));

	for (int s = 0; s < K; ++s) {
		PRG p(&seed);
		p.seek(G * bpc);
		lpn.compute_slice(p, reinterpret_cast<AuthValueFerret *>(ref[s].data()),
		                  reinterpret_cast<const AuthValueFerret *>(S[s].data()), chunk);
		expecting(std::memcmp(ref[s].data(), E[s].data(), (size_t)chunk * sizeof(block)) == 0,
		          "ashare_joint_fold: the joint fold differs from emp-ot's Lpn");
	}
	std::printf("  joint fold == Lpn: nP=%d, %d streams, row of %d blocks, tree %llu\n", nP, K,
	            kRow, (unsigned long long)G);
}

int main() {
	// ferret_b12's shapes: an LPN secret of 2^19 entries and 4096-row trees, at a tree of
	// round 0 and one of a later round.
	const int64_t k = int64_t(1) << 19, chunk = 4096;
	check<2>(k, chunk, 7);
	check<3>(k, chunk, 4200ULL * 3 + 11);
	check<4>(k, chunk, 5);
	check<5>(k, chunk, 4200ULL * 61 + 4058);
	std::printf("ashare_joint_fold: GOOD\n");
	return 0;
}
