// The share layer (backend/ashare) on its own: an AShareGen over every mint the build
// has, at ASHARE_NP parties. White-box: the parties reveal their Δ and their keys to each
// other, which a real session never does.
//
// For each pool:
//   - Δ: bit 0 of every Δ_p is 1, and bit 1 of the XOR of all of them is 1;
//   - every share, in both directions of every pair: i's MAC under j's key equals j's key
//     on i's bit ⊕ x^i·Δ_j, where x^i is bit 0 of i's MAC toward its first peer;
//   - a party's bit is bit 0 of every one of its MACs alike, and bit 0 of every key is 0;
//   - compute(), draw() (AoS) and draw_soa() each give such shares, and so do
//     compute_deferred() draws, an empty one among them, folded at one coin;
//   - cots_per_stream() counts every COT drawn: the length, check2's hiding shares at
//     nP > 2, and check1's tail on the first call;
//   - many draws of awkward sizes, enough for a SilentFerret stream to cross two rounds
//     (one in a Debug build, where every COT costs far more);
//   - check2's tags pass, and its views are agreed on their own and inside another open
//     check;
//   - with SilentFerret prepaid at nP = 2, drawing moves no bytes.
// SoftSpokenMint runs once; SilentFerretMint twice, unplanned (its streams prepay the next
// round on the wire when one runs out) and prepaid for the whole test. SilentFerretMint
// runs on ferret_b9, the smallest LPN set, whose rounds are short.
#include "emp-ag/backend/ashare/ashare_gen.h"
#include "emp-ag/backend/ashare/open_check.h"   // SymmetricOpenCheck
#include <array>
#include <cstdio>
#include <vector>
using namespace emp;
using namespace emp::ag;

#ifndef ASHARE_NP
#define ASHARE_NP 3
#endif
constexpr int nP = ASHARE_NP;
static int party;

// The awkward sizes compute() runs at, the draw() and draw_soa() sizes, and the long
// sequence: enough COTs for a ferret_b9 SilentFerret stream (2229 · 512 user COTs a
// round) to cross two rounds, or one in a Debug build.
static const int kSizes[] = {1, 128, 4095, 4096, 4097, 37200};
// Draws whose check2 waits for one fold, an empty one among them.
static const int kDeferredSizes[] = {1000, 0, 777, 4097};
constexpr int kDrawSize = 5000, kDrawSoaSize = 7000, kSettleSize = 4096;
#ifdef NDEBUG
constexpr int kLongSize = 100003, kLongDraws = 24, kRoundsCrossed = 2;
#else
constexpr int kLongSize = 100003, kLongDraws = 12, kRoundsCrossed = 1;
#endif

using FerretMint = SilentFerretMint<nP, emp::tuning::ferret_b9>;
constexpr PrimalLPNParameter kB9 = emp::tuning::ferret_b9;
constexpr int64_t kRoundCots = (kB9.t - kB9.refill_trees) << kB9.tree_depth;   // 2229 · 512
static_assert((int64_t)kLongSize * kLongDraws > kRoundsCrossed * kRoundCots,
              "ashare_test: the long sequence must cross the SilentFerret rounds it claims");

// This party's shares of one draw: mac[j][k] is its MAC on its bit k under peer j's key,
// key[j][k] its key on j's bit k.
struct View {
	const block *mac[nP + 1] = {};
	const block *key[nP + 1] = {};
};

// White-box: every party learns every Δ.
static void exchange_deltas(NetIOMP<nP> *io, block Delta, block all[nP + 1]) {
	all[party] = Delta;
	for (int p = 1; p <= nP; ++p) if (p != party) {
		io->send_data(p, &Delta, sizeof(block));
		io->flush(p);
	}
	for (int p = 1; p <= nP; ++p) if (p != party) io->recv_data(p, &all[p], sizeof(block));
}

static void check_pins(const block all[nP + 1]) {
	block x = zero_block;
	for (int p = 1; p <= nP; ++p) {
		expecting(getLSB(all[p]), "ashare_test: bit 0 of a Delta is not 1");
		x = x ^ all[p];
	}
	expecting(LSB1(x) == 1, "ashare_test: bit 1 of the XOR of every Delta is not 1");
}

// Check positions 0, stride, 2·stride, ... and n - 1 of one draw.
static void check_shares(NetIOMP<nP> *io, const block all[nP + 1], const View &v, int64_t n,
                         int64_t stride) {
	if (n == 0) return;
	std::vector<int64_t> pos;
	for (int64_t k = 0; k < n; k += stride) pos.push_back(k);
	if (pos.back() != n - 1) pos.push_back(n - 1);
	const int m = (int)pos.size();
	const int first = (party == 1) ? 2 : 1;   // the peer whose MAC gives this party's bit
	for (int64_t k : pos)
		for (int j = 1; j <= nP; ++j) if (j != party) {
			expecting(getLSB(v.mac[j][k]) == getLSB(v.mac[first][k]),
			          "ashare_test: a party's bit differs across its peers");
			expecting(!getLSB(v.key[j][k]), "ashare_test: bit 0 of a key is not 0");
		}
	// Every ordered pair (owner i, verifier j), in one order at every party: j sends i its
	// keys on i's bits, and i checks its MACs under j's key.
	std::vector<block> keys((size_t)m);
	for (int i = 1; i <= nP; ++i)
		for (int j = 1; j <= nP; ++j) if (i != j) {
			if (party == j) {
				for (int t = 0; t < m; ++t) keys[(size_t)t] = v.key[i][pos[(size_t)t]];
				io->send_data(i, keys.data(), (size_t)m * sizeof(block));
				io->flush(i);
			} else if (party == i) {
				io->recv_data(j, keys.data(), (size_t)m * sizeof(block));
				for (int t = 0; t < m; ++t) {
					const int64_t k = pos[(size_t)t];
					const block want =
						keys[(size_t)t] ^ (select_mask[getLSB(v.mac[first][k])] & all[j]);
					expecting(cmpBlock(&want, &v.mac[j][k], 1),
					          "ashare_test: a MAC does not match its key");
				}
			}
		}
}

// The COTs one call draws from every stream: its length, check2's hiding shares at
// nP > 2, and check1's tail on the session's first call at nP > 2.
static int64_t cots_of(int n, bool first) {
	return n + (nP > 2 ? 128 : 0) + ((nP > 2 && first) ? 128 : 0);
}

// Every COT this test draws from each stream, after setup.
static int64_t total_cots(int long_draws) {
	int64_t total = 0;
	bool first = true;
	auto add = [&](int n) { total += cots_of(n, first); first = false; };
	for (int n : kSizes) add(n);
	for (int n : kDeferredSizes) add(n);
	add(kDrawSize);
	add(kDrawSoaSize);
	for (int r = 0; r < long_draws; ++r) add(kLongSize);
	add(kSettleSize);
	return total;
}

template <class Pool>
struct Run {
	NetIOMP<nP> *io;
	Pool &ap;
	block all[nP + 1];
	int64_t expect = 0;   // cots_per_stream() after the calls so far
	int64_t moved = 0;    // bytes the draws moved
	bool first = true;

	Run(NetIOMP<nP> *io_, Pool &ap_) : io(io_), ap(ap_) {
		exchange_deltas(io, ap.delta(), all);
		check_pins(all);
		expect = ap.cots_per_stream();
	}
	void counted_(int n) {
		expect += cots_of(n, first);
		first = false;
		expecting(ap.cots_per_stream() == expect,
		          "ashare_test: cots_per_stream() does not count every COT drawn");
	}
	void compute(int n, int64_t stride) {
		BlockVec MAC[nP + 1], KEY[nP + 1];
		const int64_t c0 = io->count();
		ap.compute(MAC, KEY, n);
		moved += io->count() - c0;
		counted_(n);
		View v;
		for (int j = 1; j <= nP; ++j) if (j != party) {
			expecting(MAC[j].size() == (size_t)n && KEY[j].size() == (size_t)n,
			          "ashare_test: compute() returned the wrong length");
			v.mac[j] = MAC[j].data();
			v.key[j] = KEY[j].data();
		}
		check_shares(io, all, v, n, stride);
	}
	// Several draws with check2 deferred, then one fold of all of them at a coin every
	// party holds (honest shares pass under any coefficients), then every share checked.
	void deferred(block coin) {
		constexpr int kN = (int)(sizeof(kDeferredSizes) / sizeof(kDeferredSizes[0]));
		std::vector<std::array<BlockVec, nP + 1>> mac(kN), key(kN);   // live until the fold
		const int64_t c0 = io->count();
		for (int s = 0; s < kN; ++s) {
			ap.compute_deferred(mac[(size_t)s].data(), key[(size_t)s].data(), kDeferredSizes[s]);
			counted_(kDeferredSizes[s]);
		}
		ap.fold_check2(coin);
		moved += io->count() - c0;
		for (int s = 0; s < kN; ++s) {
			const int n = kDeferredSizes[s];
			View v;
			for (int j = 1; j <= nP; ++j) if (j != party) {
				expecting(mac[(size_t)s][j].size() == (size_t)n &&
				              key[(size_t)s][j].size() == (size_t)n,
				          "ashare_test: compute_deferred() returned the wrong length");
				v.mac[j] = mac[(size_t)s][j].data();
				v.key[j] = key[(size_t)s][j].data();
			}
			check_shares(io, all, v, n, 1);
		}
	}
	void draw(int n) {   // AoS bundles
		AShareBundleVec<nP> bundles;
		const int64_t c0 = io->count();
		ap.draw(n, bundles);
		moved += io->count() - c0;
		counted_(n);
		expecting(bundles.size() == (size_t)n, "ashare_test: draw() returned the wrong length");
		std::vector<block> mac[nP + 1], key[nP + 1];
		View v;
		for (int j = 1; j <= nP; ++j) if (j != party) {
			const int s = peer_slot(party, j);
			mac[j].resize((size_t)n);
			key[j].resize((size_t)n);
			for (int k = 0; k < n; ++k) {
				mac[j][(size_t)k] = bundles[(size_t)k].mac(s);
				key[j][(size_t)k] = bundles[(size_t)k].key(s);
			}
			v.mac[j] = mac[j].data();
			v.key[j] = key[j].data();
		}
		check_shares(io, all, v, n, 1);
	}
	void draw_soa(int n) {   // pointers into the pool's scratch, valid until its next draw
		const block *mac[nP + 1] = {}, *key[nP + 1] = {};
		const int64_t c0 = io->count();
		ap.draw_soa(n, mac, key);
		moved += io->count() - c0;
		counted_(n);
		View v;
		for (int j = 1; j <= nP; ++j) if (j != party) {
			v.mac[j] = mac[j];
			v.key[j] = key[j];
		}
		check_shares(io, all, v, n, 1);
	}
};

template <class Mint>
static void exercise(NetIOMP<nP> *io, ThreadPool *pool, const char *name, block sid,
                     int64_t plan, int long_draws, bool silent) {
	AShareGen<nP, Mint> ap(io, pool, party, nullptr, sid, BaseOtKind::CSW, plan, plan);
	io->flush();
	Run<AShareGen<nP, Mint>> run(io, ap);
	for (int n : kSizes) run.compute(n, 1);
	run.deferred(sid ^ makeBlock(0xc0, 0x1));
	run.draw(kDrawSize);
	run.draw_soa(kDrawSoaSize);
	for (int r = 0; r < long_draws; ++r) run.compute(kLongSize, 997);

	// check2's views so far are agreed on their own; the next call's go into another open
	// check's agreement. Neither may abort with honest shares.
	ap.maybe_flush_cot_check();
	ap.settle_check2();
	run.compute(kSettleSize, 1);
	const auto pending = ap.take_pending_check2();
	expecting(pending.any == (nP > 2), "ashare_test: check2 left no view pending at nP > 2");
	PRG prg;
	SymmetricOpenCheck<nP> check(io, pool, party, ap.delta(), sid ^ makeBlock(0, 1), &prg,
	                             nullptr, "emp-ag:ashare-test");
	if (pending.any) check.agree(pending.view);
	check.check_result();

	if (silent)
		expecting(run.moved == 0, "ashare_test: a prepaid SilentFerret draw moved bytes");
	if (party == 1)
		std::printf("  %-28s %10lld COTs per stream, draws moved %lld bytes\n", name,
		            (long long)ap.cots_per_stream(), (long long)run.moved);
}

int main(int argc, char **argv) {
	party = parse_party(argv, nP);
	const int port = peer_port();
	if (party > nP) return 0;
	NetIOMP<nP> io(party, port);
	ThreadPool pool(ag::default_pool_size(nP));
	if (party == 1) std::printf("ashare_test: nP=%d\n", nP);

	// SoftSpokenMint draws no rounds, so a few long draws are enough.
	exercise<SoftSpokenMint<nP>>(&io, &pool, "SoftSpokenMint", makeBlock(0xa5, 1), -1, 3, false);
	exercise<FerretMint>(&io, &pool, "SilentFerretMint, unplanned", makeBlock(0xa5, 2), -1,
	                     kLongDraws, false);
	exercise<FerretMint>(&io, &pool, "SilentFerretMint, prepaid", makeBlock(0xa5, 3),
	                     total_cots(kLongDraws), kLongDraws, nP == 2);
	if (party == 1) std::printf("ashare_test: GOOD\n");
	return 0;
}
