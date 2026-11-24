#ifndef EMP_AG_BACKEND_ASHARE_SILENT_FERRET_MINT_H__
#define EMP_AG_BACKEND_ASHARE_SILENT_FERRET_MINT_H__
//
// SilentFerretMint: the share pool's COT streams (the mint interface is in softspoken_mint.h)
// as one SilentFerret instance per peer and direction, whose outputs are folded together.
// A Ferret COT is E + A·S: the cGGM leaves E of a tree plus a public sparse matrix A times
// the stream's LPN secret S. Every stream of the session uses one public A for its user
// trees, so a party folds its 2(n-1) streams in one pass: each output row's indices are
// drawn once, and each index reads one row of a table that holds that index of every
// stream's S.
//
// Setup is SilentFerret's own: each stream bootstraps from its own public-key base OT and
// prepays its planned COTs (begin(n)), corrections and consistency checks included, so
// nothing is left to check later. After that the mint drives the streams through
// SilentFerret's lower-level path (produce_range_leaves, lpn_secret, next_round), in
// lockstep: the pool draws the same count from every stream, so all of them are always at
// the same round and tree.
//   - At each round the mint copies every stream's S into the table, transposed: row i
//     holds S_s[i] for every stream s, in share-slot order (MAC, then key, per peer slot).
//   - A draw fills whole trees: each stream's leaves go straight into the caller's array,
//     and the fold adds A·S in place. The rest of a draw's last tree, already folded,
//     serves the next draw.
//   - When a round's trees run out, next_round() rolls every stream. Its refill trees
//     fold inside SilentFerret, with that stream's own matrix.
// The rows of A for user trees come from a seed derived from the session id, in the word
// layout of emp-ot's Lpn (lpn_tree_words), so both ends of every stream fold with the same A.
//
// Shared choices (nP > 2): a party's receiver streams all draw their choice bits from one
// secret seed, and every stream's own matrix (the refill trees') from one public seed, through
// emp-ot's Ferret::set_choice_seed. In lockstep, every receiver stream then gives the same
// choice bit at each position, so a share bit x^me is bit 0 of any of its MACs and no Fix
// exchange is sent. Only the check1 tail needs choices of its own per peer, which split_tail
// gives it (see AShareGen::process_phase1).
//
// Plans: one count for every stream (sender == receiver), counting the COTs the pool
// draws, with no bootstrap prefix; the mint prepays one tree more, since it draws whole
// trees.
//
// kLpn is every stream's LPN parameter set: ferret_b12 unless the instantiation names
// another. A smaller set has shorter rounds.
//
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/common/runtime.h"            // peer_order, parallel_for
#include "emp-ag/backend/ashare/cot_extension_factory.h"
#include "emp-ag/backend/ashare/fix.h"         // the Fix exchange's two halves
#include "emp-ag/backend/ashare/joint_lpn.h"   // the joint fold and its index words
#include "emp-ag/backend/ashare/share.h"       // peer_slot
#include "emp-ot/base_ot/base_ot_select.h"  // BaseOtKind / make_base_ot
#include "emp-ot/common/lpn.h"              // Lpn: the index stream's blocks per tree
#include "emp-ot/common/table_alloc.h"      // LpnTableBlockVec (line-aligned, huge pages)
#include "emp-ot/ot_extension/ferret/silent_ferret.h"
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#ifndef EMP_AG_FERRET_THREADS
#define EMP_AG_FERRET_THREADS 2
#endif

namespace emp::ag {

template <int nP, const PrimalLPNParameter &kLpn = emp::tuning::ferret_b12>
class SilentFerretMint {
 public:
	// Streams: 2s receives from the peer of slot s (MACs), 2s + 1 sends to it (keys).
	static constexpr int K = 2 * (nP - 1);
	// Every receiver stream gives the same choice bit at each position (see above).
	static constexpr bool kSharedChoices = nP > 2;
	// The table's row stride in blocks (joint_lpn.h).
	static constexpr int kRow = lpn_row_blocks<K>;

	SilentFerretMint(NetIOMP<nP> *io, ThreadPool *pool, int party, NetIOMPGroup<nP> * /*grp*/,
	                 block session_id, BaseOtKind base_ot_kind, int64_t planned_sender_cots,
	                 int64_t planned_receiver_cots, const bool delta_bits[128],
	                 const CotExtensionFactory &cot = {})
		: io_(io), pool_(pool), party_(party) {
		expecting(!cot.supplied(), "COT streams: supplied streams need the SoftSpoken mint");
		expecting(planned_sender_cots == planned_receiver_cots,
		          "AShareGen: with SilentFerret every stream has one plan (sender == receiver)");
		expecting(planned_sender_cots >= -1,
		          "AShareGen: planned COT count must be -1 or nonnegative");
		// Stream ids, one per ordered pair, derived in one global order so that both ends
		// of a stream agree.
		block sid_send[nP + 1], sid_recv[nP + 1];
		SessionID root(session_id);
		for (int lo = 1; lo <= nP; ++lo)
			for (int hi = lo + 1; hi <= nP; ++hi) {
				const block up = root.derive().value();     // lo sends to hi
				const block down = root.derive().value();   // hi sends to lo
				if (party == lo) { sid_send[hi] = up; sid_recv[hi] = down; }
				else if (party == hi) { sid_send[lo] = down; sid_recv[lo] = up; }
			}
		// Shared choices: one secret choice seed for this party's receiver streams, and one
		// public seed for every stream's own matrix.
		block choice_seed = zero_block;
		const block stream_lpn_seed = RO("emp-ag:ashare-stream-lpn", session_id).squeeze_block();
		if constexpr (kSharedChoices) PRG().random_block(&choice_seed, 1);
		// Each stream bootstraps from its own public-key base OT, on the same channels as
		// SoftSpokenMint's lane 0.
		for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
			const int s = peer_slot(party, peer);
			const bool me_smaller = party < peer;
			NetIO *ch_send = io->get(peer, /*swap=*/!me_smaller);
			NetIO *ch_recv = io->get(peer, /*swap=*/me_smaller);
			peer_[2 * s] = peer_[2 * s + 1] = peer;
			chan_[2 * s] = ch_recv;
			chan_[2 * s + 1] = ch_send;
			st_[2 * s] = std::make_unique<SilentFerret>(
				BOB, ch_recv, /*malicious=*/true, kLpn,
				make_base_ot(base_ot_kind, ch_recv), EMP_AG_FERRET_THREADS);
			st_[2 * s]->set_sid(sid_recv[peer]);
			st_[2 * s + 1] = std::make_unique<SilentFerret>(
				ALICE, ch_send, /*malicious=*/true, kLpn,
				make_base_ot(base_ot_kind, ch_send), EMP_AG_FERRET_THREADS);
			st_[2 * s + 1]->set_sid(sid_send[peer]);
			if constexpr (kSharedChoices) {
				st_[2 * s]->set_choice_seed(&choice_seed, stream_lpn_seed);
				st_[2 * s + 1]->set_choice_seed(nullptr, stream_lpn_seed);
			}
			bool split_delta[128];
			st_[2 * s + 1]->set_delta(test_split_delta(delta_bits, party, peer, split_delta));
		}
		chunk_ = st_[0]->chunk_size();
		const int64_t plan = (planned_sender_cots < 0) ? -1 : planned_sender_cots + chunk_;
		for_each_stream_([plan](SilentFerret *st, NetIO *ch) {
			if (plan >= 0) st->begin(plan);
			else           st->begin();
			ch->flush();
		});
		began_ = true;
		Delta_ = st_[1]->Delta;
		t_ = st_[0]->param.t;
		k_ = st_[0]->param.k;
		cap_ = st_[0]->round_capacity();
		bpc_ = Lpn<AuthValueFerret, 10>((int)k_).blocks_per_chunk(chunk_);
		seed_ = RO("emp-ag:ashare-lpn", session_id).squeeze_block();
		table_.resize((size_t)k_ * kRow);
		for (int s = 0; s < K; ++s) tail_[s].resize((size_t)chunk_);
	}

	~SilentFerretMint() {
		if (began_)
			for (auto &st : st_) st->end();
	}
	SilentFerretMint(const SilentFerretMint &) = delete;
	SilentFerretMint &operator=(const SilentFerretMint &) = delete;

	block delta() const { return Delta_; }
	static constexpr int64_t kPrefix = 0;   // no bootstrap prefix is drawn from the streams
	int64_t bootstrap_cots() const { return kPrefix; }
	void maybe_flush_check() {}   // every stream was checked when it was prepaid
	// One stream's draw on its own: not offered, since every draw applies the joint LPN
	// step to all streams at once.
	void draw_cots(int, bool, block *, int64_t) {
		expecting(false, "AShareGen::draw_cots: one-direction draws need the SoftSpoken mint");
	}

	// The streams' choices are shared (or, at nP = 2, there is one receiver), so no Fix
	// exchange runs: nfix is 0 and xme unused.
	void draw(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int ext_len, int nfix,
	          const uint8_t * /*xme*/, [[maybe_unused]] block dxor) {
		expecting(nfix == 0, "SilentFerretMint: the streams' choices are shared; no Fix exchange");
		block *out[K];
		for (int s = 0; s < K; s += 2) {
			out[s] = MAC[peer_[s]].data();
			out[s + 1] = KEY[peer_[s]].data();
		}
		int64_t done = 0;
		if (tail_n_ > 0) {   // the folded rest of the last tree
			const int64_t take = std::min<int64_t>(tail_n_, ext_len);
			for (int s = 0; s < K; ++s)
				std::memcpy(out[s], tail_[s].data() + tail_off_, (size_t)take * sizeof(block));
			tail_off_ += take;
			tail_n_ -= take;
			done = take;
		}
		while (done < ext_len) {
			if (tree_ == cap_) next_round_();
			ensure_table_();
			const int64_t left = ext_len - done;
			const int64_t whole = std::min<int64_t>(left / chunk_, cap_ - tree_);
			block *dst[K];
			if (whole > 0) {
				for (int s = 0; s < K; ++s) dst[s] = out[s] + done;
				produce_and_fold_(dst, tree_, whole);
				tree_ += whole;
				done += whole * chunk_;
			} else {   // part of one tree: fold all of it, hand out the part
				for (int s = 0; s < K; ++s) dst[s] = tail_[s].data();
				produce_and_fold_(dst, tree_, 1);
				tree_ += 1;
				for (int s = 0; s < K; ++s)
					std::memcpy(out[s] + done, tail_[s].data(), (size_t)left * sizeof(block));
				tail_off_ = left;
				tail_n_ = chunk_ - left;
				done = ext_len;
			}
		}
#ifdef EMP_AG_TEST_SPLIT_CHOICE
		test_split_choice_(MAC, KEY, ext_len, dxor);
#endif
#if defined(EMP_AG_TEST_SPLIT_CHOICE) && defined(EMP_AG_TEST_SPLIT_FIRST_DRAW)
		++test_draws_;
#endif
	}

	// Choices of its own toward every peer on [off, off + n), for the check1 tail: toward
	// each peer the Fix exchange's halves (fix.h) with an independent random target, so the
	// tail's bits differ across peers. One bit per COT per peer.
	void split_tail(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int off, int n, block dxor) {
		PRG prg;
		const uint8_t *target[nP + 1] = {};
		for (int i = 1; i <= nP; ++i) if (i != party_) {
			if (tail_x_[i].size() < (size_t)n) tail_x_[i].resize((size_t)n);
			prg.random_bool(tail_x_[i].data(), n);
			target[i] = tail_x_[i].data();
		}
		fix_(MAC, KEY, off, n, target, dxor);
	}

 private:
	NetIOMP<nP> *io_;
	ThreadPool *pool_;
	int party_;
	std::unique_ptr<SilentFerret> st_[K];
	int peer_[K];
	NetIO *chan_[K];
	bool began_ = false;
	block Delta_;
	int64_t chunk_ = 0, t_ = 0, k_ = 0, cap_ = 0;   // tree size, trees and LPN size per round, user trees per round
	uint64_t bpc_ = 0;                               // index-stream blocks per tree
	block seed_;                                     // the user trees' public matrix
	LpnTableBlockVec table_;                         // the transposed S of the current round
	uint64_t table_round_ = ~0ULL;
	int64_t tree_ = 0;                               // the current round's next tree
	BlockVec tail_[K];                               // the last tree, folded
	int64_t tail_off_ = 0, tail_n_ = 0;              // its unused part
	std::vector<uint8_t> fix_out_[nP + 1], fix_in_[nP + 1];
	std::vector<uint8_t> tail_x_[nP + 1];            // split_tail's targets, per peer
#if defined(EMP_AG_TEST_SPLIT_CHOICE) && defined(EMP_AG_TEST_SPLIT_FIRST_DRAW)
	int test_draws_ = 0;   // TEST-ONLY: draws so far
#endif

	// Every stream, in the canonical order: peer-major, sender then receiver.
	template <typename F>
	void for_each_stream_(F op) {
		vector<future<void>> res;
		for (int peer : peer_order(party_, nP)) {
			const int s = peer_slot(party_, peer);
			SilentFerret *snd = st_[2 * s + 1].get();
			SilentFerret *rcv = st_[2 * s].get();
			NetIO *cs = chan_[2 * s + 1], *cr = chan_[2 * s];
			res.push_back(pool_->enqueue([op, snd, cs]() { op(snd, cs); }));
			res.push_back(pool_->enqueue([op, rcv, cr]() { op(rcv, cr); }));
		}
		joinNclean(res);
	}

	// Roll every stream to its next round (live only past a prepaid batch).
	void next_round_() {
		for_each_stream_([](SilentFerret *st, NetIO *ch) {
			st->next_round();
			ch->flush();
		});
		tree_ = 0;
	}

	// Copy the current round's S of every stream into the table, once per round.
	void ensure_table_() {
		const uint64_t round = st_[0]->current_round();
		if (round == table_round_) return;
		const block *S[K];
		for (int s = 0; s < K; ++s) {
			expecting(st_[s]->current_round() == round, "SilentFerretMint: streams out of lockstep");
			S[s] = st_[s]->lpn_secret();
		}
		block *table = table_.data();
		const int64_t rows = k_;
		ag::parallel_for(pool_, (int)rows, [table, &S](int lo, int hi) {
			for (int64_t i = lo; i < hi; ++i)
				for (int s = 0; s < K; ++s) table[(size_t)i * kRow + s] = S[s][i];
		});
		table_round_ = round;
	}

	// One worker's index words, bpc_ blocks.
	static block *words_scratch_(size_t n) {
		thread_local BlockVec v;
		if (v.size() < n) v.resize(n);
		return v.data();
	}

	// Trees [tree0, tree0 + n) of the current round into dst[s] + (i * chunk_): every
	// stream's leaves, then the joint fold, a tree at a time so its leaves stay in cache.
	void produce_and_fold_(block *const dst[K], int64_t tree0, int64_t n) {
		const uint64_t round = st_[0]->current_round();
		const block *table = table_.data();
		const uint32_t mask = (uint32_t)(k_ - 1);
		ag::parallel_for(pool_, (int)n, [&, round, table, mask](int lo, int hi) {
			block *words = words_scratch_((size_t)bpc_);
			for (int i = lo; i < hi; ++i) {
				const int64_t tree = tree0 + i;
				block *o[K];
				for (int s = 0; s < K; ++s) {
					o[s] = dst[s] + (int64_t)i * chunk_;
					st_[s]->produce_range_leaves(o[s], tree, 1);
				}
				lpn_tree_words(seed_, round * (uint64_t)t_ + (uint64_t)tree, bpc_, words);
				lpn_fold_rows<K, kRow>(o, reinterpret_cast<const uint32_t *>(words), chunk_,
				                       table, mask);
			}
		});
	}

	// The Fix exchange's halves on [off, off + n): each receiver stream's corrections toward
	// `target[peer]` go out on its channel, each sender stream takes its peer's on its own.
	void fix_(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int off, int n,
	          const uint8_t *const target[nP + 1], block dxor) {
		for (int i = 1; i <= nP; ++i) if (i != party_) {
			if (fix_out_[i].size() < (size_t)n) fix_out_[i].resize((size_t)n);
			if (fix_in_[i].size() < (size_t)n) fix_in_[i].resize((size_t)n);
		}
		vector<future<void>> res;
		for (int peer : peer_order(party_, nP)) {
			const int s = peer_slot(party_, peer);
			NetIO *cs = chan_[2 * s + 1], *cr = chan_[2 * s];
			block *KEYp = KEY[peer].data() + off;
			block *MACp = MAC[peer].data() + off;
			uint8_t *din = fix_in_[peer].data();
			uint8_t *dout = fix_out_[peer].data();
			const uint8_t *tp = target[peer];
			res.push_back(pool_->enqueue([cs, KEYp, din, n, dxor]() {
				cs->recv_bool(din, n);
				fix_sender_half(KEYp, n, din, dxor);
			}));
			res.push_back(pool_->enqueue([cr, MACp, dout, tp, n]() {
				fix_receiver_half(MACp, n, tp, dout, /*flip=*/false);
				cr->send_bool(dout, n);
				cr->flush();
			}));
		}
		joinNclean(res);
	}

#ifdef EMP_AG_TEST_SPLIT_CHOICE
	// TEST-ONLY (never in production): party 2 holds the complement of its bits toward
	// party 3, with valid MACs, as if party 3 had taken a correction d = 1 from it: party 2
	// flips bit 0 of its MACs from party 3, and party 3 adds Δ ⊕ e0 to its keys on party
	// 2's bits. Nothing is sent. With EMP_AG_TEST_SPLIT_FIRST_DRAW, the first draw only.
	void test_split_choice_(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int n, block dxor) {
		bool split = true;
#ifdef EMP_AG_TEST_SPLIT_FIRST_DRAW
		split = test_draws_ == 0;
#endif
		if constexpr (nP >= 3) {
			if (!split) return;
			if (party_ == 2)
				for (int k = 0; k < n; ++k) MAC[3][k] = MAC[3][k] ^ bit0_mask;
			if (party_ == 3)
				for (int k = 0; k < n; ++k) KEY[2][k] = KEY[2][k] ^ dxor;
		}
	}
#endif
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_ASHARE_SILENT_FERRET_MINT_H__
