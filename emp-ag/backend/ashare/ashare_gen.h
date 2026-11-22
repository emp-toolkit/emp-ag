#ifndef EMP_AG_BACKEND_ASHARE_ASHARE_GEN_H__
#define EMP_AG_BACKEND_ASHARE_ASHARE_GEN_H__
#include "emp-ag/backend/common/protocols.h"   // EchoBC, sampleRandom, check_MAC (debug)
#include "emp-ag/backend/common/runtime.h"            // parallel_for
#include "emp-tool/runtime/core/test_mode.h"   // emp::is_test_mode (production guard, ctor)
#include "emp-ag/backend/common/feq.h"     // enable_fs_pairs
#include "emp-ag/backend/common/fzero.h"   // fzero_xor
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/common/fs_hash.h"  // FsHash (FS/check digests)
#include "emp-ag/backend/common/profiling.h"
#include "emp-ag/backend/ashare/share.h"
#include "emp-ag/backend/ashare/cot.h"              // Cot, the choice of mint
#include "emp-ag/backend/ashare/softspoken_mint.h"   // SoftSpokenMint
#include "emp-ag/backend/ashare/silent_ferret_mint.h"   // SilentFerretMint
#include <algorithm>
#include <climits>
#include <cstdint>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

namespace emp::ag {

// The mint for a Cot (cot.h). What a mint offers is in softspoken_mint.h.
template <int nP, Cot C>
using MintFor = std::conditional_t<C == Cot::SilentFerret, SilentFerretMint<nP>,
                                   SoftSpokenMint<nP>>;

// The digest of check2's openings not yet agreed (every party's hash value, as this party
// received it), which every party must share; `any` is false when no check2 ran since the
// last take, and then there is nothing to agree (AShareGen::take_pending_check2).
struct PendingCheck2 {
	bool any = false;
	char view[FsHash::DIGEST_SIZE];
};

// The share generator as the triple layer sees it, the same whichever mint the session
// chose (AShareGen below implements it).
template <int nP>
class AShareSource {
 public:
	virtual ~AShareSource() = default;
	virtual block delta() const = 0;
	virtual void compute(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length) = 0;
	// compute(), with check2 left to the next fold_check2() (see AShareGen).
	virtual void compute_deferred(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length) = 0;
	virtual void fold_check2(block coin) = 0;
	virtual void maybe_flush_cot_check() = 0;
	// Take check2's pending view to agree on it inside an agreement the caller runs anyway.
	// The caller must then run that agreement: this clears the view, so settle_check2()
	// no longer sees it, and nothing else checks it.
	virtual PendingCheck2 take_pending_check2() = 0;
	// Agree on check2's pending view on its own (one round); a no-op if nothing is
	// pending.
	virtual void settle_check2() = 0;
};

// Π_aShare, the authenticated-share generator: each call mints fresh shares. check1 is the gadget-tail Δ-consistency check
// using pair-specific x^{me,j}; check2 is the share-consistency check (nP>2): every peer
// checks a MAC tag on a hash of each party's shares at once, and the parties agree on
// the hash values in the next agreement the protocol runs (see check2).
// The COTs come from a mint (softspoken_mint.h, silent_ferret_mint.h), one stream
// per peer and direction.
// The COT post-processing pins bit0(Δ)=1, bit0(K)=0 and bit0(M)=choice, so each
// draw gives M = K ⊕ choice · Δ. At nP=2 the single receiver's choice is x^me.
// At nP>2 every receiver draws its own choices r_j and the Fix exchange aligns
// them: the party samples x^me and sends each peer d_j = x^me ⊕ r_j, one bit per
// COT; the receiver sets M ^= d_j·e0 and the peer K ^= d_j·(Δ ⊕ e0). So bit0(K)=0,
// bit0(M)=x^me and M = K ⊕ x^me · Δ hold at every peer slot, and the share x^me_k
// is bit0(MAC[any non-self peer][k]).
//
// Two small implementation choices:
//
// (1) The F_mCOT extension is ext_len = length + pad + tail tuples per peer.
//     Positions [0, length) are the output aShares. At nP>2 the next
//     pad = kCheck2Pad tuples are check2's hiding shares, minted on every call
//     and dropped once check2 has run (see check2). The last tail = csp
//     s-tuples, minted on the first call only, are consumed by check1's gadget
//     packing (Δ-consistency, run once per session — the global keys are
//     fixed, so one check covers every batch).
//
// (2) check1's F_Zero is implemented via pairwise seed-and-expand under the
//     ideal-cipher assumption on the AES-based PRG, and runs in the ctor: its
//     masks are pairwise one-time pads, independent of the tail they mask, so
//     check1 itself needs no round for them.
//
// Public API:
//   - compute(MAC, KEY, length) — the full Π_aShare into caller-allocated SoA arrays.
//     Two phases: process_phase1 (COT extension + the one-time check1
//     Δ-consistency on the first call) then check2 (share consistency, nP>2 only),
//     seeded by an internal post-commitment sampleRandom; it leaves the view of its
//     opening pending.
//   - compute_deferred(MAC, KEY, length) / fold_check2(coin) — compute() with check2
//     left to a later coin, and check2 of every such draw at that coin.
//   - draw(n, out) — one-shot convenience: compute() into the reusable draw
//     scratch, transposed into caller's AoS bundles. At nP>2 every call also
//     mints check2's kCheck2Pad hiding shares, and the first call check1's
//     csp = 128 gadget tail; neither reaches the output. draw_soa(n, mac, key,
//     defer) gives the scratch itself, with check2 optionally deferred.
//   - maybe_flush_cot_check() — flush the deferred long-lived-COT consistency check
//     before a reveal (no-op when nothing was minted since the last flush).
//   - take_pending_check2() / settle_check2() — hand check2's pending view to another
//     agreement, or agree on it on its own (before garbling or a reveal).
template <int nP, class Mint = MintFor<nP, Cot::EMP_AG_COT>>
class AShareGen final : public AShareSource<nP> {
 public:
	// Δ_me, the party's global MAC key, fixed by the ctor. Every party's generator pins
	// two of its bits, and the layers above rely on both: bit 0 of every Δ_p is 1 (the
	// share encoding above), and bit 1 of the XOR of all of them is 1 (the leaky ANDs,
	// triple/laand.h, decode their d, and the evaluator b_γ, from that bit).
	block delta() const override { return Delta; }

 private:
	block Delta;
	NetIOMPGroup<nP> *grp = nullptr;   // caller-owned; its meshes carry the mint's lanes; null => one mesh
	NetIOMP<nP> *io;
	ThreadPool *pool;
	int party;
	block session_id;
	PRG prg;
	int csp = 128;
	GaloisFieldPacking packer;
	// check1 (gadget-tail Δ-consistency) runs ONCE per session: the
	// global keys are fixed at COT setup, so one check certifies them for every
	// later batch. Set true after the first process_phase1 runs the check.
	bool delta_checked_ = false;
	// check1's zero-sharing u^me (nP>2): ⊕_p u^p_k = 0 for every column k. Drawn in
	// the ctor, used once by check1.
	block check1_u_[nP];

	// check2's hiding shares per call at nP>2: one per bit of the 128-bit hash value
	// it opens (see check2).
	static constexpr int kCheck2Pad = 128;
	// The running digest of the views of check2's openings not yet agreed (every party's
	// bw as this party received it), and whether there is any.
	FsHash pending_check2_view_;
	bool pending_views_ = false;
	// Draws whose check2 waits for fold_check2(): their outputs where compute_deferred()
	// left them, and their own copy of their hiding shares.
	struct Deferred {
		const block *mac[nP + 1] = {}, *key[nP + 1] = {};
		std::vector<block> pad_mac[nP + 1], pad_key[nP + 1];
		int64_t n = 0;
	};
	std::vector<Deferred> deferred_;
	bool scratch_deferred_ = false;   // a deferred draw_soa() reads the draw scratch
	BlockVec draw_mac_[nP + 1], draw_key_[nP + 1];   // reused draw() scratch
	// x^me for the current call's Fix exchange (nP>2; grow-only).
	std::vector<uint8_t> fix_x_;
	int64_t cots_per_stream_ = 0;   // see cots_per_stream()
	std::unique_ptr<Mint> mint_;   // the COT streams, set up in the ctor body

 public:

	// `grp_in` (optional): a NetIOMPGroup whose mesh(0) == io. When non-null and
	// the backend is SoftSpoken, COT/aShare generation runs on
	// L lanes: the parent COT on mesh 0 + clones on meshes 1..L-1. null => the
	// single-mesh path (L == 1). `base_ot_kind` selects the public-key base OT
	// for each pair's primary direction; every party must select the same kind.
	// Optional planned sender/receiver counts bound each COT stream when its demand is
	// known; -1 keeps the ordinary unbounded streaming path. With SoftSpokenMint they
	// include the 128-COT bootstrap prefix and go to OTExtension::begin(n_ots),
	// letting a one-lane SoftSpoken stream shorten its terminal transfer; for every
	// pair, this party's sender count must equal its peer's receiver count and vice
	// versa, so one identical (sender, receiver) pair at every party is valid only when
	// the two counts are equal. With SilentFerretMint the two counts must be equal,
	// count only the pool's draws, and size every stream's prepay. `cot` supplies the
	// COT streams (cot_extension_factory.h), empty keeping the mint's own; only the
	// SoftSpoken mint takes supplied streams, on one lane.
	AShareGen(NetIOMP<nP> *io, ThreadPool *pool, int party,
			NetIOMPGroup<nP> *grp_in = nullptr,
			block session_id_in = zero_block,
			BaseOtKind base_ot_kind = BaseOtKind::CSW,
			int64_t planned_sender_cots = -1,
			int64_t planned_receiver_cots = -1,
			const CotExtensionFactory &cot = {})
		: io(io), pool(pool), party(party), session_id(session_id_in) {
			ag::validate_protocol_runtime(pool, party, nP);
			expecting(io != nullptr, "AShareGen: NetIOMP must not be null");
			expecting(io->party == party,
			          "AShareGen: NetIOMP party does not match pool party");
			expecting(grp_in == nullptr || (grp_in->size() >= 1 && &grp_in->mesh(0) == io),
			          "AShareGen: group mesh(0) must equal the pool NetIOMP");
			grp = grp_in;
			// A test-mode build (-DEMP_TEST_MODE=ON) makes emp-tool's default-constructed
			// PRGs deterministic, for wire-byte-identity tests only. If it leaks into a real
			// run every secret -- Delta, the COT choices, labels, the F_eq nonce --
			// becomes predictable and the c_gamma soundness (which rests on Delta staying
			// secret and random) collapses. Every construction path (session and raw backend)
			// funnels through this ctor, so refuse here unless a build explicitly opts in.
			// The trace_digest targets set -DEMP_AG_ALLOW_TEST_MODE.
#ifndef EMP_AG_ALLOW_TEST_MODE
			expecting(!emp::is_test_mode(),
			          "emp-ag: EMP_TEST_MODE is enabled -- randomness would be deterministic and "
			          "all secrets predictable. Refusing to run. This mode is for byte-identity "
			          "tests only; build with -DEMP_AG_ALLOW_TEST_MODE to override.");
#endif
			// Enable the IOChannel transcript hash on every pairwise channel and lane
			// before any COT traffic. The post-commitment coins fold every lane, so a
			// secondary mesh must not begin recording only after its rows are fixed.
			// No-op where a COT already enabled FS.
			enable_fs_pairs<nP>(io, party);
			if (grp != nullptr)
				for (int lane = 1; lane < grp->size(); ++lane)
					enable_fs_pairs<nP>(&grp->mesh(lane), party);

			// Init: pick Δ_me with two pinned bits:
			//   bit 0 of Δ — share-value encoding (always 1; lets bit0(M) carry
			//                the authenticated bit when bit0(K)=0).
			//   bit 1 of Δ — half-gate Λ_γ recovery: bit1(Δ_j)=1 for j≠1,
			//                bit1(Δ_1) = nP mod 2. So bit1(⊕_p Δ_p) = 1, which
			//                the leaky ANDs' decoding d = LSB1(⊕ s^p) and
			//                AGMPCSession's b_γ = LSB1(m_{γ,0}^2) both rely on.
			// The lemma checked at compile time, colocated with the pinning it
			// governs: the per-party bit-1 choices below must XOR to 1.
			static_assert([] {
				bool x = false;
				for (int p = 1; p <= nP; ++p) x ^= (p == 1) ? (nP % 2 == 1) : true;
				return x;
			}(), "Delta pinning: bit1 of the XOR of all parties' Delta must be 1");
			bool tmp[128];
			prg.random_bool(tmp, 128);
			tmp[0] = true;
			if (party == 1) tmp[1] = (nP % 2 == 1);
			else tmp[1] = true;

			// The COT streams: base OTs, bootstrap, and (SoftSpoken) lanes.
			mint_ = std::make_unique<Mint>(io, pool, party, grp, session_id, base_ot_kind,
			                               planned_sender_cots, planned_receiver_cots, tmp, cot);
			Delta = mint_->delta();
			cots_per_stream_ = mint_->bootstrap_cots();

			// check1's F_Zero, ahead of the tail it will mask (see (2) above).
			for (int k = 0; k < nP; ++k) check1_u_[k] = zero_block;
			if constexpr (nP > 2) {
				BlockVec fz_scratch;   // nP blocks, once per session
				fzero_xor<nP>(io, &prg, pool, party, check1_u_, nP, fz_scratch);
			}
		}

	// Flush the deferred COT consistency check before a reveal; no-op when
	// nothing was minted since the last flush.
	void maybe_flush_cot_check() override {
		mint_->maybe_flush_check();
	}

	// COTs drawn so far from each COT stream, any bootstrap prefix included
	// (SoftSpokenMint's 128 COTs). Every stream, toward every peer and in both directions, draws the
	// same count, so a run's final value is the planned count for the same run.
	int64_t cots_per_stream() const { return cots_per_stream_; }

	// Hand the pending view to an agreement the caller runs anyway
	// (SymmetricOpenCheck::agree, whose check_result() aborts unless every party handed in
	// the same one). Every deferred draw must be folded first. The caller must then run
	// that agreement: the view is cleared here, so settle_check2() no longer sees it.
	PendingCheck2 take_pending_check2() override {
		expecting(deferred_.empty(), "AShareGen: check2 view taken with deferred draws not yet folded");
		PendingCheck2 p;
		p.any = std::exchange(pending_views_, false);
		pending_check2_view_.digest(p.view);   // and resets
		return p;
	}

	// Agree on check2's pending view on its own: one round, this party's digest to every
	// peer and every peer's back, aborting on any mismatch. Two honest parties compare
	// over their own channel, so a party that sent them different hash values is caught.
	// No-op when nothing is pending. Call before garbling with, or revealing anything
	// computed from, shares whose view no other agreement took. A deferred draw's view
	// joins the pending one only at fold_check2(), so every deferred draw must be folded
	// first.
	void settle_check2() override {
		expecting(deferred_.empty(), "AShareGen: settle_check2() with deferred draws not yet folded");
		if (!pending_views_) return;
		const PendingCheck2 pending = take_pending_check2();
		char recv[nP + 1][FsHash::DIGEST_SIZE];
		vector<future<void>> res;
		for (int p = 1; p <= nP; ++p) if (p != party) {
			res.push_back(pool->enqueue([this, &pending, p]() {
				io->send_data(p, pending.view, FsHash::DIGEST_SIZE);
				io->flush(p);
			}));
			res.push_back(pool->enqueue([this, &recv, p]() {
				io->recv_data(p, recv[p], FsHash::DIGEST_SIZE);
			}));
		}
		joinNclean(res);
		for (int p = 1; p <= nP; ++p) if (p != party)
			expecting(memcmp(recv[p], pending.view, FsHash::DIGEST_SIZE) == 0,
			          "cheat aShare: parties saw different consistency values\n");
	}

	// The full Π_aShare. On entry MAC[i]/KEY[i] may have any size; compute() grows them
	// for check2's hiding shares (nP>2) and check1's gadget tail (first call), then
	// shrinks back to length (preserving capacity). The output share x^me_k is implicit in
	// bit0(MAC[any non-self peer][k]) — no separate share buffer. Two phases:
	// process_phase1 (COT extension + the one-time check1) then check2 (universal-hash
	// MAC check, nP>2 only).
	void compute(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length) override {
		constexpr int pad = (nP > 2) ? kCheck2Pad : 0;
		expecting(length >= 0, "AShareGen: negative length");
		expecting((int64_t)length + pad <= INT_MAX, "auth_share: padded length overflow");
		process_phase1(MAC, KEY, length + pad);

		// check2 verifies every party holds the same bits toward every peer — only
		// meaningful for nP>2. At nP=2 there is a single peer, so it is vacuous and the
		// deferred COT consistency check (flush_cot_check before reveal) provides
		// malicious security, as in KRRW. The seed is sampled after MAC/KEY are
		// committed so the adversary can't adapt to it. check2 covers the hiding
		// shares after [0, length); they are never used again.
		if constexpr (nP > 2) {
			block seed = sampleRandom<nP>(io, &prg, pool, party, session_id);
			Check2Segment g;
			for (int i = 1; i <= nP; ++i) if (i != party) {
				g.mac[i] = MAC[i].data();
				g.key[i] = KEY[i].data();
				g.pad_mac[i] = MAC[i].data() + length;
				g.pad_key[i] = KEY[i].data() + length;
			}
			g.n = length;
			check2(seed, &g, 1);
			for (int i = 1; i <= nP; ++i) if (i != party) {
				MAC[i].resize(length);
				KEY[i].resize(length);
			}
		}

#ifdef EMP_AG_DEBUG_CHECKS
		// DEBUG ONLY — never ship: check_MAC broadcasts each party's Delta in the clear, which
		// lets any party forge MACs and defeats the c_gamma MACCheck (whose soundness rests on
		// Delta staying local). The compile-time warning guards against enabling it in a real build.
#warning "EMP_AG_DEBUG_CHECKS transmits Delta in the clear (check_MAC) -- DO NOT enable in production"
		check_MAC(io, MAC, KEY, Delta, length, party);
#endif
	}

	// compute(), but with check2 left to the next fold_check2(): no coin and nothing sent
	// for it now; this draw's hiding shares are kept, and its outputs are read where
	// compute() leaves them. The caller keeps those arrays, changing them only by
	// corrections that every party applies alike from public values (a leaky AND's opened
	// d, a cut-and-choose candidate's opened z ^ r), until the fold. At nP = 2 there is no
	// check2, and this is compute().
	void compute_deferred(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length) override {
		expecting(length >= 0, "AShareGen: negative length");
		if constexpr (nP == 2) {
			compute(MAC, KEY, length);
		} else {
			expecting((int64_t)length + kCheck2Pad <= INT_MAX, "auth_share: padded length overflow");
			process_phase1(MAC, KEY, length + kCheck2Pad);
			Deferred d;
			d.n = length;
			for (int i = 1; i <= nP; ++i) if (i != party) {
				d.pad_mac[i].assign(MAC[i].begin() + length, MAC[i].begin() + length + kCheck2Pad);
				d.pad_key[i].assign(KEY[i].begin() + length, KEY[i].begin() + length + kCheck2Pad);
				MAC[i].resize(length);
				KEY[i].resize(length);
				d.mac[i] = MAC[i].data();
				d.key[i] = KEY[i].data();
			}
			deferred_.push_back(std::move(d));
#ifdef EMP_AG_DEBUG_CHECKS
			check_MAC(io, MAC, KEY, Delta, length, party);
#endif
		}
	}

	// check2 of every draw since the last fold, under coefficients from `coin`, which every
	// party drew after the last of those draws: one fold, one hash value and one tag to
	// every peer, every peer's tag checked at once, and the view joins the pending one.
	// No-op with nothing deferred (and at nP = 2).
	void fold_check2(block coin) override {
		if (deferred_.empty()) return;
		const block seed = RO("emp-ag:ashare-check2", coin).squeeze_block();
		std::vector<Check2Segment> segs(deferred_.size());
		for (size_t s = 0; s < deferred_.size(); ++s) {
			Deferred &d = deferred_[s];
			for (int i = 1; i <= nP; ++i) if (i != party) {
				segs[s].mac[i] = d.mac[i];
				segs[s].key[i] = d.key[i];
				segs[s].pad_mac[i] = d.pad_mac[i].data();
				segs[s].pad_key[i] = d.pad_key[i].data();
			}
			segs[s].n = d.n;
		}
		check2(seed, segs.data(), (int)segs.size());
		deferred_.clear();
		scratch_deferred_ = false;
	}

 private:
	// Phase 1: COT extension (+ the one-time check1), no check2.
	// On entry, MAC[i]/KEY[i] may have any size; on return they are exactly
	// `length` blocks each, with MAC = KEY ⊕ x^me · Δ and bit0(MAC) = x^me
	// across all peers (honest case). On the first call only, the csp gadget
	// tail is minted and consumed by check1 (Δ-consistency, once per session).
	void process_phase1(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length) {
		// COT-Extend: ext_len = length + tail random tuples per peer,
		// tail = csp on the first call (the csp s-tuples check1 packs through the
		// gadget) and 0 afterwards. The Δ-consistency check runs once — the global
		// keys are fixed at COT setup — so later batches mint no tail.
		// check1 (Δ-consistency across pairs) is only meaningful for nP>2: at nP=2
		// there is a single pair, so it is vacuous and the deferred COT check
		// substitutes. So nP=2 mints no gadget tail and runs no
		// check1.
		const bool do_delta_check = (nP > 2) && !delta_checked_;
		const int tail = do_delta_check ? csp : 0;
		expecting((int64_t)length + tail <= INT_MAX, "auth_share: ext_len overflow");
		int ext_len = length + tail;
		for (int i = 1; i <= nP; ++i) if (i != party) {
			MAC[i].resize(ext_len);
			KEY[i].resize(ext_len);
		}

		// Fix exchange (nP>2). Every receiver draws its own choices, so the party
		// samples x^me for the corrected positions [0, length) -- the outputs and
		// check2's hiding shares -- and the mint sends each peer d = x^me ⊕ choice,
		// one bit per COT, on that peer's channel. The receiver sets MAC ^= d·e0 and the peer KEY ^= d·(Δ ⊕ e0),
		// so bit0(KEY) = 0, bit0(MAC) = x^me and MAC = KEY ⊕ x^me·Δ hold at every
		// peer slot. The check1 tail [length, ext_len) keeps its pair-specific
		// choices. A party whose corrections disagree across peers holds different
		// bits toward them, which check2 catches. At nP=2 the receiver's choice is
		// x^me and nothing is sent.
		if constexpr (nP > 2) {
			if (fix_x_.size() < (size_t)length) fix_x_.resize((size_t)length);
			prg.random_bool(fix_x_.data(), length);
		}
		const int nfix = (nP > 2) ? length : 0;
		const block dxor = Delta ^ bit0_mask;
#ifdef AG_PROFILE
		int64_t _cot0 = io->count();
#endif
		mint_->draw(MAC, KEY, ext_len, nfix, nfix > 0 ? fix_x_.data() : nullptr, dxor);
		cots_per_stream_ += ext_len;
#ifdef AG_PROFILE
		g_ag_cot_bytes += (uint64_t)(io->count() - _cot0);
#endif

		// check1: certify Δ-consistency once, on the csp gadget tail, before it
		// is dropped. One check covers every later batch (same fixed global keys
		// from the long-lived COTs).
		if (do_delta_check) {
			check1(MAC, KEY, length);
			delta_checked_ = true;
		}

		// Drop the sacrificial tail; output region is [0, length).
		for (int i = 1; i <= nP; ++i) if (i != party) {
			MAC[i].resize(length);
			KEY[i].resize(length);
		}
	}

	// check2: every party must hold the same bits toward every peer. Each party opens a
	// hash of its shares, h(x) = Σ_k c_k·x_k, with coefficients c_k drawn after the
	// shares -- PRG(`seed`) on the outputs [0, length), X^0..X^127 on the kCheck2Pad
	// hiding shares after them (X^k is block bit k, as in check1's packing). It sends
	// every peer j the hash value bw = h(x) and the tag h(MAC[j]) = Σ_k c_k·MAC[j][k] on
	// it, and checks every peer's tag against its own keys on that peer's shares,
	// h(KEY[j]) ⊕ bw_j·Δ. bw is public, so without the hiding shares the parties' bw would
	// give away 128 GF(2)-linear equations on the shared bits, e.g. on input masks, whose
	// Λ = λ ⊕ input is public; the hiding bits add a uniform one-time pad to each bw.
	//
	// A verifier checks only the bits a party holds toward it, so the tags bind a party to
	// one set of bits only if it sent every peer the same bw. bw goes out without an echo
	// of its own; every party's view of the opening -- each party's bw as received --
	// feeds pending_check2_view_ instead, and a later agreement aborts unless all parties
	// report the same view digest: the AND gates' open check (take_pending_check2 +
	// SymmetricOpenCheck::agree) or settle_check2(). With one bw per party, a party whose
	// tags all pass holds the same bits toward every peer, or has forged a MAC: on the
	// outputs except with probability 2^-128 over the coefficients; on the hiding shares
	// of one draw always, as a sum of distinct X^k is not zero. Draws checked together
	// reuse X^0..X^127, so their hiding bits can cancel one another; that costs nothing,
	// as hiding shares are never used.
	//
	// Every party is held to its own bits, as the leaky ANDs' security argument assumes
	// (each party's share is one bit, whichever peer it is authenticated to). It costs
	// 2(n-1) multiplications per share: n-1 tags out, and n-1 folds of the keys to check
	// the tags in. The shares are used before their view is agreed, which still comes
	// before any garbling or reveal; the input open in between publishes Λ = λ ⊕ input,
	// which the owner's own share masks whatever bits any other party holds.
	static block gadget_power_(int k) {   // X^k: block bit k
		return (k < 64) ? makeBlock(0, 1ULL << k) : makeBlock(1ULL << (k - 64), 0);
	}

	// One draw's shares for check2: outputs at mac[j][0, n) and key[j][0, n), and its
	// kCheck2Pad hiding shares at pad_mac[j] and pad_key[j].
	struct Check2Segment {
		const block *mac[nP + 1] = {}, *key[nP + 1] = {};
		const block *pad_mac[nP + 1] = {}, *pad_key[nP + 1] = {};
		int64_t n = 0;
	};
	// One worker's part of check2: the hash value, and for every peer j the tag on it
	// (folding MAC[j]) and the fold of KEY[j] that checks j's tag, unreduced.
	struct Check2Fold {
		block bw, t_lo[nP + 1], t_hi[nP + 1], e_lo[nP + 1], e_hi[nP + 1];
		Check2Fold() {
			bw = zero_block;
			for (int j = 0; j <= nP; ++j) t_lo[j] = t_hi[j] = e_lo[j] = e_hi[j] = zero_block;
		}
		// Coefficient c on share k: one multiplication per peer for its MAC, one for its key.
		void add(const block &c, const block *const mac[nP + 1], const block *const key[nP + 1],
		         int64_t k, int party, int any_peer) {
			block l, h;
			for (int j = 1; j <= nP; ++j) if (j != party) {
				mul128(c, mac[j][k], &l, &h);
				t_lo[j] = t_lo[j] ^ l;
				t_hi[j] = t_hi[j] ^ h;
				mul128(c, key[j][k], &l, &h);
				e_lo[j] = e_lo[j] ^ l;
				e_hi[j] = e_hi[j] ^ h;
			}
			bw = bw ^ (c & select_mask[getLSB(mac[any_peer][k])]);
		}
		void merge(const Check2Fold &o) {
			bw = bw ^ o.bw;
			for (int j = 0; j <= nP; ++j) {
				t_lo[j] = t_lo[j] ^ o.t_lo[j];
				t_hi[j] = t_hi[j] ^ o.t_hi[j];
				e_lo[j] = e_lo[j] ^ o.e_lo[j];
				e_hi[j] = e_hi[j] ^ o.e_hi[j];
			}
		}
	};

	// check2 over one or more draws. The outputs of all of them take coefficients from
	// PRG(`seed`) in draw order, a draw's output k at PRG position (its first position + k),
	// so a draw checked alone gets PRG position k for its output k; the
	// hiding shares of every draw take X^0..X^127 (a sum of distinct X^k is still never
	// zero within one draw, and several draws' hiding bits only add to the pad on bw).
	void check2(block seed, const Check2Segment *segs, int nsegs) {
		const int any_peer = (party == 1) ? 2 : 1;
		std::vector<int64_t> start((size_t)nsegs + 1, 0);   // each draw's first position
		for (int s = 0; s < nsegs; ++s) start[(size_t)s + 1] = start[(size_t)s] + segs[s].n;
		const int64_t total = start[(size_t)nsegs];
		// One pass over the outputs, width-split across the pool. The coefficients are
		// streamed in batches that stay in cache; PRG position k is coefficient k
		// whichever worker produces it.
		PRG prg2(&seed);
		const int W = std::max(1, (int)pool->size());
		const int64_t width = std::max<int64_t>(1, (total + W - 1) / W);
		const int nr = (int)((total + width - 1) / width);
		std::vector<Check2Fold> part((size_t)nr + 1);
		vector<future<void>> fold_res;
		for (int r = 0; r < nr; ++r) {
			const int64_t lo = r * width, hi = std::min(lo + width, total);
			fold_res.push_back(pool->enqueue([this, &prg2, segs, &start, &part, r, lo, hi,
			                                  any_peer]() {
				Check2Fold f;
				PRG p = prg2.fork_at((uint64_t)lo);
				alignas(16) block cb[64];
				int s = (int)(std::upper_bound(start.begin(), start.end(), lo) - start.begin()) - 1;
				for (int64_t base = lo; base < hi; base += 64) {
					const int m = (int)std::min<int64_t>(64, hi - base);
					p.random_block(cb, m);
					for (int t = 0; t < m; ++t) {
						const int64_t pos = base + t;
						while (pos >= start[(size_t)s + 1]) ++s;
						f.add(cb[t], segs[s].mac, segs[s].key, pos - start[(size_t)s], party, any_peer);
					}
				}
				part[(size_t)r] = f;
			}));
		}
		{   // the hiding shares, small: here while the pool folds the outputs
			Check2Fold f;
			for (int s = 0; s < nsegs; ++s)
				for (int k = 0; k < kCheck2Pad; ++k)
					f.add(gadget_power_(k), segs[s].pad_mac, segs[s].pad_key, k, party, any_peer);
			part[(size_t)nr] = f;
		}
		joinNclean(fold_res);
		Check2Fold all;
		for (int r = 0; r <= nr; ++r) all.merge(part[(size_t)r]);
		const block bw = all.bw;
		block tag_to[nP + 1], key_fold[nP + 1];
		for (int j = 1; j <= nP; ++j) if (j != party) {
			tag_to[j] = reduce(all.t_lo[j], all.t_hi[j]);
			key_fold[j] = reduce(all.e_lo[j], all.e_hi[j]);
		}

		// Open bw to every peer, with no echo of its own (see above), and its tag.
		block out_to[nP + 1];
		for (int peer = 1; peer <= nP; ++peer) out_to[peer] = bw;
#ifdef EMP_AG_TEST_FLIP_BW
		// TEST-ONLY (never in production): party 2 sends party 3 a different bw than it
		// sends everyone else. Party 3's check of party 2's tag must abort.
		if constexpr (nP >= 3) if (party == 2) out_to[3] = out_to[3] ^ makeBlock(0, 1);
#endif
#ifdef EMP_AG_TEST_TWO_WORLD
		// TEST-ONLY (never in production): party 2, built with EMP_AG_TEST_SPLIT_CHOICE so
		// that its bits toward party 3 differ from those toward everyone else, sends each
		// peer the fold of the bits it holds toward that peer. Every tag then passes; only
		// the agreement on the view catches it.
		if (party == 2) {
			PRG q(&seed);
			for (int peer = 1; peer <= nP; ++peer) out_to[peer] = zero_block;
			for (int s = 0; s < nsegs; ++s)
				for (int64_t k = 0; k < segs[s].n; ++k) {
					block c;
					q.random_block(&c, 1);
					for (int peer = 1; peer <= nP; ++peer) if (peer != party)
						out_to[peer] = out_to[peer] ^ (c & select_mask[getLSB(segs[s].mac[peer][k])]);
				}
			for (int s = 0; s < nsegs; ++s)
				for (int k = 0; k < kCheck2Pad; ++k) {
					const block c = gadget_power_(k);
					for (int peer = 1; peer <= nP; ++peer) if (peer != party)
						out_to[peer] = out_to[peer] ^ (c & select_mask[getLSB(segs[s].pad_mac[peer][k])]);
				}
		}
#endif
		block bw_recv[nP + 1], tag_recv[nP + 1];
		vector<future<void>> res;
		for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
			res.push_back(pool->enqueue([this, &out_to, &tag_to, peer]() {
				io->send_data(peer, &out_to[peer], sizeof(block));
				io->send_data(peer, &tag_to[peer], sizeof(block));
				io->flush(peer);
			}));
			res.push_back(pool->enqueue([this, &bw_recv, &tag_recv, peer]() {
				io->recv_data(peer, &bw_recv[peer], sizeof(block));
				io->recv_data(peer, &tag_recv[peer], sizeof(block));
			}));
		}
		joinNclean(res);
		// Every peer's tag on its bw, under this party's keys on its shares.
		for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
			block want;
			gfmul(bw_recv[peer], Delta, &want);
			want = want ^ key_fold[peer];
			expecting(cmpBlock(&tag_recv[peer], &want, 1), "cheat aShare: MAC tag mismatch\n");
		}
		// This party's view of the opening, every party's bw in party order.
		for (int p = 1; p <= nP; ++p)
			pending_check2_view_.put(p == party ? &bw : &bw_recv[p], sizeof(block));
		pending_views_ = true;
	}

	// check1: gadget-tail Δ-consistency check, in three rounds: broadcast y, commit to z,
	// open z, with F_Zero's masks drawn in the ctor (check1_u_). Each broadcast is agreed
	// in the round after it: the commitments carry the digest of every party's view of y,
	// which every party checks before anything is opened, and the openings carry the
	// digest of the commitments. The openings need no agreement of their own, as each is
	// checked against a commitment the parties have agreed on.
	void check1(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length) {
		// Pack the csp s-tuple tail through the gadget g = (1, X, …,
		// X^{λ-1}) to get pair-specific x^{me,j} ∈ F_{2^λ} (one per peer).
		//   Mx[j] = M_j[x^{me,j}] from MAC tail
		//   Kx[j] = K_me[x^{j,me}] from KEY tail
		//   xv[j] = x^{me,j}        from bit0 of MAC[j] tail (carries choice)
		block Mx[nP + 1], Kx[nP + 1], xv[nP + 1];
		for (int i = 1; i <= nP; ++i) if (i != party) {
			packer.packing(&Mx[i], MAC[i].data() + length);
			packer.packing(&Kx[i], KEY[i].data() + length);
			// ⟨g, s⟩ = ∑ s_k · X^k packs the 128 choice bits into a 128-bit
			// field element; bit_k of the block is s_k. Read s_k from bit0
			// of the MAC tail entry directly.
			bool tail_bits[128];
			for (int k = 0; k < 128; ++k)
				tail_bits[k] = getLSB(MAC[i][length + k]);
			xv[i] = bool_to_block(tail_bits);
		}
		Mx[party] = zero_block;
		Kx[party] = zero_block;
		xv[party] = zero_block;  // x^{me,me} := 0

		// y^me_k = x^{me,k} ⊕ u^me_k, with u^me from F_Zero (⊕_p u^p_k = 0 for every
		// column k) and x^{me,me} := 0, so the k+1==me column is just u^me_k. Index k
		// (0-based) here corresponds to column k+1 (1-indexed parties).
		block y_me[nP];
		for (int k = 0; k < nP; ++k)
			y_me[k] = xv[k + 1] ^ check1_u_[k];

		EchoBC<nP> echo(io, pool, party);
		block y_storage[nP + 1][nP];
		block *y_view[nP + 1];
		for (int p = 1; p <= nP; ++p) y_view[p] = y_storage[p];
		echo.all_bcast(y_me, nP, y_view);   // round 1

		// y_j = ⊕_p y^p_j (column sum). By zero-share, y_j = ⊕_{p≠j} x^{p,j}.
		// Build z^me with z^me_j = M_j[x^{me,j}] for j ≠ me and
		// z^me_me = ⊕_{j≠me} K_me[x^{j,me}] ⊕ y_me · Δ_me. Commit via a hash digest.
		block y_global[nP];
		for (int k = 0; k < nP; ++k) {
			y_global[k] = zero_block;
			for (int p = 1; p <= nP; ++p) y_global[k] ^= y_view[p][k];
		}

		block z[nP + 1];
		for (int i = 1; i <= nP; ++i) z[i] = Mx[i];
		block tD;
		gfmul(y_global[party - 1], Delta, &tD);
		z[party] = tD;
		for (int i = 1; i <= nP; ++i) if (i != party) z[party] ^= Kx[i];

		struct DigestT { char d[FsHash::DIGEST_SIZE]; };
		DigestT z_dgst[nP + 1];
		role_bound_commitment(z_dgst[party].d, session_id,
		                      "emp-ag:ashare-delta", party,
		                      z + 1, nP * sizeof(block));
		echo.all_bcast_agree(z_dgst[party], z_dgst,   // round 2, agreeing on y
		                     "cheat check1: parties saw different y\n");

		// Open z^me; verify ⊕_p z^p_j = 0 for every column j.
		// Columns where j = some party p collapse via MAC = KEY ⊕ x · Δ_p
		// to a Δ-consistency identity that holds iff Δ_p is consistent across
		// p's COT instances (and the y-construction is faithful).
		block z_storage[nP + 1][nP];
		block *z_recv[nP + 1];
		for (int i = 1; i <= nP; ++i) z_recv[i] = z_storage[i];
		echo.all_bcast_agree(z + 1, nP, z_recv,   // round 3, agreeing on the commitments
		                     "cheat check1: parties saw different commitments\n");
		for (int peer = 1; peer <= nP; ++peer) {
			char chk[FsHash::DIGEST_SIZE];
			role_bound_commitment(chk, session_id, "emp-ag:ashare-delta",
			                      peer, z_recv[peer], nP * sizeof(block));
			expecting(memcmp(chk, z_dgst[peer].d, FsHash::DIGEST_SIZE) == 0,
			          "cheat check1: commit mismatch\n");
		}

		for (int k = 0; k < nP; ++k) {
			block sum = zero_block;
			for (int p = 1; p <= nP; ++p) sum ^= z_recv[p][k];
			expecting(cmpBlock(&sum, &zero_block, 1), "cheat check1\n");
		}
	}

 public:
	// One-shot mint helper: run compute() into the reusable draw_mac_/draw_key_
	// scratch and transpose into AoS bundles. The underlying COT's own
	// correlation/consistency check is NOT run here — it is deferred to
	// maybe_flush_cot_check and flushed before any reveal, so a draw alone is not
	// the full end-to-end check. Prefer one large draw to many small ones — the
	// per-call fixed cost amortizes.
	void draw(int n, AShareBundleVec<nP> &out_bundle) {
		expecting(!scratch_deferred_, "AShareGen: draw() before the deferred draw_soa() was folded");
		BlockVec(&tmac)[nP + 1] = draw_mac_;
		BlockVec(&tkey)[nP + 1] = draw_key_;
		compute(tmac, tkey, n);
		out_bundle.resize(n);
		for (int i = 0; i < n; ++i) {
			AShareBundle<nP> &wb = out_bundle[i];
			for (int j = 1, k = 0; j <= nP; ++j) {
				if (j == party) continue;
				wb.mac(k) = tmac[j][i];
				wb.key(k) = tkey[j][i];
				++k;
			}
		}
	}

	// Mint n aShares and expose them in SoA form (per-peer MAC/KEY block arrays;
	// [party] entries unused) without draw()'s AoS bundle transpose, so the draw
	// walk seeds its wire slots straight from these. Pointers stay valid until the
	// next draw()/draw_soa() call (both use the grow-only draw_mac_/draw_key_
	// scratch). draw() serves the small AoS consumers (input authentication).
	// defer_check2 leaves this draw's check2 to the next fold_check2() (compute_deferred);
	// no other draw may use the scratch before that fold.
	void draw_soa(int n, const block *mac_out[nP + 1], const block *key_out[nP + 1],
	              bool defer_check2 = false) {
		expecting(!scratch_deferred_, "AShareGen: draw_soa() before the deferred one was folded");
		if (defer_check2) {
			compute_deferred(draw_mac_, draw_key_, n);
			scratch_deferred_ = (nP > 2);
		} else {
			compute(draw_mac_, draw_key_, n);
		}
		for (int j = 1; j <= nP; ++j) {
			mac_out[j] = draw_mac_[j].data();
			key_out[j] = draw_key_[j].data();
		}
	}
};

}  // namespace emp::ag
#endif // EMP_AG_BACKEND_ASHARE_ASHARE_GEN_H__
