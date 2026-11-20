#ifndef EMP_AG_BACKEND_PREPROC_AUTH_SHARE_POOL_H__
#define EMP_AG_BACKEND_PREPROC_AUTH_SHARE_POOL_H__
#include "emp-ag/backend/crypto/protocols.h"   // EchoBC, sampleRandom, check_MAC (debug)
#include "emp-ag/backend/runtime.h"            // peer_order, lane_range, parallel_for
#include "emp-tool/runtime/core/test_mode.h"   // emp::is_test_mode (production guard, ctor)
#include "emp-ag/backend/crypto/feq.h"     // enable_fs_pairs
#include "emp-ag/backend/crypto/fzero.h"   // fzero_xor
#include "emp-ag/backend/netmp.h"
#include "emp-ag/backend/crypto/fs_hash.h"  // FsHash (FS/check digests)
#include "emp-ag/backend/profiling.h"
#include "emp-ot/base_ot/base_ot_select.h"  // BaseOtKind / make_base_ot
#include "emp-ot/ot_extension/iknp.h"
#include "emp-ot/ot_extension/ferret/ferret.h"
#include "emp-ot/ot_extension/softspoken/softspoken.h"
#include "emp-ag/backend/preproc/buffer_ot.h"   // BufferOT (one base OT per unordered pair)
#include "emp-tool/runtime/crypto/ccrh.h"        // CCRH (COT->ROT for the derived base OTs)
#include "emp-ag/backend/shares.h"
#include <algorithm>
#include <climits>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace emp::ag {


// Choose the OT extension backend used for the per-pair COT mesh.
// EMP_AG_OT_BACKEND selects the backend. The pool drives it through
// OTExtension's public API; SoftSpoken lane cloning and Ferret's shared LPN
// matrix seed are the only backend-specific calls. Candidates:
//   IKNP        — low setup, ~κ B/COT, fastest on small batches.
//   SoftSpoken<k> — k tunes compute vs. bandwidth (larger k sends fewer bytes
//                   but costs more AES per OT); default k=8 minimizes COT
//                   communication, the binding cost on bandwidth-bound and
//                   egress-metered links; a smaller k trades COT bytes for
//                   less AES compute.
//   Ferret      — ferret_b13 default; smallest steady-state bandwidth.
#ifndef EMP_AG_OT_BACKEND
#define EMP_AG_OT_BACKEND 1
#endif
#ifndef EMP_AG_SOFTSPOKEN_K
#define EMP_AG_SOFTSPOKEN_K 8
#endif
#if EMP_AG_OT_BACKEND == 0
using ConfiguredOTExt = emp::IKNP;
#elif EMP_AG_OT_BACKEND == 1
using ConfiguredOTExt = emp::SoftSpoken<EMP_AG_SOFTSPOKEN_K>;
#elif EMP_AG_OT_BACKEND == 2
using ConfiguredOTExt = emp::Ferret;
#else
#error "EMP_AG_OT_BACKEND must be 0=IKNP, 1=SoftSpoken, or 2=Ferret"
#endif

using OTExt = emp::OTExtension;

// Π_aShare. Despite the "Pool" in the class name, this type keeps no pool —
// each call mints fresh shares. check1 is the gadget-tail Δ-consistency check
// using pair-specific x^{me,j}; check2 is the universal-hash share check.
// Sampling x^me and the Fix exchange are collapsed into the COT itself: under
// the pinned-bit invariant bit0(Δ)=1, bit0(K)=0, bit0(M)=choice (enforced
// by COT post-processing), the receiver's choice IS x^me and the MAC
// relation M = K ⊕ x · Δ already holds straight out of rcot — no Fix
// exchange or KEY update is needed. The share x^me_k is recoverable as
// bit0(MAC[any non-self peer][k]).
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
// (2) FZero is implemented via pairwise seed-and-expand under
//     the ideal-cipher assumption on the AES-based PRG; see check1.
//
// Public API:
//   - compute(MAC, KEY, length) — the full Π_aShare into caller-allocated SoA arrays.
//     Two phases: process_phase1 (COT extension + the one-time check1
//     Δ-consistency on the first call) then check2 (universal-hash MAC check, nP>2
//     only), seeded by an internal post-commitment sampleRandom.
//   - draw(n, out) — one-shot convenience: compute() into the reusable draw
//     scratch, transposed into caller's AoS bundles. At nP>2 every call also
//     mints check2's kCheck2Pad hiding shares, and the first call check1's
//     csp = 128 gadget tail; neither reaches the output.
//   - maybe_flush_cot_check() — flush the deferred long-lived-COT consistency check
//     before a reveal (no-op when nothing was minted since the last flush).
template <int nP>
class AuthSharePool {
 public:
	// Δ_me, the party's global MAC key (pinned in the ctor). Public: TriplePool
	// mirrors it (Delta(abit.Delta)) so the two share one Δ.
	block Delta;

 private:
	// Each party holds both COT directions against every peer: abit1 is always
	// the local extension sender and abit2 is always the local receiver. Slot
	// [party] is unused. The ConfiguredOTExt alias at the top of
	// this file selects the backend (IKNP / SoftSpoken / Ferret); ctor
	// takes its role, channel, and owned base OT upfront, so we store
	// unique_ptrs and construct per-peer in the AuthSharePool ctor.
	std::unique_ptr<OTExt> abit1[nP + 1];   // lane 0 (sender role), mesh 0
	std::unique_ptr<OTExt> abit2[nP + 1];   // lane 0 (recv role),  mesh 0
	// Lanes 1..L-1: clone_lane copies of the parent COT (lane 0 = abit1/abit2)
	// running independent extensions on grp meshes 1..L-1, so one COT instance's
	// compute/transfer fills more cores. Declared AFTER the parents so member destruction tears
	// the clones (which borrow the parents' checked leaves) down FIRST. Empty on
	// the single-mesh path (L == 1).
	std::vector<std::unique_ptr<OTExt>> abit1_lane[nP + 1];
	std::vector<std::unique_ptr<OTExt>> abit2_lane[nP + 1];
	NetIOMPGroup<nP> *grp = nullptr;   // caller-owned; meshes 1..L-1 carry lane COT; null => L==1
	int L = 1;                          // agreed lane count; 1 = the single-mesh path
	NetIOMP<nP> *io;
	ThreadPool *pool;
	int party;
	block session_id;

	// Lane partition is the shared ag::lane_range (runtime.h) — peer-INDEPENDENT:
	// lane t owns [lo, hi) toward EVERY peer.
	// The mesh carrying lane t (lane 0 == io == grp->mesh(0)).
	NetIOMP<nP> *lane_mesh(int t) { return (t == 0) ? io : &grp->mesh(t); }
	// The COT instance for (peer, sender-role?, lane t).
	OTExt *cot(int peer, bool sender, int t) {
		if (t == 0) return (sender ? abit1[peer] : abit2[peer]).get();
		return (sender ? abit1_lane[peer][t - 1] : abit2_lane[peer][t - 1]).get();
	}
	// The channel for (peer, sender-role?, lane t) — the SAME smaller-party-dials
	// selector as the parent (abit1 sender: swap=!me_smaller; abit2 recv:
	// swap=me_smaller), only the MESH swaps by lane. Keeping the selector
	// identical is what makes clone_lane's role-based enable_fs land the same
	// send_first orientation as the parent on both ends.
	NetIO *cot_chan(int peer, bool sender, int t) {
		const bool me_smaller = party < peer;
		const bool swap = sender ? (!me_smaller) : me_smaller;
		return lane_mesh(t)->get(peer, swap);
	}
	PRG prg;
	int csp = 128;
	GaloisFieldPacking packer;
	// check1 (gadget-tail Δ-consistency) runs ONCE per session: the
	// global keys are fixed at COT setup, so one check certifies them for every
	// later batch. Set true after the first process_phase1 runs the check.
	bool delta_checked_ = false;

	// check2's hiding shares per call at nP>2: one per bit of the 128-bit value
	// it broadcasts (see check2).
	static constexpr int kCheck2Pad = 128;
	// check2 coefficient buffer: grow-only scratch reused across calls.
	BlockVec check2_coeff;
	BlockVec draw_mac_[nP + 1], draw_key_[nP + 1];   // reused draw() scratch
	bool cot_sessions_open = false;
	bool cots_minted_since_check = false;

 public:

	// `choice_seed_in` (optional): when non-null, all of this party's COT
	// receiver instances (abit2[peer]) seed their choice_prg from the same
	// block. With a shared choice seed, the choice bits Pi commits in
	// COT(i, j) are identical across j by construction, so x^me_k =
	// bit0(MAC[any_peer][k]) is automatically consistent across peers —
	// the r_choice/d exchange + K-update is unnecessary. When null,
	// we sample one internally; that's the default and gives the same
	// behavior. Pass an explicit seed only for determinism / testing.
	// `grp_in` (optional): a NetIOMPGroup whose mesh(0) == io. When non-null and
	// the backend is SoftSpoken, COT/aShare generation runs on
	// L lanes: the parent COT on mesh 0 + clones on meshes 1..L-1. null => the
	// single-mesh path (L == 1). `base_ot_kind` selects the public-key base OT
	// for each pair's primary direction; every party must select the same kind.
	// Optional planned sender/receiver counts include the 128-COT bootstrap prefix
	// and are forwarded to OTExtension::begin(n_ots), allowing a one-lane
	// SoftSpoken stream to shorten its terminal transfer. For every pair, this
	// party's sender count must equal its peer's receiver count and vice versa;
	// passing one identical (sender,receiver) pair at every party is therefore
	// valid only when the two counts are equal. -1 keeps the ordinary unbounded
	// streaming path.
	AuthSharePool(NetIOMP<nP> *io, ThreadPool *pool, int party,
			const block *choice_seed_in = nullptr,
			NetIOMPGroup<nP> *grp_in = nullptr,
			block session_id_in = zero_block,
			BaseOtKind base_ot_kind = BaseOtKind::CSW,
			int64_t planned_sender_cots = -1,
			int64_t planned_receiver_cots = -1)
		: io(io), pool(pool), party(party), session_id(session_id_in) {
			ag::validate_protocol_runtime(pool, party, nP);
			expecting(io != nullptr, "AuthSharePool: NetIOMP must not be null");
			expecting(io->party == party,
			          "AuthSharePool: NetIOMP party does not match pool party");
			expecting(grp_in == nullptr || (grp_in->size() >= 1 && &grp_in->mesh(0) == io),
			          "AuthSharePool: group mesh(0) must equal the pool NetIOMP");
			expecting(planned_sender_cots == -1 || planned_sender_cots >= 128,
			          "AuthSharePool: planned sender COT count must be -1 or include the 128-COT bootstrap prefix");
			expecting(planned_receiver_cots == -1 || planned_receiver_cots >= 128,
			          "AuthSharePool: planned receiver COT count must be -1 or include the 128-COT bootstrap prefix");
			expecting((planned_sender_cots < 0 && planned_receiver_cots < 0) ||
			              grp_in == nullptr || grp_in->size() == 1,
			          "AuthSharePool: counted COT plans require one lane");
			grp = grp_in;
			// A test-mode build (-DEMP_TEST_MODE=ON) makes emp-tool's default-constructed
			// PRGs deterministic, for wire-byte-identity tests only. If it leaks into a real
			// run every secret -- Delta, choice seeds, labels, the F_eq nonce --
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
			//                TriplePool's LaAND decoding d = LSB1(⊕ s^p) and
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

			// One public-key base OT per unordered pair: the higher-numbered
			// party's COT direction bootstraps normally, then supplies hashed
			// random OTs as the reverse direction's base OTs.
			block choice_seed;
			if (choice_seed_in) choice_seed = *choice_seed_in;
			else prg.random_block(&choice_seed, 1);
			dedup_bootstrap_pairs_(tmp, choice_seed, base_ot_kind,
			                       planned_sender_cots, planned_receiver_cots);

#if EMP_AG_OT_BACKEND == 1
			// SoftSpoken lanes clone the now-bootstrapped parents, including the
			// direction whose base OTs were derived above.
			if (grp != nullptr) {
				L = std::max(1, grp->size());
				if (L > 1) spawn_and_begin_lanes();
			}
#endif
		}

	~AuthSharePool() {
		if (cot_sessions_open)
			close_cot_sessions();
	}

 private:
	// Iterate EVERY (peer, direction, lane) COT instance in the canonical order
	// (peer-major, directions adjacent, lanes 0..L-1). Used for close/check,
	// which must span parent + all clones. For L == 1 this visits only the two
	// lane-0 parents.
	template <typename F>
	void for_each_cot_all(F op) {
		vector<future<void>> res;
		for (int peer : peer_order(party, nP))
			for (int t = 0; t < L; ++t) {
				OTExt *otS = cot(peer, true, t);   NetIO *chS = cot_chan(peer, true, t);
				OTExt *otR = cot(peer, false, t);  NetIO *chR = cot_chan(peer, false, t);
				res.push_back(pool->enqueue([op, otS, chS]() { op(otS, chS); }));
				res.push_back(pool->enqueue([op, otR, chR]() { op(otR, chR); }));
			}
		joinNclean(res);
	}

#if EMP_AG_OT_BACKEND == 1
	// After the parents are bootstrapped, spawn lanes 1..L-1 as clone_lane
	// copies on meshes 1..L-1 and begin() each (clones skip bootstrap; begin()
	// just enters a session + guards
	// FS on their fresh mesh channel). Salt = lane index t (never
	// peer-dependent). SoftSpoken-only (clone_lane is a SoftSpoken method).
	void spawn_and_begin_lanes() {
		for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
			abit1_lane[peer].resize(L - 1);
			abit2_lane[peer].resize(L - 1);
			for (int t = 1; t < L; ++t) {
				auto *send_parent = static_cast<ConfiguredOTExt *>(abit1[peer].get());
				auto *recv_parent = static_cast<ConfiguredOTExt *>(abit2[peer].get());
				abit1_lane[peer][t - 1] = send_parent->clone_lane(cot_chan(peer, true, t), (uint16_t)t);
				abit2_lane[peer][t - 1] = recv_parent->clone_lane(cot_chan(peer, false, t), (uint16_t)t);
			}
		}
		vector<future<void>> res;
		for (int peer = 1; peer <= nP; ++peer) if (peer != party)
			for (int t = 1; t < L; ++t) {
				OTExt *otS = cot(peer, true, t);   NetIO *chS = cot_chan(peer, true, t);
				OTExt *otR = cot(peer, false, t);  NetIO *chR = cot_chan(peer, false, t);
				res.push_back(pool->enqueue([otS, chS]() { otS->begin(); chS->flush(); }));
				res.push_back(pool->enqueue([otR, chR]() { otR->begin(); chR->flush(); }));
			}
		joinNclean(res);
	}
#endif

	std::unique_ptr<OTExt> make_cot_extension_(
			int role, NetIO *channel, std::unique_ptr<OT> base) {
		return std::make_unique<ConfiguredOTExt>(
			role, channel, /*malicious=*/true, std::move(base));
	}

	// Ferret normally derives its public LPN matrix from the pair-specific sid.
	// emp-ag instead needs every stream received by Pi to expose the same choice
	// vector, while keeping those pair/direction transcript ids distinct. Both
	// endpoints know the receiver identity, so install one session/receiver root
	// on the configured Ferret instance. Other backends already derive matching
	// choices directly from set_choice_seed and compile this helper to a no-op.
	void configure_shared_choice_matrix_(OTExt *ot, int receiver) {
#if EMP_AG_OT_BACKEND == 2
		const block root = RO("emp-ag:ferret:lpn-matrix", session_id)
			.absorb((uint64_t)receiver)
			.squeeze_block();
		static_cast<ConfiguredOTExt *>(ot)->set_lpn_matrix_seed(root);
#else
		(void)ot;
		(void)receiver;
#endif
	}

	// Bootstrap one direction per unordered pair with its normal public-key base
	// OT, then derive the reverse direction's 128 base OTs from CCR-hashed COTs.
	// The higher-numbered party is the primary sender. Both directions consume the
	// same 128-output prefix so every local receiver stream remains at an identical
	// offset across peers, preserving the shared-choice invariant for nP > 2.
	void dedup_bootstrap_pairs_(const bool* delta_me, const block& choice_seed,
			BaseOtKind base_ot_kind, int64_t planned_sender_cots,
			int64_t planned_receiver_cots) {
		constexpr int64_t K = 128;
		std::vector<BlockVec> primary((size_t)nP + 1);
		std::vector<block> primary_sid((size_t)nP + 1);
		std::vector<block> reverse_sid((size_t)nP + 1);
		// Derive every unordered pair's two directional child ids in one global
		// order. All parties execute the complete loop, so the endpoints of a
		// pair obtain identical ids even though their local peer iteration differs.
		// Distinct directions and distinct peers must never reuse a base-OT RO
		// domain.
		SessionID sid_root(session_id);
		for (int lo = 1; lo <= nP; ++lo)
			for (int hi = lo + 1; hi <= nP; ++hi) {
				const block p = sid_root.derive().value();
				const block r = sid_root.derive().value();
				if (party == lo) {
					primary_sid[(size_t)hi] = p;
					reverse_sid[(size_t)hi] = r;
				} else if (party == hi) {
					primary_sid[(size_t)lo] = p;
					reverse_sid[(size_t)lo] = r;
				}
			}
		vector<future<void>> res;

		// Phase 1: bootstrap and draw the canonical primary direction for every
		// pair. The barrier keeps no worker blocked in a reverse bootstrap while a
		// peer still needs that worker to make progress on another primary pair.
		for (int peer : peer_order(party, nP)) {
			primary[(size_t)peer].resize((size_t)K);
			res.push_back(pool->enqueue([this, peer, delta_me, &choice_seed,
			                                  base_ot_kind, planned_sender_cots,
			                                  planned_receiver_cots, &primary,
			                                  &primary_sid]() {
				const bool me_smaller = party < peer;
				NetIO* ch_send = io->get(peer, /*swap=*/!me_smaller);
				NetIO* ch_recv = io->get(peer, /*swap=*/me_smaller);
				if (!me_smaller) {
					// Higher party: primary sender.
					abit1[peer] = make_cot_extension_(
						ALICE, ch_send, make_base_ot(base_ot_kind, ch_send));
					abit1[peer]->set_sid(primary_sid[(size_t)peer]);
					configure_shared_choice_matrix_(abit1[peer].get(), peer);
					abit1[peer]->set_delta(delta_me);
					if (planned_sender_cots >= 0) abit1[peer]->begin(planned_sender_cots);
					else                          abit1[peer]->begin();
					ch_send->flush();
					abit1[peer]->next_n(primary[(size_t)peer].data(), K); ch_send->flush();
				} else {
					// Lower party: primary receiver.
					abit2[peer] = make_cot_extension_(
						BOB, ch_recv, make_base_ot(base_ot_kind, ch_recv));
					abit2[peer]->set_sid(primary_sid[(size_t)peer]);
					configure_shared_choice_matrix_(abit2[peer].get(), party);
					abit2[peer]->set_choice_seed(choice_seed);
					if (planned_receiver_cots >= 0) abit2[peer]->begin(planned_receiver_cots);
					else                            abit2[peer]->begin();
					ch_recv->flush();
					abit2[peer]->next_n(primary[(size_t)peer].data(), K); ch_recv->flush();
				}
			}));
		}
		joinNclean(res);

		// Phase 2: use each primary transcript to bootstrap its reverse direction,
		// then consume the matching prefix that keeps all receiver cursors aligned.
		res.clear();
		for (int peer : peer_order(party, nP)) {
			res.push_back(pool->enqueue([this, peer, delta_me, &choice_seed,
			                              planned_sender_cots, planned_receiver_cots,
			                              &primary, &reverse_sid]() {
				const bool me_smaller = party < peer;
				NetIO* ch_send = io->get(peer, /*swap=*/!me_smaller);
				NetIO* ch_recv = io->get(peer, /*swap=*/me_smaller);
				emp::CCRH ccrh;
				BlockVec reverse_prefix((size_t)K);
				if (!me_smaller) {
					std::vector<block> m0((size_t)K), m1((size_t)K);
					for (int64_t i = 0; i < K; ++i) {
						m0[(size_t)i] = ccrh.H(primary[(size_t)peer][(size_t)i]);
						m1[(size_t)i] = ccrh.H(
							primary[(size_t)peer][(size_t)i] ^ abit1[peer]->Delta);
					}
					abit2[peer] = make_cot_extension_(
						BOB, ch_recv,
						std::make_unique<BufferOT>(ch_recv, std::move(m0), std::move(m1)));
					abit2[peer]->set_sid(reverse_sid[(size_t)peer]);
					configure_shared_choice_matrix_(abit2[peer].get(), party);
					abit2[peer]->set_choice_seed(choice_seed);
					if (planned_receiver_cots >= 0) abit2[peer]->begin(planned_receiver_cots);
					else                            abit2[peer]->begin();
					ch_recv->flush();
					abit2[peer]->next_n(reverse_prefix.data(), K); ch_recv->flush();
				} else {
					std::vector<uint8_t> c((size_t)K);
					std::vector<block> mc((size_t)K);
					for (int64_t i = 0; i < K; ++i) {
						c[(size_t)i] = emp::getLSB(primary[(size_t)peer][(size_t)i]) ? 1 : 0;
						mc[(size_t)i] = ccrh.H(primary[(size_t)peer][(size_t)i]);
					}
					abit1[peer] = make_cot_extension_(
						ALICE, ch_send,
						std::make_unique<BufferOT>(ch_send, std::move(c), std::move(mc)));
					abit1[peer]->set_sid(reverse_sid[(size_t)peer]);
					configure_shared_choice_matrix_(abit1[peer].get(), peer);
					abit1[peer]->set_delta(delta_me);
					if (planned_sender_cots >= 0) abit1[peer]->begin(planned_sender_cots);
					else                          abit1[peer]->begin();
					ch_send->flush();
					abit1[peer]->next_n(reverse_prefix.data(), K); ch_send->flush();
				}
			}));
		}
		joinNclean(res);
		Delta = abit1[party == 1 ? 2 : 1]->Delta;
		cot_sessions_open = true;
		cots_minted_since_check = true;
	}

	void close_cot_sessions() {
		for_each_cot_all([](OTExt *ot, NetIO *ch) {
			ot->end();
			ch->flush();
		});
		cot_sessions_open = false;
		cots_minted_since_check = false;
	}

	void flush_cot_check() {
		if (!cot_sessions_open) return;
		for_each_cot_all([](OTExt *ot, NetIO *ch) {
			ot->check();
			ch->flush();
		});
		cots_minted_since_check = false;
	}
 public:
	// Flush the deferred COT consistency check before a reveal; no-op when
	// nothing was minted since the last flush.
	void maybe_flush_cot_check() {
		if (cots_minted_since_check)
			flush_cot_check();
	}

	// The full Π_aShare. On entry MAC[i]/KEY[i] may have any size; compute() grows them
	// for check2's hiding shares (nP>2) and check1's gadget tail (first call), then
	// shrinks back to length (preserving capacity). The output share x^me_k is implicit in
	// bit0(MAC[any non-self peer][k]) — no separate share buffer. Two phases:
	// process_phase1 (COT extension + the one-time check1) then check2 (universal-hash
	// MAC check, nP>2 only).
	void compute(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length) {
		constexpr int pad = (nP > 2) ? kCheck2Pad : 0;
		expecting((int64_t)length + pad <= INT_MAX, "auth_share: padded length overflow");
		process_phase1(MAC, KEY, length + pad);

		// check2 verifies the per-peer MACs agree across peers — only
		// meaningful for nP>2. At nP=2 there is a single peer, so it is vacuous and the
		// deferred COT consistency check (flush_cot_check before reveal) provides
		// malicious security, as in KRRW. The seed is sampled after MAC/KEY are
		// committed so the adversary can't adapt to it. check2 covers the hiding
		// shares after [0, length); they are never used again.
		if constexpr (nP > 2) {
			block seed = sampleRandom<nP>(io, &prg, pool, party, session_id);
			check2(seed, MAC, KEY, length);
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

		// No x^me sampling or Fix exchange: with the shared choice_prg seed set
		// in the ctor, all of Pi's abit2[peer] receivers commit the SAME choice bits
		// across peer pairs. So bit0(MAC[peer1][k]) = bit0(MAC[peer2][k])
		// = ... = x^me_k automatically — no need to sample x^me, exchange
		// r_choice/d, or update K. The pinned-bit invariants (bit0(Δ)=1,
		// bit0(K)=0, bit0(M)=choice) hold straight out of rcot's bit-0
		// post-processing. Honest Pi gets a consistent share by
		// construction; a malicious Pi using non-shared seeds across peers
		// would produce mismatched per-peer bit0(MAC), and check2's per-
		// peer Mw verification catches that — soundness preserved.
#ifdef AG_PROFILE
		int64_t _cot0 = io->count();
#endif
		// Lane fan-out: partition [0, ext_len) into L contiguous ranges (a
		// pure function of ext_len, L), and draw each lane's range on its own COT
		// instance + mesh with ONE next_n per lane. Order: peer-major, lanes
		// 0..L-1, directions adjacent (sender then receiver) — the canonical
		// deadlock-contract order, identical on both ends. Every task pushes into
		// the SAME `res`, so the one joinNclean below is the barrier that check1/
		// check2 rely on. L == 1 => t=0 only => lane 0 (the parents) over the whole
		// range on io.
		vector<future<void>> res;
		for (int peer : peer_order(party, nP))
			for (int t = 0; t < L; ++t) {
				auto [lo, hi] = lane_range(t, ext_len, L);
				const int n = hi - lo;
				if (n <= 0) continue;   // never an empty lane (caller guarantees L <= ext_len)
				OTExt *otS = cot(peer, true, t);   NetIO *chS = cot_chan(peer, true, t);
				OTExt *otR = cot(peer, false, t);  NetIO *chR = cot_chan(peer, false, t);
				block *KEYp = KEY[peer].data() + lo;
				block *MACp = MAC[peer].data() + lo;
				res.push_back(pool->enqueue([otS, chS, KEYp, n]() { otS->next_n(KEYp, n); chS->flush(); }));
				res.push_back(pool->enqueue([otR, chR, MACp, n]() { otR->next_n(MACp, n); chR->flush(); }));
			}
		joinNclean(res);
		cots_minted_since_check = true;
#ifdef AG_PROFILE
		g_ag_cot_bytes += (uint64_t)(io->count() - _cot0);
#endif

		// check1: certify Δ-consistency once, on the csp gadget tail, before it
		// is dropped. One check covers every later batch (same fixed global keys
		// from the long-lived COTs).
		if (do_delta_check) {
			EchoBC<nP> echo(io, pool, party);
			check1(MAC, KEY, length, echo);
			echo.finalize();
			delta_checked_ = true;
		}

		// Drop the sacrificial tail; output region is [0, length).
		for (int i = 1; i <= nP; ++i) if (i != party) {
			MAC[i].resize(length);
			KEY[i].resize(length);
		}
	}

	// check2: one-shot universal-hash MAC consistency over the whole batch with
	// the collectively-sampled `seed`. Folds w^me = Σ_k coeff[k]·bit0(MAC[any_peer][k])
	// and the per-peer Mw[peer] = Σ coeff·MAC, Kw[peer] = Σ coeff·KEY; broadcasts bw
	// via FBC, exchanges Mw with each peer, and verifies
	// M_me[w^peer] = K_me[w^peer] ⊕ w^peer · Δ_me. Because bw is broadcast, every peer
	// checks the same value, so a party must hold the same bits toward every peer.
	// Aborts on cheating; echo.finalize() also confirms the all_bcast transcripts
	// agreed across parties. `seed` must be drawn AFTER MAC/KEY are committed so the
	// adversary can't adapt to it.
	//
	// bw is public, and the XOR of all parties' bw is Σ_k coeff[k]·x_k: 128 GF(2)-linear
	// equations on the shared bits, e.g. on input masks whose Λ = λ ⊕ input is public.
	// So the fold also covers the kCheck2Pad hiding shares at [length, length + pad),
	// with coefficients X^0..X^127 (the gadget powers; X^k is block bit k, as in
	// check1's packing). Their contribution to bw is the party's own 128 hiding bits,
	// a uniform one-time pad, so bw is uniform and independent of the outputs. An
	// inconsistency confined to the hiding shares shifts a peer's sum by Σ X^k over a
	// nonempty set, which is never zero, so it is always caught; one that touches the
	// outputs is caught except with probability 2^-128, as their coefficients are
	// uniform and drawn after the shares.
	void check2(block seed, BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length) {
		const int n = length + kCheck2Pad;   // outputs + hiding shares
		// coeff: grow-only scratch reused across calls — resize(n) reuses the
		// capacity instead of re-faulting. The CTR expansion is range-split via
		// fork_at (bit-identical to one sequential random_block: position c of the
		// stream is position c regardless of who produces it).
		check2_coeff.resize(n);
		PRG prg2(&seed);
		{
			block *coeff = check2_coeff.data();
			ag::parallel_for(pool, length, [&](int lo, int hi) {
				PRG p = prg2.fork_at((uint64_t)lo);
				p.random_block(coeff + lo, hi - lo);
			});
			for (int k = 0; k < kCheck2Pad; ++k)
				coeff[length + k] = (k < 64) ? makeBlock(0, 1ULL << k) : makeBlock(1ULL << (k - 64), 0);
		}

		int any_peer = (party == 1) ? 2 : 1;

		block Mw[nP + 1], Kw[nP + 1];
		block bw = zero_block;
		{
			// Width-split the O(length) GF folds across the whole pool. Each range
			// computes partial Mw[i]/Kw[i]/bw over its slice, with bw =
			// Σ_k coeff[k]·bit0(MAC[any_peer][k]) (bit0(MAC) agrees across peers, so
			// one peer's MAC suffices; branchless tab[bit]). The inner products and bw
			// are Σ coeff·(), and GF add == XOR, so XOR-reducing the per-range partials
			// yields the full sums.
			const int W = std::max(1, (int)pool->size());
			const int width = (n + W - 1) / W;
			const int nr = (n + width - 1) / width;
			std::vector<block> pMw((size_t)nr * (nP + 1), zero_block);
			std::vector<block> pKw((size_t)nr * (nP + 1), zero_block);
			std::vector<block> pbw((size_t)nr, zero_block);
			vector<future<void>> fold_res;
			for (int r = 0; r < nr; ++r) {
				const int lo = r * width, hi = std::min(lo + width, n);
				fold_res.push_back(pool->enqueue([this, &pMw, &pKw, &pbw, &MAC, &KEY, r, lo, hi, any_peer]() {
					for (int i = 1; i <= nP; ++i) if (i != party) {
						vector_inn_prdt_sum_red(&pMw[(size_t)r * (nP + 1) + i], check2_coeff.data() + lo, MAC[i].data() + lo, hi - lo);
						vector_inn_prdt_sum_red(&pKw[(size_t)r * (nP + 1) + i], check2_coeff.data() + lo, KEY[i].data() + lo, hi - lo);
					}
					block tab[2] = {zero_block, zero_block}, b = zero_block;
					for (int k = lo; k < hi; ++k) { tab[1] = check2_coeff[k]; b = b ^ tab[getLSB(MAC[any_peer][k])]; }
					pbw[r] = b;
				}));
			}
			joinNclean(fold_res);
			for (int i = 1; i <= nP; ++i) if (i != party) {
				Mw[i] = zero_block; Kw[i] = zero_block;
				for (int r = 0; r < nr; ++r) { Mw[i] = Mw[i] ^ pMw[(size_t)r * (nP + 1) + i]; Kw[i] = Kw[i] ^ pKw[(size_t)r * (nP + 1) + i]; }
			}
			for (int r = 0; r < nr; ++r) bw = bw ^ pbw[r];
		}

		// Broadcast bw via FBC, exchange Mw with each peer, verify the MAC relation.
		EchoBC<nP> echo(io, pool, party);
		block bw_recv[nP + 1];
		echo.all_bcast(bw, bw_recv);

		vector<future<void>> res;
		for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
			res.push_back(pool->enqueue([this, &Mw, peer]() {
				io->send_data(peer, &Mw[peer], sizeof(block));
				io->flush(peer);
			}));
			res.push_back(pool->enqueue([this, &bw_recv, &Kw, peer]() {
				block Mw_recv, tmp;
				io->recv_data(peer, &Mw_recv, sizeof(block));
				gfmul(bw_recv[peer], Delta, &tmp);
				block Kw_check = Kw[peer] ^ tmp;
				expecting(cmpBlock(&Kw_check, &Mw_recv, 1), "cheat aShare\n");
			}));
		}
		joinNclean(res);
		echo.finalize();
	}

	// check1: gadget-tail Δ-consistency check.
	void check1(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int length, EchoBC<nP> &echo) {
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

		// FZero: produce u^me ∈ (F_{2^λ})^nP with ⊕_p u^p_k = 0 for
		// every column k. See fzero_xor in crypto/fzero.h.
		block u_me[nP];
		for (int k = 0; k < nP; ++k) u_me[k] = zero_block;
		BlockVec fz_scratch;   // tiny (nP blocks), low-freq check1 -- local is fine
		fzero_xor<nP>(io, &prg, pool, party, u_me, nP, fz_scratch);

		// y^me_k = x^{me,k} ⊕ u^me_k (with x^{me,me} := 0 so the k+1==me
		// column is just u^me_k). Broadcast y^me via FBC (echo). Index k
		// (0-based) here corresponds to column k+1 (1-indexed parties).
		block y_me[nP];
		for (int k = 0; k < nP; ++k)
			y_me[k] = xv[k + 1] ^ u_me[k];

		block y_storage[nP + 1][nP];
		block *y_view[nP + 1];
		for (int p = 1; p <= nP; ++p) y_view[p] = y_storage[p];
		echo.all_bcast(y_me, nP, y_view);

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
		echo.all_bcast(z_dgst[party], z_dgst);

		// Open z^me; verify ⊕_p z^p_j = 0 for every column j.
		// Columns where j = some party p collapse via MAC = KEY ⊕ x · Δ_p
		// to a Δ-consistency identity that holds iff Δ_p is consistent across
		// p's COT instances (and the y-construction is faithful).
		block z_storage[nP + 1][nP];
		block *z_recv[nP + 1];
		for (int i = 1; i <= nP; ++i) z_recv[i] = z_storage[i];
		echo.all_bcast(z + 1, nP, z_recv);
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
	void draw_soa(int n, const block *mac_out[nP + 1], const block *key_out[nP + 1]) {
		compute(draw_mac_, draw_key_, n);
		for (int j = 1; j <= nP; ++j) {
			mac_out[j] = draw_mac_[j].data();
			key_out[j] = draw_key_[j].data();
		}
	}
};

}  // namespace emp::ag
#endif // EMP_AG_BACKEND_PREPROC_AUTH_SHARE_POOL_H__
