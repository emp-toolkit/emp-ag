#ifndef EMP_AG_BACKEND_ASHARE_SOFTSPOKEN_MINT_H__
#define EMP_AG_BACKEND_ASHARE_SOFTSPOKEN_MINT_H__
//
// A mint holds the COT streams behind the share generator (ashare_gen.h): one stream
// per peer and direction, this party sending toward peer j (its keys on j's bits) and
// receiving from j (its MACs on its own bits). The generator turns the raw COTs into
// authenticated shares and checks them. Every mint offers
//   Mint(io, pool, party, grp, session_id, base_ot_kind, planned_sender_cots,
//        planned_receiver_cots, delta_bits)
//                        set up every stream, with Δ_me = delta_bits on the sender streams
//   delta()              Δ_me as the sender streams hold it
//   bootstrap_cots()     the COTs each stream drew during setup
//   draw(MAC, KEY, ext_len, nfix, xme, dxor)
//                        ext_len raw COTs from every stream into MAC[j][0, ext_len) and
//                        KEY[j][0, ext_len), then the Fix exchange (fix.h) on [0, nfix)
//                        with x^me = xme and dxor = Δ_me ⊕ e0; nfix > 0 only at nP > 2
//   maybe_flush_check()  the streams' deferred consistency checks, before a reveal
// and closes its streams when destroyed.
//
// SoftSpokenMint runs one SoftSpoken<EMP_AG_SOFTSPOKEN_K> extension per stream. It
// bootstraps one direction per unordered pair from a public-key base OT and derives the
// other direction from it (dedup_bootstrap_pairs_), runs on the session's lanes, and
// defers each stream's consistency check to maybe_flush_check(). SilentFerretMint
// (silent_ferret_mint.h) is the other mint.
//
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/common/runtime.h"            // peer_order, lane_range
#include "emp-ot/base_ot/base_ot_select.h"  // BaseOtKind / make_base_ot
#include "emp-ot/ot_extension/softspoken/softspoken.h"
#include "emp-ag/backend/ashare/buffer_ot.h"   // BufferOT (one base OT per unordered pair)
#include "emp-ag/backend/ashare/cot_extension_factory.h"
#include "emp-ag/backend/ashare/fix.h"         // the Fix exchange's two halves
#include "emp-tool/runtime/crypto/mitccrh.h"     // MITCCRH (COT->ROT for the derived base OTs)
#include <algorithm>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

namespace emp::ag {


// SoftSpoken<k>: k tunes compute against bandwidth. A larger k sends fewer bytes per COT
// but costs more AES per OT; the default k = 8 minimizes COT communication, the binding
// cost on bandwidth-bound and egress-metered links.
#ifndef EMP_AG_SOFTSPOKEN_K
#define EMP_AG_SOFTSPOKEN_K 8
#endif
using SoftSpokenCot = emp::SoftSpoken<EMP_AG_SOFTSPOKEN_K>;
using OTExt = emp::OTExtension;

template <int nP>
class SoftSpokenMint {
 public:
	// Planned sender/receiver counts include the 128-COT bootstrap prefix and are
	// forwarded to OTExtension::begin(n_ots); see AShareGen.
	// `cot` supplies the streams in place of SoftSpoken over a public-key base OT
	// (cot_extension_factory.h); empty keeps them.
	SoftSpokenMint(NetIOMP<nP> *io, ThreadPool *pool, int party, NetIOMPGroup<nP> *grp_in,
	           block session_id, BaseOtKind base_ot_kind, int64_t planned_sender_cots,
	           int64_t planned_receiver_cots, const bool delta_bits[128],
	           const CotExtensionFactory &cot = {})
		: grp(grp_in), io(io), pool(pool), party(party), session_id(session_id), cot_(cot) {
			validate_cot_extension_factory(cot_);
			expecting(!cot_.supplied() || grp_in == nullptr || grp_in->size() == 1,
			          "COT streams: supplied streams run on one lane");
			expecting(planned_sender_cots == -1 || planned_sender_cots >= 128,
			          "AShareGen: planned sender COT count must be -1 or include the 128-COT bootstrap prefix");
			expecting(planned_receiver_cots == -1 || planned_receiver_cots >= 128,
			          "AShareGen: planned receiver COT count must be -1 or include the 128-COT bootstrap prefix");
			// Lanes split each draw, and a plan counts one stream.
			expecting((planned_sender_cots < 0 && planned_receiver_cots < 0) ||
			              grp_in == nullptr || grp_in->size() == 1,
			          "AShareGen: counted COT plans require one lane");

			// One public-key base OT per unordered pair: the higher-numbered
			// party's COT direction bootstraps normally, then supplies hashed
			// random OTs as the reverse direction's base OTs.
			dedup_bootstrap_pairs_(delta_bits, base_ot_kind,
			                       planned_sender_cots, planned_receiver_cots);

			// Lanes clone the now-bootstrapped parents, including the direction whose
			// base OTs were derived above.
			if (grp != nullptr) {
				L = std::max(1, grp->size());
				if (L > 1) spawn_and_begin_lanes();
			}
		}

	~SoftSpokenMint() {
		if (cot_sessions_open)
			close_cot_sessions();
	}
	SoftSpokenMint(const SoftSpokenMint &) = delete;
	SoftSpokenMint &operator=(const SoftSpokenMint &) = delete;

	block delta() const { return Delta_; }
	int64_t bootstrap_cots() const { return kPrefix; }

	// ext_len raw COTs from every stream, then the Fix exchange on [0, nfix_all).
	// Lane fan-out: partition [0, ext_len) into L contiguous ranges (a
	// pure function of ext_len, L), and draw each lane's range on its own COT
	// instance + mesh with ONE next_n per lane. Order: peer-major, lanes
	// 0..L-1, directions adjacent (sender then receiver) — the canonical
	// deadlock-contract order, identical on both ends. Every task pushes into
	// the SAME `res`, so the one joinNclean below is the barrier that check1/
	// check2 rely on. L == 1 => t=0 only => lane 0 (the parents) over the whole
	// range on io. Each (peer, lane) receiver task sends its Fix corrections right
	// after its draw, on the same channel.
	void draw(BlockVec MAC[nP + 1], BlockVec KEY[nP + 1], int ext_len, int nfix_all,
	          const uint8_t *xme_all, block dxor) {
		if (nfix_all > 0)
			for (int i = 1; i <= nP; ++i) if (i != party) {
				if (fix_out_[i].size() < (size_t)nfix_all) fix_out_[i].resize((size_t)nfix_all);
				if (fix_in_[i].size() < (size_t)nfix_all) fix_in_[i].resize((size_t)nfix_all);
			}
		vector<future<void>> res;
		for (int peer : peer_order(party, nP))
			for (int t = 0; t < L; ++t) {
				auto [lo, hi] = lane_range(t, ext_len, L);
				const int n = hi - lo;
				if (n <= 0) continue;   // never an empty lane (caller guarantees L <= ext_len)
				// This lane's corrected positions: [lo, lo + nfix).
				const int nfix = std::max(0, std::min(hi, nfix_all) - lo);
				OTExt *otS = cot(peer, true, t);   NetIO *chS = cot_chan(peer, true, t);
				OTExt *otR = cot(peer, false, t);  NetIO *chR = cot_chan(peer, false, t);
				block *KEYp = KEY[peer].data() + lo;
				block *MACp = MAC[peer].data() + lo;
				uint8_t *din = nfix > 0 ? fix_in_[peer].data() + lo : nullptr;
				uint8_t *dout = nfix > 0 ? fix_out_[peer].data() + lo : nullptr;
				const uint8_t *xme = nfix > 0 ? xme_all + lo : nullptr;
				bool split = false;
#ifdef EMP_AG_TEST_SPLIT_CHOICE
				// TEST-ONLY (never in production): party 2 holds the complement of its
				// bits toward party 3 -- it applies and sends the flipped correction --
				// so its shares disagree across peers while every MAC stays valid. The
				// share-consistency check must abort.
				split = (party == 2 && peer == 3);
#ifdef EMP_AG_TEST_SPLIT_FIRST_DRAW
				// TEST-ONLY: only the session's first draw is split (the input masks), so
				// the triples stay consistent and only that draw's check2 views disagree.
				split = split && test_draws_ == 0;
#endif
#endif
				res.push_back(pool->enqueue([otS, chS, KEYp, n, din, nfix, dxor]() {
					otS->next_n(KEYp, n);
					chS->flush();   // before blocking on the correction
					if (nfix > 0) {
						chS->recv_bool(din, nfix);
						fix_sender_half(KEYp, nfix, din, dxor);
					}
				}));
				res.push_back(pool->enqueue([otR, chR, MACp, n, dout, xme, nfix, split]() {
					otR->next_n(MACp, n);
					if (nfix > 0) {
						fix_receiver_half(MACp, nfix, xme, dout, split);
						chR->send_bool(dout, nfix);
					}
					chR->flush();
				}));
			}
		joinNclean(res);
		cots_minted_since_check = true;
#if defined(EMP_AG_TEST_SPLIT_CHOICE) && defined(EMP_AG_TEST_SPLIT_FIRST_DRAW)
		++test_draws_;
#endif
	}

	// Flush the deferred COT consistency check before a reveal; no-op when
	// nothing was minted since the last flush.
	void maybe_flush_check() {
		if (cots_minted_since_check)
			flush_cot_check();
	}

 private:
	static constexpr int64_t kPrefix = 128;   // each stream's checked bootstrap prefix
	// Each party holds both COT directions against every peer: abit1 is always
	// the local extension sender and abit2 is always the local receiver. Slot
	// [party] is unused. A SoftSpoken ctor takes the role, channel
	// and owned base OT upfront, so the instances are unique_ptrs constructed per peer
	// in the bootstrap.
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
	CotExtensionFactory cot_;   // supplied streams, or empty for SoftSpoken's own
	block Delta_;   // Δ_me, as the sender streams hold it
	// Fix exchange scratch (grow-only): the corrections sent to and received from each peer.
	std::vector<uint8_t> fix_out_[nP + 1], fix_in_[nP + 1];
#if defined(EMP_AG_TEST_SPLIT_CHOICE) && defined(EMP_AG_TEST_SPLIT_FIRST_DRAW)
	int test_draws_ = 0;   // TEST-ONLY: draws so far
#endif
	bool cot_sessions_open = false;
	bool cots_minted_since_check = false;

	// Lane partition is the shared ag::lane_range (runtime.h), a pure function of
	// (ext_len, L), so both ends of every pair agree on lane t's [lo, hi).
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

	// After the parents are bootstrapped and their prefixes checked, spawn lanes
	// 1..L-1 as clone_lane copies on meshes 1..L-1 and begin() each (clones skip
	// bootstrap; begin() just enters a session + guards FS on their fresh mesh
	// channel). Each clone derives its session id from its parent's, so both ends
	// clone every parent in the same order, t = 1..L-1. SoftSpoken-only
	// (clone_lane is a SoftSpoken method).
	void spawn_and_begin_lanes() {
		for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
			abit1_lane[peer].resize(L - 1);
			abit2_lane[peer].resize(L - 1);
			for (int t = 1; t < L; ++t) {
				auto *send_parent = static_cast<SoftSpokenCot *>(abit1[peer].get());
				auto *recv_parent = static_cast<SoftSpokenCot *>(abit2[peer].get());
				abit1_lane[peer][t - 1] = send_parent->clone_lane(cot_chan(peer, true, t));
				abit2_lane[peer][t - 1] = recv_parent->clone_lane(cot_chan(peer, false, t));
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

	std::unique_ptr<OTExt> make_cot_extension_(
			int role, NetIO *channel, std::unique_ptr<OT> base) {
		return std::make_unique<SoftSpokenCot>(
			role, channel, /*malicious=*/true, std::move(base));
	}

	// A pair's primary stream: the supplied one, or SoftSpoken over a public-key base OT.
	std::unique_ptr<OTExt> make_primary_(int role, NetIO *channel, BaseOtKind base_ot_kind) {
		if (cot_.supplied()) return supplied_stream_(cot_.primary(role, channel));
		return make_cot_extension_(role, channel, make_base_ot(base_ot_kind, channel));
	}

	// A pair's reverse stream, over the base OTs derived from the primary's checked prefix.
	std::unique_ptr<OTExt> make_reverse_(int role, NetIO *channel, std::unique_ptr<OT> base) {
		if (cot_.supplied()) return supplied_stream_(cot_.reverse(role, channel, std::move(base)));
		return make_cot_extension_(role, channel, std::move(base));
	}

	static std::unique_ptr<OTExt> supplied_stream_(std::unique_ptr<OTExt> stream) {
		expecting(stream != nullptr, "COT streams: the factory returned no stream");
		return stream;
	}

	// Bootstrap one direction per unordered pair with its normal public-key base
	// OT, then derive the reverse direction's 128 base OTs from its first 128 COTs.
	// The higher-numbered party is the primary sender. The prefix is check()ed
	// before anything is derived from it. In the reverse direction the primary
	// receiver becomes the sender, the party that verifies the reverse bootstrap
	// and the reverse consistency fold. Derived from an unchecked prefix, those
	// messages would let a cheating primary receiver test guesses of the primary
	// sender's Delta offline, with no abort, and then repair its own primary fold
	// before that check ran. The derivation hashes prefix row i under gid i of a
	// MITCCRH stream started from the reverse direction's sid: H(K_i) and
	// H(K_i ^ Delta) for the primary sender, H(M_i) for the receiver. The
	// derivation relies on each primary receiver's prefix choices being its own
	// fresh, private randomness. Both directions draw and check a 128-COT prefix,
	// so counted plans include the prefix in either direction.
	void dedup_bootstrap_pairs_(const bool* delta_me,
			BaseOtKind base_ot_kind, int64_t planned_sender_cots,
			int64_t planned_receiver_cots) {
		constexpr int64_t K = kPrefix;
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
			res.push_back(pool->enqueue([this, peer, delta_me,
			                                  base_ot_kind, planned_sender_cots,
			                                  planned_receiver_cots, &primary,
			                                  &primary_sid]() {
				const bool me_smaller = party < peer;
				NetIO* ch_send = io->get(peer, /*swap=*/!me_smaller);
				NetIO* ch_recv = io->get(peer, /*swap=*/me_smaller);
				if (!me_smaller) {
					// Higher party: primary sender.
					abit1[peer] = make_primary_(ALICE, ch_send, base_ot_kind);
					abit1[peer]->set_sid(primary_sid[(size_t)peer]);
					bool split_delta[128];
					abit1[peer]->set_delta(test_split_delta(delta_me, party, peer, split_delta));
					if (planned_sender_cots >= 0) abit1[peer]->begin(planned_sender_cots);
					else                          abit1[peer]->begin();
					ch_send->flush();
					abit1[peer]->next_n(primary[(size_t)peer].data(), K); ch_send->flush();
					abit1[peer]->check(); ch_send->flush();   // certify the prefix
				} else {
					// Lower party: primary receiver.
					abit2[peer] = make_primary_(BOB, ch_recv, base_ot_kind);
					abit2[peer]->set_sid(primary_sid[(size_t)peer]);
					if (planned_receiver_cots >= 0) abit2[peer]->begin(planned_receiver_cots);
					else                            abit2[peer]->begin();
					ch_recv->flush();
#ifdef EMP_AG_TEST_TAMPER_PREFIX
					// TEST-ONLY (never in production): party 1 flips one bit of the first
					// prefix correction it sends to party 2. Party 2's check of the prefix
					// must abort before anything is derived from it.
					if (party == 1 && peer == 2) static_cast<TamperNetIO *>(ch_recv)->arm();
#endif
					abit2[peer]->next_n(primary[(size_t)peer].data(), K); ch_recv->flush();
					abit2[peer]->check(); ch_recv->flush();
				}
			}));
		}
		joinNclean(res);

		// Phase 2: derive each reverse direction's base OTs from its checked primary
		// prefix, then draw and check that direction's own 128-COT prefix.
		res.clear();
		for (int peer : peer_order(party, nP)) {
			res.push_back(pool->enqueue([this, peer, delta_me,
			                              planned_sender_cots, planned_receiver_cots,
			                              &primary, &reverse_sid]() {
				const bool me_smaller = party < peer;
				NetIO* ch_send = io->get(peer, /*swap=*/!me_smaller);
				NetIO* ch_recv = io->get(peer, /*swap=*/me_smaller);
				BlockVec reverse_prefix((size_t)K);
				MITCCRH<> hash;
				hash.setS(RO("emp-ag:reverse-base-ot", reverse_sid[(size_t)peer]).squeeze_block());
				static_assert(K % 8 == 0, "the derivation hashes the prefix 8 rows per call");
				if (!me_smaller) {
					std::vector<block> m0((size_t)K), m1((size_t)K);
					const block D = abit1[peer]->Delta;
					for (int64_t i = 0; i < K; i += 8) {
						block pad[16];
						for (int j = 0; j < 8; ++j) {
							pad[2 * j] = primary[(size_t)peer][(size_t)(i + j)];
							pad[2 * j + 1] = pad[2 * j] ^ D;
						}
						hash.hash<8, 2>(pad);
						for (int j = 0; j < 8; ++j) {
							m0[(size_t)(i + j)] = pad[2 * j];
							m1[(size_t)(i + j)] = pad[2 * j + 1];
						}
					}
					abit2[peer] = make_reverse_(
						BOB, ch_recv,
						std::make_unique<BufferOT>(ch_recv, std::move(m0), std::move(m1)));
					abit2[peer]->set_sid(reverse_sid[(size_t)peer]);
					if (planned_receiver_cots >= 0) abit2[peer]->begin(planned_receiver_cots);
					else                            abit2[peer]->begin();
					ch_recv->flush();
					abit2[peer]->next_n(reverse_prefix.data(), K); ch_recv->flush();
					abit2[peer]->check(); ch_recv->flush();
				} else {
					std::vector<uint8_t> c((size_t)K);
					std::vector<block> mc((size_t)K);
					for (int64_t i = 0; i < K; i += 8) {
						block pad[8];
						for (int j = 0; j < 8; ++j) {
							pad[j] = primary[(size_t)peer][(size_t)(i + j)];
							c[(size_t)(i + j)] = emp::getLSB(pad[j]) ? 1 : 0;
						}
						hash.hash<8, 1>(pad);
						for (int j = 0; j < 8; ++j) mc[(size_t)(i + j)] = pad[j];
					}
					abit1[peer] = make_reverse_(
						ALICE, ch_send,
						std::make_unique<BufferOT>(ch_send, std::move(c), std::move(mc)));
					abit1[peer]->set_sid(reverse_sid[(size_t)peer]);
					bool split_delta[128];
					abit1[peer]->set_delta(test_split_delta(delta_me, party, peer, split_delta));
					if (planned_sender_cots >= 0) abit1[peer]->begin(planned_sender_cots);
					else                          abit1[peer]->begin();
					ch_send->flush();
					abit1[peer]->next_n(reverse_prefix.data(), K); ch_send->flush();
					abit1[peer]->check(); ch_send->flush();
				}
			}));
		}
		joinNclean(res);
		Delta_ = abit1[party == 1 ? 2 : 1]->Delta;
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
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_ASHARE_SOFTSPOKEN_MINT_H__
