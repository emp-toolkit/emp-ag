#ifndef EMP_AG_BACKEND_ASHARE_FIX_H__
#define EMP_AG_BACKEND_ASHARE_FIX_H__
//
// The Fix exchange (nP > 2), which gives a party the same share bit toward every peer.
// Each receiver stream draws its own random choices r_j, so the party samples x^me and
// sends each peer d_j = x^me ⊕ r_j, one bit per COT. These are its two halves on one
// stream's slice; a mint runs them on that stream's channel, after its draw. A mint whose
// receivers share their choices runs them only toward per-peer targets, to give the
// check1 tail bits of its own per peer. Both mints also take a sender stream's Δ through
// test_split_delta, a test-only hook.
//
#include "emp-tool/emp-tool.h"
#include <cstdint>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

// Receiver half, on the MACs this party drew from one peer: d = x^me ⊕ r, where r is
// bit 0 of the MAC, then MAC ^= d·e0, so that bit 0 of every MAC is x^me. The caller
// sends d. `flip` complements every d (the split_choice test hook only).
inline void fix_receiver_half(block *mac, int n, const uint8_t *xme, uint8_t *d, bool flip) {
	const uint8_t f = flip ? 1 : 0;
	for (int k = 0; k < n; ++k)
		d[k] = (uint8_t)(xme[k] ^ (getLSB(mac[k]) ? 1 : 0) ^ f);
	for (int k = 0; k < n; ++k)
		mac[k] = mac[k] ^ (select_mask[d[k]] & bit0_mask);
}

// The Δ bits a party's sender stream toward `peer` takes: delta_bits itself. Under the
// split_delta test hook (TEST-ONLY, compiled out of production), party 2's stream toward
// party 3 takes them with bit 7 flipped (neither pinned bit), written to `buf`, so that
// party 2's global key differs across its peers; check1 must abort.
inline const bool *test_split_delta(const bool *delta_bits, [[maybe_unused]] int party,
                                    [[maybe_unused]] int peer, [[maybe_unused]] bool *buf) {
	if constexpr (kTestHooks) {
		if (hooks().split_delta && party == 2 && peer == 3) {
			for (int k = 0; k < 128; ++k) buf[k] = delta_bits[k];
			buf[7] = !buf[7];
			return buf;
		}
	}
	return delta_bits;
}

// Sender half, on this party's keys for one peer's bits, with the d that peer sent:
// KEY ^= d·(Δ ⊕ e0), where dxor = Δ ⊕ e0, so MAC = KEY ⊕ x^me·Δ and bit 0 of KEY stays 0.
inline void fix_sender_half(block *key, int n, const uint8_t *d, const block &dxor) {
	for (int k = 0; k < n; ++k)
		key[k] = key[k] ^ (select_mask[d[k]] & dxor);
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_ASHARE_FIX_H__
