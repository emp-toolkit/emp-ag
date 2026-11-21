#ifndef EMP_AG_BACKEND_ASHARE_FIX_H__
#define EMP_AG_BACKEND_ASHARE_FIX_H__
//
// The Fix exchange (nP > 2), which gives a party the same share bit toward every peer.
// Each receiver stream draws its own random choices r_j, so the party samples x^me and
// sends each peer d_j = x^me ⊕ r_j, one bit per COT. These are its two halves on one
// stream's slice; a mint runs them on that stream's channel, after its draw.
//
#include "emp-tool/emp-tool.h"
#include <cstdint>

namespace emp::ag {

// Receiver half, on the MACs this party drew from one peer: d = x^me ⊕ r, where r is
// bit 0 of the MAC, then MAC ^= d·e0, so that bit 0 of every MAC is x^me. The caller
// sends d. `flip` complements every d (EMP_AG_TEST_SPLIT_CHOICE only).
inline void fix_receiver_half(block *mac, int n, const uint8_t *xme, uint8_t *d, bool flip) {
	const uint8_t f = flip ? 1 : 0;
	for (int k = 0; k < n; ++k)
		d[k] = (uint8_t)(xme[k] ^ (getLSB(mac[k]) ? 1 : 0) ^ f);
	for (int k = 0; k < n; ++k)
		mac[k] = mac[k] ^ (select_mask[d[k]] & bit0_mask);
}

// Sender half, on this party's keys for one peer's bits, with the d that peer sent:
// KEY ^= d·(Δ ⊕ e0), where dxor = Δ ⊕ e0, so MAC = KEY ⊕ x^me·Δ and bit 0 of KEY stays 0.
inline void fix_sender_half(block *key, int n, const uint8_t *d, const block &dxor) {
	for (int k = 0; k < n; ++k)
		key[k] = key[k] ^ (select_mask[d[k]] & dxor);
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_ASHARE_FIX_H__
