#ifndef EMP_AG_BACKEND_ASHARE_SOURCE_H__
#define EMP_AG_BACKEND_ASHARE_SOURCE_H__
//
// The share pool as an AND-gate protocol sees it (triple/and_prep.h), apart from the
// generator behind it (ashare_gen.h, which implements it over a session's COT streams), so
// a protocol's translation unit need not compile either mint.
//
#include "emp-ag/backend/common/fs_hash.h"   // FsHash::DIGEST_SIZE
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/core/block_vector.h"
#include <cstdint>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

// The digest of check2's openings not yet agreed (every party's hash value, as this party
// received it), which every party must share; `any` is false when no check2 ran since the
// last take, and then there is nothing to agree (AShareGen::take_pending_check2).
struct PendingCheck2 {
	bool any = false;
	char view[FsHash::DIGEST_SIZE];
};

// The share generator as the triple layer sees it, the same whichever mint the session
// chose (AShareGen, ashare_gen.h, implements it).
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
	// n raw COTs from this party's lane-0 stream with `peer`, for a sub-protocol that
	// needs the session's correlation under its global keys (for example a VOLE-based
	// proof whose values then enter a computation authenticated). As the stream's sender:
	// this party's keys K, bit 0 clear, under Delta; as its receiver: its MACs
	// M = K ^ b * Delta, the choice b in bit 0. Both ends call it at the same point with
	// the same n, and a counted plan counts the draw. The stream's deferred consistency
	// check covers these COTs: run maybe_flush_cot_check() before releasing anything that
	// depends on them, or a cheating receiver could learn about Delta first. While a
	// session's computation job is outstanding, the pool refuses both calls: draw and
	// check through AGMPCSession::draw_cots(job, ...) and check_cots(job). SoftSpoken
	// mint only.
	virtual void draw_cots(int peer, bool as_sender, block *out, int64_t n) = 0;
};

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_ASHARE_SOURCE_H__
