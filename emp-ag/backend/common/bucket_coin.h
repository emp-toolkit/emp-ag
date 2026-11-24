#ifndef EMP_AG_BACKEND_COMMON_BUCKET_COIN_H__
#define EMP_AG_BACKEND_COMMON_BUCKET_COIN_H__
//
// The two-party bucket coin that costs no flight of its own. Each party draws a fresh seed
// and commits to it, role-bound so a commitment cannot be reflected. The commitment rides
// the flight that fixes what the coin will bucket (the leaky ANDs' rows), and the seed the
// next flight (their s-bits); the coin is both seeds in party order. Neither party picks
// it, and it is unpredictable while the rows are being fixed.
//
// It must be commit-then-open, never a hash of the transcript: a party's s-bits carry its
// selective-failure guesses, so with a hashed coin it could try every guess vector
// offline and send the one whose buckets fill with its leaky triples.
//
#include "emp-ag/backend/common/fs_hash.h"     // FsHash::DIGEST_SIZE
#include "emp-ag/backend/common/protocols.h"   // role_bound_commitment
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/crypto/prg.h"
#include "emp-tool/runtime/crypto/ro.h"
#include <cstring>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

struct BucketCoin2PC {
  block mine = zero_block, peer = zero_block;
  char com_mine[FsHash::DIGEST_SIZE] = {}, com_peer[FsHash::DIGEST_SIZE] = {};
};

// Draw this party's seed and commit to it. com_mine goes out with the rows and the peer's
// lands in com_peer; mine goes out with the s-bits and the peer's lands in peer.
inline void bucket_coin_commit(BucketCoin2PC &c, PRG &prg, block session_id, int party) {
  prg.random_block(&c.mine, 1);
  role_bound_commitment(c.com_mine, session_id, "emp-ag:bucket-seed", party, &c.mine,
                        sizeof(block));
  if constexpr (kTestHooks) {
    // TEST-ONLY (hook flip_bucket_seed): a malicious party 2 opens a seed other than the
    // one it committed to. The opening check must abort.
    if (hooks().flip_bucket_seed && party == 2) c.mine = c.mine ^ makeBlock(0, 1);
  }
}

// The coin, once both seeds are in: aborts unless the peer's seed opens its commitment.
inline block bucket_coin_open(const BucketCoin2PC &c, block session_id, int party) {
  const int peer = (party == 1) ? 2 : 1;
  char expect[FsHash::DIGEST_SIZE];
  role_bound_commitment(expect, session_id, "emp-ag:bucket-seed", peer, &c.peer, sizeof(block));
  expecting(memcmp(expect, c.com_peer, FsHash::DIGEST_SIZE) == 0,
            "bucket coin: the peer's bucket seed does not open its commitment");
  const block s1 = (party == 1) ? c.mine : c.peer;
  const block s2 = (party == 1) ? c.peer : c.mine;
  return RO("emp-ag:bucket-coin", session_id).absorb(s1).absorb(s2).squeeze_block();
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_COMMON_BUCKET_COIN_H__
