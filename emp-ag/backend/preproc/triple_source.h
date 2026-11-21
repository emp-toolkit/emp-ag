#ifndef EMP_AG_BACKEND_PREPROC_TRIPLE_SOURCE_H__
#define EMP_AG_BACKEND_PREPROC_TRIPLE_SOURCE_H__
//
// A source of authenticated random AND triples. TriplePool::use_source installs one in
// place of the per-call leaky ANDs (preproc/triple_pool.h). CutAndChooseTriples
// (preproc/cut_and_choose_triples.h) is one; an application can supply its own.
//
// take(n, mac, key) writes n triples (a, b, c = a AND b) as aShares under the session's
// Deltas. For every peer p, mac[p] and key[p] are resized to 3n, with a at [0, n), b at
// [n, 2n) and c at [2n, 3n). mac[p][i] = K_p[x_i] ^ x_i * Delta_p is this party's MAC on
// its share x_i, so bit 0 of it is x_i, and key[p][i] is this party's key on p's share
// (shares.h).
//
// The source alone is responsible for its triples. TriplePool opens a ^ lambda_alpha and
// b ^ lambda_beta, where lambda_alpha and lambda_beta are the circuit masks, and checks
// those opens against their MACs. Nothing it runs later catches a wrong c, which becomes
// a wrong but validly authenticated sigma. So every triple must satisfy c = a AND b, a
// and b must be uniformly random and hidden from the corrupt parties, and no triple may
// be served twice. Every party calls take() at the same points with the same n.
//
#include "emp-tool/runtime/core/block_vector.h"   // BlockVec
#include <cstdint>

namespace emp::ag {

template <int nP>
class TripleSource {
public:
  virtual ~TripleSource() = default;
  virtual void take(int64_t n, BlockVec mac[nP + 1], BlockVec key[nP + 1]) = 0;
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_PREPROC_TRIPLE_SOURCE_H__
