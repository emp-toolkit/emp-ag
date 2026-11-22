#ifndef EMP_AG_BACKEND_TRIPLE_TRIPLE_ROW_H__
#define EMP_AG_BACKEND_TRIPLE_TRIPLE_ROW_H__
//
// A row of triples (a, b, c) as aShares: component r (a = 0, b = 1, c = 2) toward peer p
// is the vector at mac[r][p], this party's MACs on its shares, and key[r][p], its keys on
// p's shares (share.h). The components are separate vectors, so a row can be laid out
// [a | b | c] in one array per peer, or take a component from elsewhere.
//
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/core/block_vector.h"
#include <cstdint>

namespace emp::ag {

template <int nP>
struct TripleRow {
  block *mac[3][nP + 1] = {};
  block *key[3][nP + 1] = {};
};

// The row laid out [a | b | c] from `offset` in mac[p] and key[p], its components
// `stride` apart, for every peer p of `party`.
template <int nP>
TripleRow<nP> strided_row(BlockVec mac[nP + 1], BlockVec key[nP + 1], int64_t offset,
                          int64_t stride, int party) {
  TripleRow<nP> t;
  for (int p = 1; p <= nP; ++p) if (p != party)
    for (int r = 0; r < 3; ++r) {
      t.mac[r][p] = mac[p].data() + offset + r * stride;
      t.key[r][p] = key[p].data() + offset + r * stride;
    }
  return t;
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_TRIPLE_TRIPLE_ROW_H__
