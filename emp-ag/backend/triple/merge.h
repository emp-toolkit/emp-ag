#ifndef EMP_AG_BACKEND_TRIPLE_MERGE_H__
#define EMP_AG_BACKEND_TRIPLE_MERGE_H__
//
// Bucketing ("merge"): B rows of ell leaky AND triples become ell triples free of the
// leakage on a, as long as some triple of each bucket is not leaky. Row 0 is not rotated;
// row m >= 1 is rotated by r_m, uniform in [0, ell) and drawn after every row is fixed.
// Bucket j is row 0's j-th triple and row m's ((j + r_m) mod ell)-th. The parties open the
// differences b_0 ^ b_m, row-major: value (m - 1) ell + j is b_0[j] ^ b_m[member(m, j)].
// With d those opened bits, bucket j's triple is
//   a = XOR_m a_m,   b = b_0,   c = c_0 ^ XOR_{m >= 1} (c_m ^ d * a_m),
// since a b_0 = XOR_m a_m (b_m ^ d). Both callers size B under one bound, 2^-B ell^(1-B)
// (triple/bucketing.h).
// Each caller opens the differences with its other openings and checks them against
// their MACs in its own open check. A protocol that assigns triples to buckets otherwise
// (any member from any row) calls the general merge_combine below with its own member
// and difference accessors, under a bound of its own.
//
#include "emp-ag/backend/common/runtime.h"   // parallel_for
#include "emp-ag/backend/common/uniform_index.h"
#include "emp-ag/backend/triple/triple_row.h"
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/crypto/prg.h"
#include <algorithm>
#include <cstdint>
#include <vector>

namespace emp::ag {

// The rotations of B rows of ell triples.
struct Buckets {
  int B = 1;
  int64_t ell = 0;
  std::vector<int64_t> rot;   // rot[0] = 0
  // Row m's triple in bucket j.
  int64_t member(int m, int64_t j) const {
    const int64_t q = j + rot[(size_t)m];
    return q < ell ? q : q - ell;
  }
  // The number of opened differences.
  int64_t differences() const { return (int64_t)(B - 1) * ell; }
};

// Draw the B - 1 rotations in order from `prg`, which the caller seeds from a coin drawn
// after every row is fixed.
inline Buckets draw_buckets(PRG &prg, int B, int64_t ell) {
  Buckets bk;
  bk.B = B;
  bk.ell = ell;
  bk.rot.assign((size_t)B, 0);
  for (int m = 1; m < B; ++m) bk.rot[(size_t)m] = uniform_index(prg, ell);
  return bk;
}

// Difference (m, j) as an aShare toward p: the XOR of the two b's MACs (keys).
template <int nP>
block merge_diff_mac(const std::vector<TripleRow<nP>> &rows, const Buckets &bk, int m,
                     int64_t j, int p) {
  return rows[0].mac[1][p][j] ^ rows[(size_t)m].mac[1][p][bk.member(m, j)];
}
template <int nP>
block merge_diff_key(const std::vector<TripleRow<nP>> &rows, const Buckets &bk, int m,
                     int64_t j, int p) {
  return rows[0].key[1][p][j] ^ rows[(size_t)m].key[1][p][bk.member(m, j)];
}

// This party's shares of the differences, row-major, into out[0, (B - 1) ell): bit 0 of
// its MACs toward any one peer (`peer`), where share.h keeps its share.
template <int nP>
void merge_difference_shares(const std::vector<TripleRow<nP>> &rows, const Buckets &bk,
                             int peer, unsigned char *out, ThreadPool *pool) {
  for (int m = 1; m < bk.B; ++m) {
    const block *b0 = rows[0].mac[1][peer], *bm = rows[(size_t)m].mac[1][peer];
    unsigned char *o = out + (size_t)(m - 1) * bk.ell;
    ag::parallel_for(pool, (int)bk.ell, [&, b0, bm, o, m](int lo, int hi) {
      for (int j = lo; j < hi; ++j)
        o[j] = (unsigned char)(getLSB(b0[j]) ^ getLSB(bm[bk.member(m, j)]));
    });
  }
}

// Where bucket j's member from row m >= 1 sits: a row of the caller's and an index in it.
struct MergeSource {
  int row;
  int64_t index;
};

// Merge every bucket into row 0: bucket j's member from row m >= 1 is member(m, j), a
// MergeSource into `rows` other than row 0, and d(m, j) is its opened difference, the b of
// row 0's j-th triple XOR the member's b. Linear in the MACs and keys toward each peer, so
// no party adds a public constant. Width-split: each task owns one peer's range of
// buckets, and every member is read once.
template <int nP, class Member, class DBit>
void merge_combine(const std::vector<TripleRow<nP>> &rows, int B, int64_t ell,
                   Member &&member, DBit &&d, int party, ThreadPool *pool) {
  if (B < 2 || ell == 0) return;
  const int per_peer = std::max(1, (int)pool->size() / (nP - 1));
  const int64_t step = (ell + per_peer - 1) / per_peer;
  vector<future<void>> res;
  for (int p = 1; p <= nP; ++p) if (p != party)
    for (int64_t i0 = 0; i0 < ell; i0 += step) {
      const int64_t i1 = std::min(i0 + step, ell);
      res.push_back(pool->enqueue([&rows, &member, &d, B, p, i0, i1]() {
        block *am = rows[0].mac[0][p], *ak = rows[0].key[0][p];
        block *cm = rows[0].mac[2][p], *ck = rows[0].key[2][p];
        for (int64_t j = i0; j < i1; ++j) {
          block ma = am[j], ka = ak[j], mc = cm[j], kc = ck[j];
          for (int m = 1; m < B; ++m) {
            const MergeSource src = member(m, j);
            const TripleRow<nP> &r = rows[(size_t)src.row];
            const int64_t q = src.index;
            const block sel = select_mask[d(m, j)];
            ma = ma ^ r.mac[0][p][q];
            ka = ka ^ r.key[0][p][q];
            mc = mc ^ r.mac[2][p][q] ^ (r.mac[0][p][q] & sel);
            kc = kc ^ r.key[2][p][q] ^ (r.key[0][p][q] & sel);
          }
          am[j] = ma;
          ak[j] = ka;
          cm[j] = mc;
          ck[j] = kc;
        }
      }));
    }
  joinNclean(res);
}

// The rotations' merge (Buckets): row m's member of bucket j is its (j + r_m)-th triple,
// and the opened differences d are row-major.
template <int nP>
void merge_combine(const std::vector<TripleRow<nP>> &rows, const Buckets &bk,
                   const unsigned char *d, int party, ThreadPool *pool) {
  const int64_t ell = bk.ell;
  merge_combine<nP>(
      rows, bk.B, ell, [&bk](int m, int64_t j) { return MergeSource{m, bk.member(m, j)}; },
      [d, ell](int m, int64_t j) { return d[(size_t)(m - 1) * ell + j]; }, party, pool);
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_TRIPLE_MERGE_H__
