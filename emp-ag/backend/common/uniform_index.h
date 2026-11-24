#ifndef EMP_AG_BACKEND_COMMON_UNIFORM_INDEX_H__
#define EMP_AG_BACKEND_COMMON_UNIFORM_INDEX_H__

#include "emp-tool/runtime/crypto/prg.h"
#include <cstdint>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

// An exactly uniform integer in [0, bound). A plain `word % bound` is biased unless bound
// divides the word range; the bucketing proof assumes uniform rotations. Threshold
// rejection over a little-endian uint64_t is exact and deterministic across
// architectures, and rejects with probability below 2^-33 for bound <= INT_MAX. Each
// attempt consumes one PRG block.
inline int64_t uniform_index(PRG &prg, int64_t bound) {
  expecting(bound > 0, "uniform_index: bound must be positive");
  const uint64_t n = (uint64_t)bound;
  const uint64_t threshold = (uint64_t(0) - n) % n;
  uint64_t raw;
  do {
    unsigned char bytes[8];
    prg.random_data_unaligned(bytes, sizeof(bytes));
    raw = 0;
    for (int i = 0; i < 8; ++i) raw |= (uint64_t)bytes[i] << (8 * i);
  } while (raw < threshold);
  return (int64_t)(raw % n);
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_COMMON_UNIFORM_INDEX_H__
