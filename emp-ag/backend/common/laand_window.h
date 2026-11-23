#ifndef EMP_AG_BACKEND_COMMON_LAAND_WINDOW_H__
#define EMP_AG_BACKEND_COMMON_LAAND_WINDOW_H__

#include "emp-ag/backend/common/fs_hash.h"   // FsHash
#include "emp-tool/runtime/core/block.h"
#include "emp-ag/backend/common/runtime.h"     // ThreadPool, joinNclean
#include <algorithm>
#include <cstdint>
#include <cstring>
#include <future>
#include <vector>

namespace emp::ag {

// Two structural low bits plus ssp random coordinates. Local rows remain
// byte-addressable; only transport concatenates their exact bit windows.
inline int laand_window_bits(int ssp) { return std::min(128, ssp + 2); }
inline int laand_window_bytes(int ssp) { return (laand_window_bits(ssp) + 7) / 8; }
inline unsigned char laand_last_byte_mask(int bits) {
  return static_cast<unsigned char>((1u << ((bits - 1) % 8 + 1)) - 1);
}
inline int64_t laand_row_wire_bytes(int64_t rows, int bits) {
  // Production frames contain at most kLaandRowChunkRows rows.
  return (rows * bits + 7) / 8;
}
inline constexpr int kLaandRowChunkRows = 1 << 16;

// The low `bits` bits of a block.
inline block laand_bits_mask(int bits) {
  unsigned char bytes[sizeof(block)] = {};
  const int n = (bits + 7) / 8;
  std::fill_n(bytes, n, static_cast<unsigned char>(0xff));
  bytes[n - 1] = laand_last_byte_mask(bits);
  block result;
  std::memcpy(&result, bytes, sizeof(result));
  return result;
}
inline block laand_window_mask(int ssp) { return laand_bits_mask(laand_window_bits(ssp)); }

// Canonical little-endian bit stream: row i starts at bit i*bits. Unused
// bits in the last wire byte are zero; unused bits of each local row are ignored.
inline void pack_laand_rows(unsigned char* dst, const unsigned char* src,
                            int64_t rows, int bits) {
  const int stride = (bits + 7) / 8;
  const int64_t size = laand_row_wire_bytes(rows, bits);
  if (size == 0) return;
  if (bits % 8 == 0) { std::memcpy(dst, src, size); return; }
  std::fill_n(dst, size, static_cast<unsigned char>(0));
  for (int64_t i = 0; i < rows; ++i) {
    for (int j = 0; j < stride; ++j) {
      const unsigned v = src[i * stride + j] &
          (j == stride - 1 ? laand_last_byte_mask(bits) : 0xffu);
      const int64_t pos = i * bits + 8 * j;
      const int64_t byte = pos / 8;
      const int shift = pos % 8;
      dst[byte] |= static_cast<unsigned char>(v << shift);
      if (shift != 0 && byte + 1 < size)
        dst[byte + 1] |= static_cast<unsigned char>(v >> (8 - shift));
    }
  }
}

// Zero-extend each row's final byte. Reject noncanonical final wire padding.
inline bool unpack_laand_rows(unsigned char* dst, const unsigned char* src,
                              int64_t rows, int bits) {
  const int stride = (bits + 7) / 8;
  const int64_t size = laand_row_wire_bytes(rows, bits);
  if (size == 0) return true;
  const int used = (rows * bits) % 8;
  if (used != 0 && (src[size - 1] >> used) != 0) return false;
  if (bits % 8 == 0) { std::memcpy(dst, src, size); return true; }
  for (int64_t i = 0; i < rows; ++i) {
    for (int j = 0; j < stride; ++j) {
      const int64_t pos = i * bits + 8 * j;
      const int64_t byte = pos / 8;
      const int shift = pos % 8;
      unsigned v = src[byte] >> shift;
      if (shift != 0 && byte + 1 < size) v |= unsigned(src[byte + 1]) << (8 - shift);
      dst[i * stride + j] = static_cast<unsigned char>(v &
          (j == stride - 1 ? laand_last_byte_mask(bits) : 0xffu));
    }
  }
  return true;
}

// ===== windowed F_eq (nP == 2) =====
// Fixed stripe width (in elements) for the parallel F_eq window fold below. It shapes the
// CHECK VALUE (stripe digests are what the running hash binds), so it must be identical
// at both parties: a compile-time constant, never a function of the local pool size.
inline constexpr int kFeqStripeElems = 1 << 16;

// Fold L windows of gb bytes each (the transmitted bits, zero-padded, contiguous at src)
// into the running F_eq hash. The fold is a fixed two-level hash: the window bytes are
// hashed per kFeqStripeElems-window stripe (independent stripes, so the hashing runs
// pool-parallel), and the ordered stripe digests feed the running feq. Collision
// resistance composes across the levels, so this binds exactly the window bytes; both
// parties use the same stripe constant and derive the same stripe count from the common
// L. One terminal symmetric F_eq fires per call; the caller owns it.
inline void accumulate_leaky_and_window_bytes(FsHash &feq,
                                              const unsigned char *src,
                                              int L, int gb, ThreadPool *pool) {
  const int ns = (L + kFeqStripeElems - 1) / kFeqStripeElems;
  std::vector<char> dg((size_t)ns * FsHash::DIGEST_SIZE);
  vector<future<void>> res;
  for (int s = 0; s < ns; ++s) {
    res.push_back(pool->enqueue([&, s]() {
      const int k0 = s * kFeqStripeElems;
      const int k1 = std::min(L, k0 + kFeqStripeElems);
      FsHash::hash_once(dg.data() + (size_t)s * FsHash::DIGEST_SIZE,
                        src + (size_t)k0 * gb,
                        (size_t)(k1 - k0) * gb);
    }));
  }
  joinNclean(res);
  feq.put(dg.data(), dg.size());
}

}  // namespace emp::ag
#endif
