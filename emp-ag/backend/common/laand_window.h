#ifndef EMP_AG_BACKEND_COMMON_LAAND_WINDOW_H__
#define EMP_AG_BACKEND_COMMON_LAAND_WINDOW_H__

#include "emp-ag/backend/common/fs_hash.h"   // FsHash
#include "emp-tool/runtime/core/block.h"
#include "emp-ag/backend/common/runtime.h"     // ThreadPool, joinNclean
#include <algorithm>
#include <bit>
#include <cstdint>
#include <cstring>
#include <future>
#include <vector>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

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
// The one-lane 2PC path's chunk (LeakyAnd, laand.h). A multiple of 8 rows is a whole
// number of wire bytes at any width, so its chunks cut the frames above only at byte
// boundaries and the stream stays byte for byte the same. Two chunks of 42-bit rows
// (86 KB) are what that path leaves unread per direction at most.
inline constexpr int kLaandFusedChunkRows = 1 << 13;
static_assert(kLaandFusedChunkRows % 8 == 0, "a fused chunk must be whole wire bytes");

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

// Rows narrower than 64 bits on a little-endian host move a word at a time (row(i) gives
// or takes row i's low 64 bits): pack through a 128-bit accumulator that writes the
// stream eight bytes at a time, unpack by one load per row at its first stream byte.
// Wider rows and other hosts take the byte loops; both give the same stream.
inline bool laand_word_rows(int bits) {
  return std::endian::native == std::endian::little && bits < 64;
}
template <class Row>
inline void pack_laand_words_(unsigned char* dst, int64_t rows, int bits, Row row) {
  const uint64_t mask = (uint64_t(1) << bits) - 1;
  unsigned __int128 acc = 0;
  int n = 0;   // bits held in acc, below 64 between rows
  int64_t o = 0;
  for (int64_t i = 0; i < rows; ++i) {
    acc |= (unsigned __int128)(row(i) & mask) << n;
    n += bits;
    if (n >= 64) {
      const uint64_t w = (uint64_t)acc;
      std::memcpy(dst + o, &w, 8);
      o += 8;
      acc >>= 64;
      n -= 64;
    }
  }
  for (; n > 0; n -= 8, acc >>= 8) dst[o++] = (unsigned char)acc;
}
template <class Row>
inline void unpack_laand_words_(const unsigned char* src, int64_t rows, int bits, Row row) {
  const int64_t size = laand_row_wire_bytes(rows, bits);
  const uint64_t mask = (uint64_t(1) << bits) - 1;
  for (int64_t i = 0; i < rows; ++i) {
    const int64_t pos = i * bits, byte = pos >> 3;
    unsigned __int128 w = 0;
    if (byte + 16 <= size) std::memcpy(&w, src + byte, 16);
    else std::memcpy(&w, src + byte, (size_t)(size - byte));
    row(i, (uint64_t)(w >> (pos & 7)) & mask);
  }
}
// A local row is read or written as eight bytes when its buffer has them from the row's
// start: every row before this one, in order, so a later row's own bytes overwrite an
// earlier write's spill. The rest move as their own `stride` bytes.
inline int64_t laand_rows_with_8_bytes(int64_t rows, int stride) {
  return rows - (8 + stride - 1) / stride + 1;
}

// Canonical little-endian bit stream: row i starts at bit i*bits. Unused
// bits in the last wire byte are zero; unused bits of each local row are ignored.
inline void pack_laand_rows(unsigned char* dst, const unsigned char* src,
                            int64_t rows, int bits) {
  const int stride = (bits + 7) / 8;
  const int64_t size = laand_row_wire_bytes(rows, bits);
  if (size == 0) return;
  if (bits % 8 == 0) { std::memcpy(dst, src, size); return; }
  if (laand_word_rows(bits)) {
    const int64_t whole = laand_rows_with_8_bytes(rows, stride);
    pack_laand_words_(dst, rows, bits, [&](int64_t i) {
      uint64_t v = 0;
      if (i < whole) std::memcpy(&v, src + i * stride, 8);
      else std::memcpy(&v, src + i * stride, (size_t)stride);
      return v;
    });
    return;
  }
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
  if (laand_word_rows(bits)) {
    const int64_t whole = laand_rows_with_8_bytes(rows, stride);
    unpack_laand_words_(src, rows, bits, [&](int64_t i, uint64_t v) {
      if (i < whole) std::memcpy(dst + i * stride, &v, 8);
      else std::memcpy(dst + i * stride, &v, (size_t)stride);
    });
    return true;
  }
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

// The same stream from rows held as blocks, each row's bits the low bits of its block. A
// whole-byte width is each row's low bytes in order; other wide widths are staged.
inline void pack_laand_blocks(unsigned char* dst, const block* rows, int64_t n, int bits) {
  if (laand_row_wire_bytes(n, bits) == 0) return;
  if (laand_word_rows(bits)) {
    pack_laand_words_(dst, n, bits, [&](int64_t i) {
      uint64_t v;
      std::memcpy(&v, &rows[i], 8);
      return v;
    });
    return;
  }
  const int stride = (bits + 7) / 8;
  if (bits == 128) { std::memcpy(dst, rows, (size_t)n * sizeof(block)); return; }
  if (bits % 8 == 0) {
    for (int64_t i = 0; i < n; ++i) std::memcpy(dst + i * stride, &rows[i], stride);
    return;
  }
  std::vector<unsigned char> tmp((size_t)n * stride);
  for (int64_t i = 0; i < n; ++i) std::memcpy(&tmp[(size_t)i * stride], &rows[i], stride);
  pack_laand_rows(dst, tmp.data(), n, bits);
}
// Its inverse, each row zero-extended into its block; false on noncanonical padding.
inline bool unpack_laand_blocks(block* rows, const unsigned char* src, int64_t n, int bits) {
  const int64_t size = laand_row_wire_bytes(n, bits);
  if (size == 0) return true;
  if (laand_word_rows(bits)) {
    const int used = (n * bits) % 8;
    if (used != 0 && (src[size - 1] >> used) != 0) return false;
    unpack_laand_words_(src, n, bits, [&](int64_t i, uint64_t v) {
      block b = zero_block;
      std::memcpy(&b, &v, 8);
      rows[i] = b;
    });
    return true;
  }
  const int stride = (bits + 7) / 8;
  if (bits == 128) { std::memcpy(rows, src, (size_t)n * sizeof(block)); return true; }
  if (bits % 8 == 0) {   // whole bytes: no padding to check
    for (int64_t i = 0; i < n; ++i) {
      rows[i] = zero_block;
      std::memcpy(&rows[i], src + i * stride, stride);
    }
    return true;
  }
  std::vector<unsigned char> tmp((size_t)n * stride);
  if (!unpack_laand_rows(tmp.data(), src, n, bits)) return false;
  for (int64_t i = 0; i < n; ++i) {
    rows[i] = zero_block;
    std::memcpy(&rows[i], &tmp[(size_t)i * stride], stride);
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
// prepare(k0, k1) runs first in each stripe's task and may finish windows k0 .. k1 - 1
// (only those: stripes run concurrently), so a stripe is hashed right after it is
// written, while it is still cached. The fold itself does not change.
template <class Prepare>
inline void accumulate_leaky_and_window_bytes(FsHash &feq,
                                              const unsigned char *src,
                                              int L, int gb, ThreadPool *pool,
                                              Prepare &&prepare) {
  const int ns = (L + kFeqStripeElems - 1) / kFeqStripeElems;
  std::vector<char> dg((size_t)ns * FsHash::DIGEST_SIZE);
  vector<future<void>> res;
  for (int s = 0; s < ns; ++s) {
    res.push_back(pool->enqueue([&, s]() {
      const int k0 = s * kFeqStripeElems;
      const int k1 = std::min(L, k0 + kFeqStripeElems);
      prepare(k0, k1);
      FsHash::hash_once(dg.data() + (size_t)s * FsHash::DIGEST_SIZE,
                        src + (size_t)k0 * gb,
                        (size_t)(k1 - k0) * gb);
    }));
  }
  joinNclean(res);
  feq.put(dg.data(), dg.size());
}
inline void accumulate_leaky_and_window_bytes(FsHash &feq,
                                              const unsigned char *src,
                                              int L, int gb, ThreadPool *pool) {
  accumulate_leaky_and_window_bytes(feq, src, L, gb, pool, [](int, int) {});
}

EMP_AG_NAMESPACE_END
#endif
