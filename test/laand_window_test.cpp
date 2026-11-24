#include "emp-ag/backend/common/laand_window.h"
#include <array>
#include <cstdio>
#include <vector>

int main() {
  using namespace emp::ag;
  for (int ssp = 1; ssp <= 126; ++ssp) {
    const int bits = ssp + 2, stride = (bits + 7) / 8;
    std::array<unsigned char, 16> mask{};
    const emp::block m = laand_window_mask(ssp);
    std::memcpy(mask.data(), &m, sizeof(m));
    for (int bit = 0; bit < 128; ++bit)
      if (((mask[bit / 8] >> (bit % 8)) & 1) != (bit < bits)) return 1;
    for (int64_t n : {0, 1, 2, 7, 8, 9, 31, 256, 65535, 65536, 65537}) {
      // Exercise chunk edges for deployed widths, all row alignments otherwise.
      if (n > 256 && bits != 41 && bits != 42 && bits != 128) continue;
      std::vector<unsigned char> source(n * stride), unpacked(n * stride);
      for (size_t i = 0; i < source.size(); ++i)
        source[i] = static_cast<unsigned char>((i * 173 + i / 7 + 91) & 255);
      const int64_t size = (n * bits + 7) / 8;
      std::vector<unsigned char> wire(size + 2, 0xa5), oracle(size, 0);
      // Independent bit-at-a-time definition; not a pack/unpack round trip alone.
      for (int64_t i = 0; i < n; ++i)
        for (int b = 0; b < bits; ++b)
          oracle[(i * bits + b) / 8] |=
              ((source[i * stride + b / 8] >> (b % 8)) & 1)
                  << ((i * bits + b) % 8);
      pack_laand_rows(wire.data() + 1, source.data(), n, bits);
      if (wire.front() != 0xa5 || wire.back() != 0xa5 ||
          !std::equal(oracle.begin(), oracle.end(), wire.begin() + 1)) return 2;
      if (!unpack_laand_rows(unpacked.data(), oracle.data(), n, bits)) return 3;
      for (int64_t i = 0; i < n; ++i)
        for (int b = 0; b < stride * 8; ++b) {
          const int want = b < bits ? (source[i * stride + b / 8] >> (b % 8)) & 1 : 0;
          if (((unpacked[i * stride + b / 8] >> (b % 8)) & 1) != want) return 4;
        }
      // The block forms: the same stream from rows in blocks whose bytes past the row are
      // junk, and back into zero-extended blocks.
      std::vector<emp::block> blocks(n), unblocked(n);
      for (int64_t i = 0; i < n; ++i) {
        std::array<unsigned char, 16> b{};
        std::memcpy(b.data(), source.data() + i * stride, stride);
        for (int j = stride; j < 16; ++j) b[j] = static_cast<unsigned char>(i * 31 + j * 7 + 1);
        std::memcpy(&blocks[i], b.data(), sizeof(emp::block));
      }
      std::vector<unsigned char> wire2(size + 2, 0xa5);
      pack_laand_blocks(wire2.data() + 1, blocks.data(), n, bits);
      if (wire2.front() != 0xa5 || wire2.back() != 0xa5 ||
          !std::equal(oracle.begin(), oracle.end(), wire2.begin() + 1)) return 6;
      if (!unpack_laand_blocks(unblocked.data(), oracle.data(), n, bits)) return 7;
      for (int64_t i = 0; i < n; ++i) {
        std::array<unsigned char, 16> b{};
        std::memcpy(b.data(), &unblocked[i], sizeof(emp::block));
        for (int bit = 0; bit < 128; ++bit) {
          const int want = bit < bits ? (source[i * stride + bit / 8] >> (bit % 8)) & 1 : 0;
          if (((b[bit / 8] >> (bit % 8)) & 1) != want) return 8;
        }
      }
      if (n * bits % 8 != 0) {
        oracle.back() |= 1u << (n * bits % 8);
        if (unpack_laand_rows(unpacked.data(), oracle.data(), n, bits)) return 5;
        if (unpack_laand_blocks(unblocked.data(), oracle.data(), n, bits)) return 9;
      }
    }
  }
  std::puts("laand_window_test: all widths, boundary rows, projection and padding passed, "
            "byte and block forms");
  return 0;
}
