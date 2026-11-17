// AES-128 with split ownership: party 1 holds the plaintext block, party 2 holds
// the key, and the parties jointly compute the ciphertext, revealed to party 1 and
// checked against the FIPS-197 C.1 known answer. The cipher is emp-tool's typed
// AES kernel (emp::circuit::crypto::aes128_encrypt) over the session's gate
// context — bit convention LSB-first within each byte, bytes in natural order.
// (The stored "aes128" BooleanProgram builtin via sess.run_artifact is the other
// route to the same circuit; see test/agmpc_artifact.cpp.) Run from the repo root:
//
//   ./runN 3 build/bin/example_aes
#include <emp-ag/emp-ag.h>
#include "emp-tool/circuits/crypto/aes128.h"
#include <array>
#include <cstdio>
#include <string>
using namespace emp;

constexpr int nP = 3;

// 32 hex chars -> 128 bits, LSB-first within each byte (the BitVec clear layout).
static std::array<bool, 128> bits_from_hex(const char *hex) {
  std::array<bool, 128> a{};
  for (int i = 0; i < 16; ++i) {
    unsigned v = 0;
    sscanf(hex + 2 * i, "%2x", &v);
    for (int b = 0; b < 8; ++b) a[8 * i + b] = (v >> b) & 1;
  }
  return a;
}

static std::string hex_of(const std::array<bool, 128> &bits) {
  char buf[33] = {};
  for (int i = 0; i < 16; ++i) {
    unsigned v = 0;
    for (int b = 0; b < 8; ++b) v |= (unsigned)bits[8 * i + b] << b;
    snprintf(buf + 2 * i, 3, "%02x", v);
  }
  return std::string(buf, 32);
}

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(), /*ip table*/ nullptr, &pool);

  using Ctx   = AGMPCSession<nP>::ctx_t;
  using Block = BitVec_T<Ctx, 128>;

  // FIPS-197 Appendix C.1: AES-128(000102...0e0f, 00112233...eeff) = 69c4e0d8...
  const char *pt_hex  = "00112233445566778899aabbccddeeff";
  const char *key_hex = "000102030405060708090a0b0c0d0e0f";
  const char *ct_hex  = "69c4e0d86a7b0430d8cdb78070b4c55a";

  auto pt  = sess.input<Block>(1, party == 1 ? bits_from_hex(pt_hex)  : std::array<bool, 128>{});
  auto key = sess.input<Block>(2, party == 2 ? bits_from_hex(key_hex) : std::array<bool, 128>{});
  auto ct  = sess.reveal(circuit::crypto::aes128_encrypt(sess.ctx(), pt, key), /*recipient*/ 1);

  if (party == 1) {
    std::string got = hex_of(ct.value());
    printf("AES-128(pt @ party 1, key @ party 2) = %s\n", got.c_str());
    return got == ct_hex ? 0 : 1;                  // the ctest verdict
  }
  return 0;
}
