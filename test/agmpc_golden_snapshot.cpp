// AG-MPC golden snapshot — pins a strategy x circuit matrix and gates on OUTPUT
// CORRECTNESS (not a frozen transcript), by necessity:
//
//   * the transcript is NOT byte-reproducible: Delta and the COT choices are drawn from
//     hardware-seeded PRGs, so the wire bytes differ run to run.
//   * so the gate is OUTPUT CORRECTNESS vs a cleartext oracle (digest==OpenSSL in the
//     crypto cases), across the matrix, at nP=2, 3 and 4. This is determinism-
//     independent (outputs are fixed given inputs).
//
// The per-channel transcript volume + folded digest are printed as a NON-GATING
// diagnostic so a change's effect on the wire is eyeball-visible (and re-baselineable),
// never asserted.
//
// Build-time nP is GOLDEN_NP (CMake instantiates np2, np3 and np4). SPMD: every party
// runs the same code; party 1 owns `a`, party 2 owns `b`; output revealed to party 1,
// which checks.
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/builtins.h"
#include "emp-tool/circuits/frontend/rec.h"
#include "emp-tool/circuits/frontend/compose.h"
#include "emp-ag/emp-ag.h"
#include "test_options.h"
#include "clear_oracle.h"
#include <array>
#include <cstdio>
#include <vector>
using namespace std;
using namespace emp;
namespace cf = emp::frontend;

#ifndef GOLDEN_NP
#define GOLDEN_NP 3
#endif
static const int nP = GOLDEN_NP;

using Ctx = AGMPCSession<GOLDEN_NP>::ctx_t;
using UInt32 = UInt_T<Ctx, 32>;

// Non-gating transcript diagnostic: fold every peer channel's rolling digest + byte
// volume into one block and print it. NOT asserted (the protocol is non-deterministic),
// but re-baselineable by eye run to run.
static block transcript_fp(NetIOMP<GOLDEN_NP> &io, int party, uint64_t bytes) {
  RO ro("agmpc-golden-diag", zero_block);
  for (int q = 1; q <= nP; ++q)
    if (q != party) {
      ro.absorb(io.get(q, false)->get_digest());  // ios[q]
      ro.absorb(io.get(q, true)->get_digest());   // ios2[q]
    }
  ro.absorb(makeBlock(bytes, (uint64_t)party));
  return ro.squeeze_block();
}

static void print_hex(block b) {
  uint64_t w[2];
  memcpy(w, &b, sizeof(b));
  printf("0x%016llx%016llx", (unsigned long long)w[1], (unsigned long long)w[0]);
}

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  const ag::ProtocolOptions opts = test_options(TestArgs(argc, argv, {TEST_OPTION_ARGS}));
  int port = peer_port();
  if (party > nP) return 0;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(ag::default_pool_size(nP));
  io.flush();

  const uint32_t A = 0x12345678u, B = 0x9abcdef0u;
  bool ok = true;

  // Each case gets a fresh session so the per-case transcript volume is isolated.
  // `expect` is the value party 1 must see; `body` runs the protocol and returns
  // party-1's revealed optional as a uint64.
  auto run_case = [&](const char *name, uint64_t expect, auto body) {
    AGMPCSession<nP> sess(&io, &pool, party, opts);
    int64_t before = io.count();
    std::optional<uint64_t> got = body(sess);
    uint64_t used = (uint64_t)(io.count() - before);
    block tfp = transcript_fp(io, party, used);
    if (party == 1) {
      bool good = got.has_value() && got.value() == expect;
      ok &= good;
      printf("  agmpc-golden[np=%d][%-12s] diag=", nP, name);
      print_hex(tfp);
      printf("  bytes=%llu  out=%s\n", (unsigned long long)used, good ? "GOOD!" : "BAD!");
    }
  };

  auto uint_in = [&](AGMPCSession<nP> &s, int owner, uint32_t v) {
    return s.input<UInt32>(owner, s.party() == owner ? v : 0u);
  };
  auto reveal_u = [&](AGMPCSession<nP> &s, auto w) -> std::optional<uint64_t> {
    auto r = s.reveal(w, 1);
    if (!r.has_value()) return std::nullopt;
    return (uint64_t)(uint32_t)r.value();
  };

  // ---- UInt32 matrix: party1 owns a, party2 owns b; reveal to party 1 -------------
  run_case("input_only", A, [&](AGMPCSession<nP> &s) {
    return reveal_u(s, uint_in(s, 1, A));
  });
  run_case("xor_only", (uint64_t)(A ^ B), [&](AGMPCSession<nP> &s) {
    return reveal_u(s, uint_in(s, 1, A) ^ uint_in(s, 2, B));
  });
  run_case("and_only", (uint64_t)(A & B), [&](AGMPCSession<nP> &s) {
    return reveal_u(s, uint_in(s, 1, A) & uint_in(s, 2, B));
  });
  run_case("add_direct", (uint64_t)(A + B), [&](AGMPCSession<nP> &s) {
    return reveal_u(s, uint_in(s, 1, A) + uint_in(s, 2, B));
  });
  run_case("add_body", (uint64_t)(A + B), [&](AGMPCSession<nP> &s) {
    auto a = uint_in(s, 1, A), b = uint_in(s, 2, B);
    return reveal_u(s, s.run([](auto x, auto y) { return x + y; }, a, b));
  });
  run_case("add_compiled", (uint64_t)(A + B), [&](AGMPCSession<nP> &s) {
    auto c = cf::compile<rec::UInt<32>, rec::UInt<32>>([](auto x, auto y) { return x + y; });
    auto a = uint_in(s, 1, A), b = uint_in(s, 2, B);
    return reveal_u(s, s.run(c, a, b));
  });

  // ---- compose: call a compiled unit f(s)=3s+1, chained 5x (output->input) --------
  {
    auto unit = cf::compile_linear<rec::UInt<32>>(
        [](auto s) { return s * s.constant(3u) + s.constant(1u); });
    const uint32_t S = 0xDEADBEEFu;
    uint32_t expect = S;
    for (int i = 0; i < 5; ++i) expect = expect * 3u + 1u;
    run_case("compose_chain", (uint64_t)expect, [&](AGMPCSession<nP> &s) {
      auto body = [&unit](auto &ctx, auto st) {
        for (int i = 0; i < 5; ++i) st = cf::run(ctx, unit, st);
        return st;
      };
      auto s0 = uint_in(s, 1, S);
      return reveal_u(s, s.run_compose(body, s0));
    });
  }

  // ---- AES-128 / SHA-256 via run_artifact vs ClearCtx oracle (digest==OpenSSL) -----
  // Party 2 owns all input bits; output revealed to party 1 and checked vs the SAME
  // program on the plaintext oracle (the bit-convention cancels).
  auto bitvec_case = [&](const char *name, const char *cir, auto Nin, auto Nout) {
    constexpr int NI = decltype(Nin)::value, NO = decltype(Nout)::value;
    const circuit::BooleanProgram &prog = circuit::builtin_circuit(cir);
    expecting((int)prog.num_inputs == NI && (int)prog.outputs.size() == NO,
              "agmpc-golden: builtin dims != expected");
    std::array<bool, NI> in_bits{};
    for (int i = 0; i < NI; ++i) in_bits[i] = ((i * 7 + 3) % 5) == 0;
    auto oracle = agmpc_test::clear_eval(prog, vector<uint8_t>(in_bits.begin(), in_bits.end()));

    AGMPCSession<nP> sess(&io, &pool, party, opts);
    int64_t before = io.count();
    auto in = sess.input<BitVec_T<Ctx, NI>>(2, party == 2 ? in_bits : std::array<bool, NI>{});
    auto out = sess.reveal(sess.run_artifact<BitVec_T<Ctx, NO>>(prog, in), 1);
    uint64_t used = (uint64_t)(io.count() - before);
    block tfp = transcript_fp(io, party, used);
    if (party == 1) {
      bool good = out.has_value() && (int)oracle.size() == NO;
      for (int i = 0; i < NO && good; ++i) good = (out.value()[i] == oracle[i]);
      ok &= good;
      printf("  agmpc-golden[np=%d][%-12s] diag=", nP, name);
      print_hex(tfp);
      printf("  bytes=%llu  out=%s\n", (unsigned long long)used, good ? "GOOD!" : "BAD!");
    }
  };
  bitvec_case("aes128", "aes128", std::integral_constant<int, 256>{}, std::integral_constant<int, 128>{});
  bitvec_case("sha256_256", "sha256_256", std::integral_constant<int, 256>{}, std::integral_constant<int, 256>{});

  if (party == 1)
    printf("agmpc_golden_snapshot[np=%d]: %s\n", nP, ok ? "GOOD!" : "BAD!");
  return (party == 1 && !ok) ? 1 : 0;
}
