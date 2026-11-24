// Share mode on AGMPCSession: Boolean circuits evaluated on aShares (authenticated GMW).
// Every party derives the same random dense circuits and inputs from fixed seeds. Inputs
// come from every owner (share_input), from the pool (share_random, revealed to get their
// values) and as public bits (share_public); each circuit is evaluated (share_evaluate) and
// its outputs revealed to everyone and to one party, then checked against the circuit
// evaluated in the clear. The evaluation takes one flight per AND layer, so the layer
// count must equal the circuit's AND depth. test/CMakeLists.txt builds it at nP = 2, 3, 4
// and with an 80-bit tag; the SHARE_* switches select the misuse and cheating cases.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "test_options.h"
#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <memory>
#include <random>
#include <vector>

using namespace emp;
using namespace emp::circuit;

#ifndef SHARE_NP
#define SHARE_NP 2
#endif
constexpr int nP = SHARE_NP;
using AgSession = AGMPCSession<nP>;
using Wires = AgSession::SharedWires;

static int fails = 0;
static void check(bool ok, const char *what, int party) {
  if (!ok) {
    std::printf("  [FAIL] P%d: %s\n", party, what);
    ++fails;
  }
}

// A random dense circuit over ni inputs: ng gates, about half of them AND, some repeated
// constants, and `no` outputs drawn from every wire.
static BooleanProgram random_circuit(std::mt19937_64 &rng, uint32_t ni, uint32_t ng, uint32_t no) {
  BooleanProgram p;
  p.num_inputs = ni;
  p.num_wires = ni + ng;
  for (uint32_t g = 0; g < ng; ++g) {
    const uint32_t out = ni + g;
    Gate x;
    x.out = out;
    const uint64_t r = rng() % 12;
    if (out == 0 || r == 11) {
      x.op = (rng() & 1) ? Op::Const1 : Op::Const0;
    } else if (r < 6) {
      x.op = Op::And;
      x.in0 = (uint32_t)(rng() % out);
      x.in1 = (uint32_t)(rng() % out);
    } else if (r < 9) {
      x.op = Op::Xor;
      x.in0 = (uint32_t)(rng() % out);
      x.in1 = (uint32_t)(rng() % out);
    } else {
      x.op = Op::Not;
      x.in0 = (uint32_t)(rng() % out);
    }
    p.gates.push_back(x);
  }
  for (uint32_t k = 0; k < no; ++k) p.outputs.push_back((uint32_t)(rng() % p.num_wires));
  return p;
}

static std::vector<uint8_t> clear_eval(const BooleanProgram &p, const std::vector<uint8_t> &in,
                                       uint32_t *and_depth) {
  std::vector<uint8_t> w(p.num_wires, 0);
  std::vector<uint32_t> depth(p.num_wires, 0);
  std::copy(in.begin(), in.end(), w.begin());
  uint32_t D = 0;
  for (const Gate &g : p.gates) {
    switch (g.op) {
      case Op::And:
        w[g.out] = w[g.in0] & w[g.in1];
        depth[g.out] = std::max(depth[g.in0], depth[g.in1]) + 1;
        break;
      case Op::Xor:
        w[g.out] = w[g.in0] ^ w[g.in1];
        depth[g.out] = std::max(depth[g.in0], depth[g.in1]);
        break;
      case Op::Not: w[g.out] = w[g.in0] ^ 1; depth[g.out] = depth[g.in0]; break;
      case Op::Const0: w[g.out] = 0; break;
      case Op::Const1: w[g.out] = 1; break;
    }
    D = std::max(D, depth[g.out]);
  }
  *and_depth = D;
  std::vector<uint8_t> out;
  for (uint32_t o : p.outputs) out.push_back(w[o]);
  return out;
}

static std::vector<uint8_t> random_bits(std::mt19937_64 &rng, size_t n) {
  std::vector<uint8_t> v(n);
  for (uint8_t &b : v) b = (uint8_t)(rng() & 1);
  return v;
}

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));
  const TestArgs args(argc, argv, {"no_bank", TEST_OPTION_ARGS});
  const ag::ProtocolOptions opts = test_options(args);
  if (args.has("no_bank")) {
    AgSession sess(party, peer_port(), nullptr, &pool, opts);   // the leaky ANDs keep no bank
    {
      std::mt19937_64 rng(1);
      const BooleanProgram p = random_circuit(rng, 4, 20, 2);
      (void)sess.share_evaluate(p, sess.share_random(4));
      return 1;
    }
  }
  AgSession sess(party, peer_port(), nullptr, &pool, opts, 40, -1, std::nullopt, BaseOtKind::CSW, -1, -1,
               ag::cut_and_choose_prep<nP>(1024));

  for (int t = 0; t < 6; ++t) {
    std::mt19937_64 rng(9000 + (uint64_t)t);
    // Inputs: 1-5 bits from every party, then a few random shares, then public bits.
    std::vector<int> owner_of;
    std::vector<uint8_t> clear;
    Wires in;
    for (int o = 1; o <= nP; ++o) {
      const std::vector<uint8_t> bits = random_bits(rng, 1 + rng() % 5);
      const Wires w = sess.share_input(o, party == o ? bits : std::vector<uint8_t>(bits.size(), 0));
      in = Wires::concat({&in, &w});
      clear.insert(clear.end(), bits.begin(), bits.end());
    }
    const Wires r = sess.share_random(1 + (int64_t)(rng() % 4));
    const std::optional<emp::session::Bits> rv = sess.share_reveal(r, PUBLIC);
    check(rv.has_value() && rv->size() == r.size(), "random shares revealed to everyone", party);
    in = Wires::concat({&in, &r});
    clear.insert(clear.end(), rv->begin(), rv->end());
    const std::vector<uint8_t> pub = random_bits(rng, 1 + rng() % 3);
    const Wires pw = sess.share_public(pub);
    in = Wires::concat({&in, &pw});
    clear.insert(clear.end(), pub.begin(), pub.end());

    const BooleanProgram p = random_circuit(rng, (uint32_t)in.size(), 30 + (uint32_t)(rng() % 90),
                                            3 + (uint32_t)(rng() % 6));
    uint32_t depth = 0;
    const std::vector<uint8_t> want = clear_eval(p, clear, &depth);
    const int64_t layers_before = sess.share_layers();
    const Wires out = sess.share_evaluate(p, in);
    check(sess.share_layers() - layers_before == (int64_t)depth, "one flight per AND layer", party);
    const std::optional<emp::session::Bits> got = sess.share_reveal(out, PUBLIC);
    check(got.has_value() && *got == want, "outputs revealed to everyone", party);
    const int to = 1 + (int)(rng() % nP);
    const std::optional<emp::session::Bits> mine = sess.share_reveal(out, to);
    check(party == to ? (mine.has_value() && *mine == want) : !mine.has_value(),
          "outputs revealed to one party", party);

    // Local XOR, and XOR with public bits.
    const Wires x = out ^ out.slice(0, out.size());
    const std::vector<uint8_t> mask = random_bits(rng, out.size());
    const Wires y = sess.share_xor_public(out, mask);
    const std::optional<emp::session::Bits> xv = sess.share_reveal(x, PUBLIC);
    const std::optional<emp::session::Bits> yv = sess.share_reveal(y, PUBLIC);
    std::vector<uint8_t> want_y(want.size());
    for (size_t i = 0; i < want.size(); ++i) want_y[i] = want[i] ^ mask[i];
    check(xv.has_value() && *xv == std::vector<uint8_t>(out.size(), 0), "local XOR", party);
    check(yv.has_value() && *yv == want_y, "XOR with public bits", party);
  }

  if (fails) {
    std::printf("P%d: FAIL (%d)\n", party, fails);
    return 1;
  }
  if (party == 1) std::printf("share evaluation: all cases passed\n");
  return 0;
}
