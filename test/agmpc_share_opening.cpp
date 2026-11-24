// Openings the caller checks itself (AGMPCSession::share_opening, absorb_expected_macs), as an
// application does when one digest per pair also covers values of its own. Every party sends
// each peer its share bits and a digest of its MACs on them under that peer's key, and checks
// each peer's digest against the MACs emp-ag expects for the bits it received. The opened
// values are checked against share_reveal. The last round opens while a Computation job is
// outstanding, between prepare_computation and run_computation, as an application does
// between its offline and online phases. The test's own messages share the session's mesh,
// in turn with the session. flip (test_args.h): party 2 flips the first bit it sends party 1,
// which party 1's digest check must catch.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "test_args.h"
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <random>
#include <vector>

using namespace emp;

#ifndef SHARE_OPEN_NP
#define SHARE_OPEN_NP 2
#endif
constexpr int nP = SHARE_OPEN_NP;
using AgSession = AGMPCSession<nP>;
using Wires = AgSession::SharedWires;
using Bits = emp::session::Bits;

static Bits random_bits(std::mt19937_64 &rng, size_t n) {
  Bits v(n);
  for (uint8_t &b : v) b = (uint8_t)(rng() & 1);
  return v;
}

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  if (party > nP) return 0;
  NetIOMP<nP> io(party, peer_port());
  ThreadPool pool(ag::default_pool_size(nP));
  AgSession sess(&io, &pool, party);
  int fails = 0;
  const bool flip = TestArgs(argc, argv, {"flip"}).has("flip");

  for (int t = 0; t < 3; ++t) {
    std::mt19937_64 rng(700 + (uint64_t)t);
    Wires v;
    for (int o = 1; o <= nP; ++o) {
      const Bits bits = random_bits(rng, 1 + rng() % 6);
      const Wires w = sess.share_input(o, party == o ? bits : Bits(bits.size(), 0));
      v = Wires::concat({&v, &w});
    }
    const Wires r = sess.share_random(1 + (int64_t)(rng() % 7));
    v = Wires::concat({&v, &r});
    const size_t n = v.size();

    // The last round: a job outstanding, its Public input negated into a Public output.
    std::optional<AgSession::job_t> job;
    Bits q;
    if (t == 2) {
      auto prog = std::make_shared<emp::circuit::BooleanProgram>();
      prog->num_inputs = 4;
      for (uint32_t k = 0; k < 4; ++k) {
        emp::circuit::Gate g;
        g.op = emp::circuit::Op::Not;
        g.in0 = k;
        g.out = 4 + k;
        prog->gates.push_back(g);
        prog->outputs.push_back(4 + k);
      }
      prog->num_wires = 8;
      auto art = std::make_shared<emp::circuit::ComputationArtifact>();
      art->program = prog;
      art->io.inputs.push_back({4, emp::circuit::InputKind::Public, PUBLIC});
      art->io.outputs.push_back({4, emp::circuit::OutputKind::Public, PUBLIC});
      job.emplace(sess.prepare_computation(art));
      q = random_bits(rng, 4);
    }

    const AgSession::ShareOpening op = sess.share_opening(v);
    for (int j = 1; j <= nP; ++j) if (j != party) {
      emp::Hash h;
      h.put(&t, sizeof(t));
      h.put_block(op.macs[(size_t)j].data(), (int64_t)n);
      char dg[emp::Hash::DIGEST_SIZE];
      h.digest(dg);
      std::vector<unsigned char> sent = op.bits;
      if (flip && party == 2 && j == 1) sent[0] ^= 1;
      io.send_data(j, sent.data(), n);
      io.send_data(j, dg, sizeof(dg));
      io.flush(j);
    }
    std::vector<unsigned char> opened = op.bits;
    for (int i = 1; i <= nP; ++i) if (i != party) {
      std::vector<unsigned char> got(n);
      char dg[emp::Hash::DIGEST_SIZE], want[emp::Hash::DIGEST_SIZE];
      io.recv_data(i, got.data(), n);
      io.recv_data(i, dg, sizeof(dg));
      emp::Hash h;
      h.put(&t, sizeof(t));
      sess.absorb_expected_macs(h, v, i, got.data());
      h.digest(want);
      expecting(std::memcmp(want, dg, sizeof(dg)) == 0,
                "share opening: a peer's bits do not match its MACs");
      for (size_t k = 0; k < n; ++k) opened[k] ^= (unsigned char)(got[k] & 1);
    }
    if (job) {
      emp::session::RawBindings b;
      b.inputs.resize(1);
      b.inputs[0] = q;
      const emp::session::RawResult res = sess.run_computation(std::move(*job), b);
      bool good = res.outputs[0].has_value();
      for (size_t k = 0; good && k < 4; ++k) good = (*res.outputs[0])[k] == (q[k] ^ 1);
      if (!good) {
        std::printf("  [FAIL] P%d: the job run after the opening\n", party);
        ++fails;
      }
    }
    const std::optional<Bits> rv = sess.share_reveal(v, PUBLIC);
    if (!rv.has_value() || *rv != Bits(opened.begin(), opened.end())) {
      std::printf("  [FAIL] P%d: round %d: the opening differs from share_reveal\n", party, t);
      ++fails;
    }
  }

  if (fails) return 1;
  if (party == 1) std::printf("share opening: all cases passed\n");
  return 0;
}
