// A computation whose Party slot is bound to a value the session already holds
// authenticated (AGMPCSession::run_computation with authenticated bundles), on COTs
// drawn one way from the session's own stream for the job (AGMPCSession::draw_cots).
//
// Party 1 draws 32 COTs as the sender toward party 2, and party 2 as the receiver, so
// party 2's choices k are authenticated under party 1's global key: M = K ^ k * Delta_1.
// The test checks that relation and the per-stream counts. The COTs make one-sided aShare
// bundles of k: party 2's share is k with MAC M, party 1's share is 0. A computation
// takes k in party 2's slot, bound to those bundles, and party 1's x in its own slot,
// and gives party 1 k | x. A second, ordinary computation then runs on the same
// session: its two streams have drawn different counts, and stay in step.
//
// The COTs are drawn after prepare_computation and never flushed here: run_computation
// runs the deferred COT check before it opens the authenticated slot.
//
// case=1 (test_args.h): party 2 claims the other value of k's first bit (bit 0 of its MAC
// flipped), and the opening's MAC check must abort.
// The slot is declared at prepare_computation, as the run requires, so its mask is never
// opened to party 2 on its own.
// AUTH_NP=3: three parties; prepare_computation refuses the authenticated slot before it
// sends anything.
// case=3: the COTs are drawn from the share pool directly while the job is outstanding,
// which the pool refuses.
// case=4: the pool's COT check is run directly while the job is outstanding, which the
// pool refuses.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "test_args.h"
#include <cstdint>
#include <cstdio>
#include <memory>
#include <optional>
#include <vector>

using namespace emp;
using namespace emp::circuit;

#ifndef AUTH_NP
#define AUTH_NP 2
#endif
constexpr int nP = AUTH_NP;
constexpr int W = 32;
// One-direction draws need the SoftSpoken mint, whatever the build's default.
using Cfg = ag::GarbleConfig<ag::Auth::EMP_AG_GARBLE_AUTH, ag::Delivery::EMP_AG_GARBLE_DELIVERY,
                             ag::Cot::SoftSpoken>;
using AgSession = AGMPCSession<nP, Cfg>;

// Slot 0: party 2's W bits (k); slot 1: party 1's W bits (x). Output to party 1:
// k | x = (k & x) ^ (k ^ x), bit by bit.
static ComputationArtifact or_computation() {
  auto p = std::make_shared<BooleanProgram>();
  p->num_inputs = 2 * W;
  p->num_wires = 2 * W + 3 * W;
  for (uint32_t i = 0; i < (uint32_t)W; ++i) {
    const uint32_t a = 2 * W + 3 * i;
    Gate g_and, g_xor, g_or;
    g_and.op = Op::And; g_and.in0 = i; g_and.in1 = W + i; g_and.out = a;
    g_xor.op = Op::Xor; g_xor.in0 = i; g_xor.in1 = W + i; g_xor.out = a + 1;
    g_or.op = Op::Xor;  g_or.in0 = a;  g_or.in1 = a + 1;  g_or.out = a + 2;
    p->gates.push_back(g_and);
    p->gates.push_back(g_xor);
    p->gates.push_back(g_or);
    p->outputs.push_back(a + 2);
  }
  ComputationArtifact art;
  art.program = std::move(p);
  art.io.inputs.push_back({(uint32_t)W, InputKind::Party, 2});
  art.io.inputs.push_back({(uint32_t)W, InputKind::Party, 1});
  art.io.outputs.push_back({(uint32_t)W, OutputKind::Party, 1});
  validate_computation(art);
  return art;
}

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  const int port = peer_port();
  if (party > nP) return 0;
  const int auth_case = (int)TestArgs(argc, argv, {"case"}).num("case", 0);
#if AUTH_NP == 3
  (void)auth_case;
  {
    NetIOMP<nP> io(party, port);
    ThreadPool pool(ag::default_pool_size(nP));
    AgSession sess(&io, &pool, party);
    auto job = sess.prepare_computation(std::make_shared<const ComputationArtifact>(or_computation()),
                                        {}, {1, 0});
    ag::AShareBundleVec<nP> bundles(W);
    emp::session::RawBindings b;
    b.inputs.resize(2);
    const std::vector<const ag::AShareBundle<nP> *> authenticated = {bundles.data(), nullptr};
    (void)sess.run_computation(std::move(job), b, authenticated);
    return 1;   // unreachable: three parties refuse authenticated slots
  }
#else
  const int peer = 3 - party;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(ag::default_pool_size(nP));
  AgSession sess(&io, &pool, party);
  ag::AShareSource<nP> &abit = *sess.protocol().abit;
  auto art = std::make_shared<const ComputationArtifact>(or_computation());

  auto job = sess.prepare_computation(art, {}, {1, 0});   // slot 0 takes an authenticated value

  // Party 1 sends on its stream to party 2; party 2 receives on it.
  const bool as_sender = party == 1;
  const int64_t before = sess.protocol().abit->cots_drawn(peer, as_sender);
  std::vector<block> cot(W);
  if (auth_case == 3) {
    abit.draw_cots(peer, as_sender, cot.data(), W);
    return 1;   // unreachable: the pool refuses a direct draw while the job is outstanding
  }
  if (auth_case == 4) {
    abit.maybe_flush_cot_check();
    return 1;   // unreachable: likewise the pool's own COT check
  }
  sess.draw_cots(job, peer, as_sender, cot.data(), W);
  expecting(sess.protocol().abit->cots_drawn(peer, as_sender) == before + W &&
                sess.protocol().abit->cots_drawn(peer, !as_sender) == before,
            "agmpc_computation_authenticated: draw_cots() counted on the wrong stream");

  // Test only: party 2 shows party 1 its MACs, which party 1 checks against its keys.
  std::vector<block> mac(W);
  uint32_t k = 0;
  if (party == 2) {
    for (int i = 0; i < W; ++i) k |= (uint32_t)getLSB(cot[(size_t)i]) << i;
    io.send_data(1, cot.data(), W * sizeof(block));
    io.flush(1);
  } else {
    io.recv_data(2, mac.data(), W * sizeof(block));
    const block D = abit.delta();
    for (int i = 0; i < W; ++i) {
      const block want = getLSB(mac[(size_t)i]) ? (cot[(size_t)i] ^ D) : cot[(size_t)i];
      expecting(getLSB(cot[(size_t)i]) == 0 && cmpBlock(&want, &mac[(size_t)i], 1),
                "agmpc_computation_authenticated: a drawn COT breaks M = K ^ b * Delta");
      k |= (uint32_t)getLSB(mac[(size_t)i]) << i;
    }
  }

  // One-sided bundles of k: party 2 holds k with its MAC under party 1's key, party 1
  // holds the key; party 1's share is 0, with a zero MAC and key.
  const int slot = ag::peer_slot(party, peer);
  ag::AShareBundleVec<nP> bundles(W);
  for (int i = 0; i < W; ++i) {
    bundles[(size_t)i].mac(slot) = party == 2 ? cot[(size_t)i] : zero_block;
    bundles[(size_t)i].key(slot) = party == 1 ? cot[(size_t)i] : zero_block;
  }
  if (auth_case == 1 && party == 2) bundles[0].mac(slot) = bundles[0].mac(slot) ^ makeBlock(0, 1);

  const uint32_t x = 0x0ff00ff0u;
  emp::session::RawBindings b;
  b.inputs.resize(2);
  if (party == 1) {
    emp::session::Bits xb(W);
    for (int i = 0; i < W; ++i) xb[(size_t)i] = (uint8_t)((x >> i) & 1);
    b.inputs[1] = std::move(xb);
  }
  const std::vector<const ag::AShareBundle<nP> *> authenticated = {bundles.data(), nullptr};
  const emp::session::RawResult r = sess.run_computation(std::move(job), b, authenticated);

  bool ok = true;
  if (party == 1) {
    uint32_t got = 0;
    for (int i = 0; i < W; ++i) got |= (uint32_t)((*r.outputs[0])[(size_t)i] & 1) << i;
    ok = got == (k | x);
  }

  // A second, ordinary computation: party 2's k bits now enter as plain input bits.
  auto job2 = sess.prepare_computation(art);
  emp::session::RawBindings b2;
  b2.inputs.resize(2);
  emp::session::Bits mine(W);
  for (int i = 0; i < W; ++i) mine[(size_t)i] = (uint8_t)(((party == 2 ? k : x) >> i) & 1);
  b2.inputs[party == 2 ? 0 : 1] = std::move(mine);
  const emp::session::RawResult r2 = sess.run_computation(std::move(job2), b2);
  if (party == 1) {
    uint32_t got = 0;
    for (int i = 0; i < W; ++i) got |= (uint32_t)((*r2.outputs[0])[(size_t)i] & 1) << i;
    ok = ok && got == (k | x);
    std::printf("agmpc_computation_authenticated: %s\n", ok ? "GOOD!" : "BAD!");
  }
  return ok ? 0 : 1;
#endif
}
