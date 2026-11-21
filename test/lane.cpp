// Lane integration end-to-end, one source for both party-count regimes
// (LANE_NP=2 and LANE_NP=3; only the rationale differs):
//
// An AGMPCSession<nP> whose COT/aShare generation is split across L=2 lanes on
// a NetIOMPGroup (mesh 0 = parent COT + all non-COT traffic, mesh 1 = clone).
//
//   nP=2 — the ONLY regime with no runtime cross-consistency backstop (check2
//   is nP>2; the deferred COT check certifies per-instance correlation, not
//   lane agreement), so this run is the guard: if the two parties ever used a
//   divergent partition / cadence / clone order for a lane, that lane's COTs would not
//   correlate -> wrong authenticated shares -> wrong triples -> a wrong AND
//   output (reveal mismatch) or a c_gamma abort.
//
//   nP=3 — unlike nP=2 this exercises BOTH malicious-check paths under lanes:
//   (1) check1's csp gadget tail — the tail [length, ext_len) falls in the last
//   lane's range and check1 reads the ASSEMBLED MAC/KEY after the one join
//   barrier; (2) check2's universal-hash fold over the assembled arrays (which
//   also cross-checks x^me across peers — the nP>2 runtime backstop nP=2
//   lacks).
//
// Reveal-correct end to end = the lane spine is consistent across all peers.
// Also runs a second cycle (exercises the long-lived COT session's flush across
// parent+clones) and an AES block (larger AND count -> multi-chunk lane draws).
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/builtins.h"
#include "emp-ag/emp-ag.h"
#include "clear_oracle.h"
#include <array>
#include <cstdint>
#include <iostream>
using namespace std;
using namespace emp;

const static int nP = LANE_NP;

int main(int argc, char** argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  // L=2: the session owns two meshes on ONE listening port per party (tagged
  // handshake). mesh(0) carries the parent COT + ALL non-COT traffic; mesh(1)
  // carries the clone lane.
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool, 40, /*lanes=*/2);
  using Ctx = AGMPCSession<nP>::ctx_t;
  using U32 = UInt_T<Ctx, 32>;
  using BV128 = BitVec_T<Ctx, 128>;

  bool ok = true;

  // Two mul+add cycles, revealed each (each reveal flushes the deferred COT check
  // across parent + clone lane).
  const uint32_t xa = 0x9e3779b9u, yb = 0x7f4a7c15u;
  auto x = sess.input<U32>(1, party == 1 ? xa : 0u);
  auto y = sess.input<U32>(2, party == 2 ? yb : 0u);
  auto step = [](auto a, auto b) { return a * b + a; };
  uint32_t ca = xa, cb = yb;
  for (int k = 0; k < 2; ++k) {
    auto z = sess.run(step, x, y);
    auto got = sess.reveal(z, 1);
    const uint32_t ref = ca * cb + ca;
    if (party == 1) ok = ok && got.has_value() && (uint32_t)got.value() == ref;
    x = y; y = z; ca = cb; cb = ref;
  }

  // An AES block (larger AND count -> the lane ranges span several COT chunks).
  const circuit::BooleanProgram &aes = circuit::builtin_circuit("aes128");
  array<bool, 128> k1{}, pt{};
  for (int i = 0; i < 128; ++i) { k1[i] = ((i * 7 + 3) % 5) == 0; pt[i] = ((i * 3 + 1) % 4) == 0; }
  auto P = sess.input<BV128>(2, party == 2 ? pt : array<bool, 128>{});
  auto K = sess.input<BV128>(1, party == 1 ? k1 : array<bool, 128>{});
  auto C = sess.reveal(sess.run_artifact<BV128>(aes, P, K), 1);
  if (party == 1) {
    vector<uint8_t> in(256);
    for (int i = 0; i < 128; ++i) { in[i] = pt[i]; in[128 + i] = k1[i]; }
    auto ref = agmpc_test::clear_eval(aes, in);
    ok = ok && C.has_value() && (int)ref.size() == 128;
    for (int i = 0; i < 128 && ok; ++i) ok = (C.value()[i] == ref[i]);
  }

  if (party == 1) {
    cout << "lane_np" << nP << " (AGMPCSession over NetIOMPGroup L=2, mul+add x2 + aes128): "
         << (ok ? "GOOD!" : "BAD!") << endl;
    return ok ? 0 : 1;
  }
  return 0;
}
