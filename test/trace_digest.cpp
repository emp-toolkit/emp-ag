// Byte-wire-identity oracle for wire-preserving refactors.
//
// Runs AES-128 (fixed inputs) over AGMPCSession<TRACE_NP> with Fiat-Shamir
// transcript hashing enabled on every pairwise channel, then writes each
// channel's directional wire-byte digest (IOChannel::get_send_digest /
// get_recv_digest — the first 16 B of SHA-256 over all bytes crossed in that
// direction) to a per-party file $TRACE_PREFIX.np<NP>.p<party>.txt.
//
// This is emp-tool's documented wire-equivalence mechanism (trace_io.h): in a
// deterministic-mode build (emp-tool configured with -DEMP_DETERMINISTIC_MODE=ON,
// emp-ot and this tree configured against it) all randomness is deterministic, so
// the digests are stable run-to-run and a refactor that preserves the wire bytes
// leaves every digest unchanged. (NetIOMP stores concrete NetIO*, so TraceIO
// byte-teeing would need a production type change; the per-channel FS digest gives
// the same SHA-256-of-wire guarantee with no production edit.)
//
// VALID ONLY AT nP==2. The digests are stable run-to-run at 2 parties, so np2 is a
// sound byte-identity gate. At nP>=3 they are NOT stable: the garbler-row aggregation
// ring streams several logical messages concurrently onto the same FS-hashed channel,
// and the byte order the digest folds over is thread-schedule dependent, so np3 differs
// run-to-run even with no code change.
// Use golden output-correctness (agmpc_golden_np3/np4) + the cheat tests to gate nP>=3;
// keep test_trace_np3 only for a coarse "did a whole channel appear/vanish" eyeball.
//
// Usage (2 parties via "runN 2", 3 via ./run), from a build configured against a
// deterministic-mode emp-tool + emp-ot install:
//   TRACE_PREFIX=/tmp/before ./runN 2 ./build/bin/test_trace_np2
//   TRACE_PREFIX=/tmp/before ./run  ./build/bin/test_trace_np3
//   ...refactor, rebuild...
//   TRACE_PREFIX=/tmp/after  ./runN 2 ./build/bin/test_trace_np2
//   diff /tmp/before.np2.p1.txt /tmp/after.np2.p1.txt   # must be empty (and p2, np3.p1..p3)
#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/builtins.h"
#include "emp-ag/emp-ag.h"
#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
using namespace std;
using namespace emp;

#ifndef TRACE_NP
#define TRACE_NP 3
#endif
static const int nP = TRACE_NP;

static string hex16(block b) {
  unsigned char buf[16];
  memcpy(buf, &b, 16);
  static const char *H = "0123456789abcdef";
  string s;
  s.reserve(32);
  for (int i = 0; i < 16; ++i) { s += H[buf[i] >> 4]; s += H[buf[i] & 0xf]; }
  return s;
}

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(&io, &pool, party);
  io.flush();
  ag::enable_fs_pairs<nP>(&io, party);   // guarded: no-op if the COT already enabled FS
  using Ctx = AGMPCSession<nP>::ctx_t;

  const circuit::BooleanProgram &prog = circuit::builtin_circuit("aes128");
  array<bool, 256> in_bits{};
  for (int i = 0; i < 256; ++i) in_bits[i] = ((i * 7 + 3) % 5) == 0;
  auto in = sess.input<BitVec_T<Ctx, 256>>(2, party == 2 ? in_bits : array<bool, 256>{});
  auto out = sess.reveal(sess.run_artifact<BitVec_T<Ctx, 128>>(prog, in), 1);
  (void)out;
  io.flush();

  const char *pre = getenv("TRACE_PREFIX");
  string path = string(pre ? pre : "/tmp/agtrace") + ".np" + to_string(nP) +
                ".p" + to_string(party) + ".txt";
  FILE *f = fopen(path.c_str(), "w");
  if (f == nullptr) { fprintf(stderr, "trace_digest: cannot open %s\n", path.c_str()); return 1; }
  for (int p = 1; p <= nP; ++p) if (p != party) {
    fprintf(f, "peer %d ios  send=%s recv=%s\n", p,
            hex16(io.ios[p]->get_send_digest()).c_str(),
            hex16(io.ios[p]->get_recv_digest()).c_str());
    fprintf(f, "peer %d ios2 send=%s recv=%s\n", p,
            hex16(io.ios2[p]->get_send_digest()).c_str(),
            hex16(io.ios2[p]->get_recv_digest()).c_str());
  }
  fclose(f);
  if (party == nP) printf("trace_digest np%d: wrote per-party wire digests\n", nP);
  return 0;
}
