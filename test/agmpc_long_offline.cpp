// A long offline phase as a session's first work: prepare() of a circuit large enough
// that the offline phase's aShare draws run past the first COT extension chunk before
// the first deferred COT check. A party's COT receivers toward different peers must then
// already sit at the same extension session and position, or their choice bits, and so
// the party's share bits toward different peers, drift apart and preprocessing aborts.
// The bootstrap keeps them aligned by checking the 128-COT prefix of both directions.
// nP >= 3: some party is the primary receiver toward one peer and the reverse receiver
// toward another.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdint>
#include <cstdio>
#include <utility>
using namespace emp;
namespace cf = emp::frontend;

#ifndef LONG_NP
#define LONG_NP 3
#endif
constexpr int nP = LONG_NP;

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool);
  using U64 = UInt_T<typename AGMPCSession<nP>::ctx_t, 64>;
  // About ten thousand ANDs, prepared before any input or reveal.
  auto circuit = cf::compile<rec::UInt<64>, rec::UInt<64>>(
      [](auto x, auto y) { return ((x * y) * (x ^ y)) * (x + y); });
  auto prepared = sess.prepare(circuit);
  const uint64_t xv = 0x0123456789abcdefull, yv = 0x00fedcba98765432ull;
  auto x = sess.input<U64>(1, party == 1 ? xv : 0);
  auto y = sess.input<U64>(2, party == 2 ? yv : 0);
  const uint64_t got = (uint64_t)sess.reveal(sess.run(std::move(prepared), x, y), PUBLIC).value_or(0);
  const uint64_t ref = ((xv * yv) * (xv ^ yv)) * (xv + yv);
  const bool ok = got == ref;
  if (party == 1)
    std::printf("agmpc_long_offline_np%d: %s (ANDs %llu)\n", nP, ok ? "GOOD!" : "BAD!",
                (unsigned long long)sess.num_and());
  return ok ? 0 : 1;
}
