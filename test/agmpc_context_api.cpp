// AGMPCSession<2> public surface:
// typed input/reveal over the value layer, arithmetic and comparison, signed Int,
// a PUBLIC constant, and reveal to a single recipient. n=2: party 1 = evaluator
// (the verdict party that gets the revealed output), party 2 = garbler; inputs map
// to party ids 1 and 2, and the single-recipient reveal routes to party 1.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdio>
#include <optional>
using namespace std;
using namespace emp;

const static int nP = 2;

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool);

  using UInt32 = UInt_T<AGMPCSession<nP>::ctx_t, 32>;
  using Int32  = Int_T<AGMPCSession<nP>::ctx_t, 32>;

  const uint32_t X = 1234567u, Y = 7654321u, K = 333u;
  bool ok = true;

  // a + b ; reveal does not prune, so a/b stay materialized for later use.
  auto a = sess.input<UInt32>(1, party == 1 ? X : 0);
  auto b = sess.input<UInt32>(2, party == 2 ? Y : 0);
  uint32_t got_sum = (uint32_t)sess.reveal(a + b, PUBLIC).value_or(0);

  // (a + b) * 3 + K, with K a PUBLIC constant input (no OT).
  auto three = sess.input<UInt32>(PUBLIC, 3);
  auto kpub  = sess.input<UInt32>(PUBLIC, K);
  uint32_t got_expr = (uint32_t)sess.reveal((a + b) * three + kpub, PUBLIC).value_or(0);

  // a < b, revealed to party 1 (evaluator) only (party 2 gets nullopt).
  std::optional<bool> lt = sess.reveal(a < b, 1);

  // Signed Int32: (-5) + 12 == 7.
  auto ia = sess.input<Int32>(1, party == 1 ? (int64_t)-5 : 0);
  auto ib = sess.input<Int32>(2, party == 2 ? (int64_t)12 : 0);
  int32_t got_signed = (int32_t)sess.reveal(ia + ib, PUBLIC).value_or(0);

  if (party == 2) ok &= !lt.has_value();   // party 2 must NOT learn a<b

  if (party == 1) {
    uint32_t ref_sum = X + Y, ref_expr = (X + Y) * 3u + K;
    bool ref_lt = X < Y;
    ok &= (got_sum == ref_sum);
    ok &= (got_expr == ref_expr);
    ok &= (lt.has_value() && lt.value() == ref_lt);
    ok &= (got_signed == 7);
    printf("agmpc_context_api: a+b=%u (exp %u), (a+b)*3+K=%u (exp %u), a<b=%d (exp %d), "
           "(-5)+12=%d (exp 7)  %s\n",
           got_sum, ref_sum, got_expr, ref_expr, (int)lt.value(), (int)ref_lt,
           got_signed, ok ? "GOOD!" : "BAD!");
  }
  return (party == 1 && !ok) ? 1 : 0;
}
