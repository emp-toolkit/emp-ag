// Direct/chunked execution over AGMPCSession<2>: multi-owner input batching,
// checkpoint prune+carry, a reveal that keeps the other pending values still in
// scope, and no-arg checkpoint cleanup. These are the behaviors of the RAII
// scope-tracked wire model in the shared ChunkedSession base.
// n=2: party 1 = evaluator/verdict, party 2 = garbler.
//
// The stale-id guards fire as expecting() -> _Exit(1) by design (fail-fast): a wire used
// after a prune, or a reserved input_batch().add value still unmaterialized at the
// next flush, has no carried state and aborts. Such an abort would desync a live
// multi-party run, so these are validated by construction here rather than death-tested.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdio>
using namespace std;
using namespace emp;

const static int nP = 2;
using UInt32 = UInt_T<AGMPCSession<nP>::ctx_t, 32>;

// party-1 + party-2 inputs authenticated in ONE process_inputs phase.
static bool batch_inputs(int party, int port) {
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool);

  const uint32_t X = 11111u, Y = 22222u;
  auto batch = sess.input_batch();
  auto a = batch.add<UInt32>(1, party == 1 ? X : 0);
  auto b = batch.add<UInt32>(2, party == 2 ? Y : 0);
  batch.finish();                       // one phase across both owners
  auto out = sess.reveal(a + b, 1);
  int calls = sess.process_input_calls();
  if (party != 1) return true;
  bool ok = out.has_value() && out.value() == (uint64_t)(X + Y) && calls == 1;
  printf("  input_batch (P1+P2, one phase): a+b=%u (exp %u) process_input_calls=%d  %s\n",
         (uint32_t)out.value_or(0), X + Y, calls, ok ? "GOOD! (batched)" : "BAD!");
  return ok;
}

// Long accumulator chain, checkpoint(acc) after each step: prunes the dropped
// per-step inputs, carries acc forward.
static bool checkpoint_chain(int party, int port) {
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool);

  const int N = 8;
  uint32_t blk[N];
  for (int i = 0; i < N; ++i) blk[i] = 0x100u * (uint32_t)(i + 1);
  const uint32_t init = 1000u;

  auto acc = sess.input<UInt32>(1, party == 1 ? init : 0);
  uint32_t ref = init;
  for (int k = 0; k < N; ++k) {
    auto x = sess.input<UInt32>(2, party == 2 ? blk[k] : 0);
    acc = acc + x;
    sess.checkpoint(acc);                 // keep acc, prune everything else
    ref += blk[k];
  }
  auto out = sess.reveal(acc, 1);
  if (party != 1) return true;
  bool ok = out.has_value() && out.value() == (uint64_t)ref;
  printf("  checkpoint chain (%d adds, prune each step): acc=%u (exp %u)  %s\n",
         N, (uint32_t)out.value_or(0), ref, ok ? "GOOD!" : "BAD!");
  return ok;
}

// reveal(p): q is pending and still in scope, so it must survive the flush and a
// later reveal(q) still finds it.
static bool reveal_keep_list(int party, int port) {
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool);

  const uint32_t X = 40u, Y = 15u;
  auto a = sess.input<UInt32>(1, party == 1 ? X : 0);
  auto b = sess.input<UInt32>(2, party == 2 ? Y : 0);
  auto p = a + b;                         // pending
  auto q = a - b;                         // pending (X > Y)
  auto rp = sess.reveal(p, 1);             // flush; q is in scope, so it is kept
  auto rq = sess.reveal(q, 1);             // q now materialized
  if (party != 1) return true;
  bool ok = rp.has_value() && rq.has_value() &&
            rp.value() == (uint64_t)(X + Y) && rq.value() == (uint64_t)(X - Y);
  printf("  reveal keeps in-scope (q=a-b kept across reveal(a+b)): p=%u (exp %u) q=%u (exp %u)  %s\n",
         (uint32_t)rp.value_or(0), X + Y, (uint32_t)rq.value_or(0), X - Y,
         ok ? "GOOD!" : "BAD!");
  return ok;
}

// no-arg checkpoint() is the RAII prune barrier: it keeps every value still in C++
// scope and prunes only what has left scope. Here `a` stays in scope across the
// checkpoint (so it must survive and stay revealable), while the inner-scope input
// `tmp` and the abandoned `a + tmp` result have left scope (pruned). The context
// stays usable with fresh inputs afterward.
static bool checkpoint_cleanup(int party, int port) {
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool);

  auto a = sess.input<UInt32>(1, party == 1 ? 5 : 0);
  {
    auto tmp = sess.input<UInt32>(2, party == 2 ? 7 : 0);
    (void)(a + tmp);                      // pending work, intentionally abandoned
  }                                        // tmp + the (a+tmp) result leave scope here
  sess.checkpoint();                       // keep in-scope (a); prune out-of-scope (tmp, the temp)

  // `a` was in scope across the checkpoint, so it survived the prune and is still
  // revealable — this is the RAII keep semantics (a no-arg checkpoint does NOT drop
  // values you still hold).
  auto ra = sess.reveal(a, 1);

  // Context stays usable with fresh inputs after the prune.
  auto c = sess.input<UInt32>(1, party == 1 ? 100 : 0);
  auto d = sess.input<UInt32>(2, party == 2 ? 23 : 0);
  auto out = sess.reveal(c + d, 1);
  if (party != 1) return true;
  bool ok = ra.has_value()  && ra.value()  == 5u &&
            out.has_value() && out.value() == 123u;
  printf("  checkpoint() RAII prune: in-scope a survived = %u (exp 5), fresh c+d = %u (exp 123)  %s\n",
         (uint32_t)ra.value_or(0), (uint32_t)out.value_or(0), ok ? "GOOD!" : "BAD!");
  return ok;
}

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  bool ok = true;
  ok &= batch_inputs(party,       port + 0);
  ok &= checkpoint_chain(party,   port + 1);
  ok &= reveal_keep_list(party,   port + 2);
  ok &= checkpoint_cleanup(party, port + 3);

  if (party == 1)
    printf("agmpc_direct_chunks: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == 1 && !ok) ? 1 : 0;
}
