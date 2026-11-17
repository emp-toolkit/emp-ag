// Body-vs-compiled OUTPUT equivalence over AGMPCSession<2>. A circuit run as a LIVE
// body (sess.run(body)) and the SAME circuit compiled to a BooleanProgram and run
// (sess.run(circuit)) must produce the same revealed OUTPUT. The transcript is
// non-deterministic (hardware-seeded Delta/choice), so there is NO byte-fingerprint
// here. The gate is: both strategies agree with each
// other AND with the cleartext-computed reference. n=2: party 1 = evaluator/verdict,
// party 2 = garbler.
//
// The const edge cases (repeated constant, constant as output, constant used both
// before and after an AND) are exactly where const-dedup / wire-id alignment bugs
// would surface as a body-vs-compiled output mismatch.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdio>
using namespace std;
using namespace emp;
namespace cf = emp::frontend;

const static int nP = 2;
using UInt32 = UInt_T<AGMPCSession<nP>::ctx_t, 32>;

struct Result { uint32_t out; bool have; };

// Run a 2-arg UInt32 body as a LIVE body (sess.run(body)); reveal to party 1.
template <class Body>
static Result run_body(int party, int port, Body body, uint32_t av, uint32_t bv) {
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool);
  auto a = sess.input<UInt32>(1, party == 1 ? av : 0);
  auto b = sess.input<UInt32>(2, party == 2 ? bv : 0);
  auto z = sess.run(body, a, b);
  auto r = sess.reveal(z, 1);
  return Result{(uint32_t)(r.value_or(0u) & 0xffffffffu), r.has_value()};
}

// Run the SAME body compiled to a BooleanProgram (sess.run(circuit)); reveal to party 1.
template <class Body>
static Result run_comp(int party, int port, Body body, uint32_t av, uint32_t bv) {
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool);
  auto c = cf::compile<rec::UInt<32>, rec::UInt<32>>(body);
  auto a = sess.input<UInt32>(1, party == 1 ? av : 0);
  auto b = sess.input<UInt32>(2, party == 2 ? bv : 0);
  auto z = sess.run(c, a, b);
  auto r = sess.reveal(z, 1);
  return Result{(uint32_t)(r.value_or(0u) & 0xffffffffu), r.has_value()};
}

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  const uint32_t A = 1234567u, B = 7654321u;
  bool ok = true;

  // A plain adder and three const-stressing bodies, each paired with its cleartext
  // reference (the value party 1 must reveal under both strategies).
  auto plain  = [](auto a, auto b) { return a + b; };
  auto rep_k  = [](auto a, auto b) { auto k = a.constant(5); return a + k + b + k; };   // const reused
  auto out_k  = [](auto a, auto b) { (void)a; return b.constant(0xABCDu); };            // const is the output
  auto around = [](auto a, auto b) { auto k = a.constant(1); auto p = a * b; return p + k; }; // const before+after AND

  const uint32_t ref_plain  = A + B;
  const uint32_t ref_rep_k  = A + 5u + B + 5u;
  const uint32_t ref_out_k  = 0xABCDu;
  const uint32_t ref_around = (A * B) + 1u;

  int slot = 0;   // advanced identically on both parties

  auto check = [&](const char *name, auto body, uint32_t ref) {
    Result b = run_body(party, port + slot++, body, A, B);
    Result c = run_comp(party, port + slot++, body, A, B);
    if (party == 1) {
      bool agree = b.have && c.have && b.out == c.out;   // body == compiled
      bool ref_ok = b.have && b.out == ref;              // both match the cleartext oracle
      bool good = agree && ref_ok;
      printf("equiv[%-10s] body==compiled=%d  out=%u (exp %u)  %s\n",
             name, (int)agree, b.out, ref, good ? "GOOD!" : "BAD!");
      ok &= good;
    }
  };

  check("add",        plain,  ref_plain);
  check("rep_const",  rep_k,  ref_rep_k);
  check("const_out",  out_k,  ref_out_k);
  check("around_and", around, ref_around);

  if (party == 1)
    printf("agmpc_body_replay_equiv: %s\n", ok ? "GOOD!" : "BAD!");
  return (party == 1 && !ok) ? 1 : 0;
}
