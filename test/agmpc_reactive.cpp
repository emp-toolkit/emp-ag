// Reactive session test, plus direct chunked-mode recording checks and RAII
// scope-liveness cases, all on one 3-party session. In session order:
//   1. const-only PUBLIC reveal — MUST stay the fresh session's FIRST chunk (a
//      zero-auth chunk: no inputs authenticated yet must still flush cleanly);
//   2. direct recording: NOT gate, PUBLIC-const input, secret^PUBLIC XOR, and a
//      designated-recipient reveal, vs plaintext;
//   3. reactive core: a mid-circuit reveal-to-all, a host branch on the value, a
//      new secret input after the reveal, and a fresh input mid-computation;
//   4. RAII: a reveal keeps every pending in-scope value live, and revealing a
//      materialized value keeps a pending sibling live.
// Every party runs the same SPMD program; party 1 carries the verdict.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
using namespace std;
using namespace emp;

const static int nP = 3;

// a from party 1, b from party 2, d from party 1. Fills {v, r, ru}.
static void reactive(AGMPCSession<nP> &sess, bool a_in, bool b_in, bool d_in, bool *out3) {
  using Ctx = AGMPCSession<nP>::ctx_t;
  using B = Bit_T<Ctx>;
  B a = sess.input<B>(1, a_in), b = sess.input<B>(2, b_in);
  B c = a & b;
  bool v = sess.reveal(c, PUBLIC).value_or(false);   // reveal to ALL; host branches
  B result;
  if (v) {
    B d = sess.input<B>(1, d_in);                     // new secret input AFTER a reveal
    result = d ^ a;                                   // `a` still live across the reveal
  } else {
    result = a;
  }
  bool r = sess.reveal(result, PUBLIC).value_or(false);

  B x = sess.input<B>(1, a_in);
  B t = x & x;                                         // a gate
  B y = sess.input<B>(2, b_in);                        // fresh mid-computation input
  B u = t ^ y;
  bool ru = sess.reveal(u, PUBLIC).value_or(false);

  out3[0] = v; out3[1] = r; out3[2] = ru;
}

static void reactive_clear(bool a, bool b, bool d, bool *out3) {
  bool v = a & b;
  bool result = v ? (d ^ a) : a;
  bool ru = (a & a) ^ b;
  out3[0] = v; out3[1] = result; out3[2] = ru;
}

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCSession<nP> sess(party, port, nullptr, &pool);
  using Ctx = AGMPCSession<nP>::ctx_t;
  using B = Bit_T<Ctx>;
  bool ok = true;

  // ---- 1. const-only PUBLIC reveal: keep as this session's FIRST chunk. ----
  {
    B c = sess.input<B>(PUBLIC, true);
    std::optional<bool> cv = sess.reveal(c, 1);
    if (party == 1 && !cv.value_or(false)) {
      cout << "agmpc_reactive const-only reveal BAD!" << endl;
      ok = false;
    }
  }

  // ---- 2. direct recording: (a&b)^(!a)^0 with a PUBLIC-const input, revealed
  // to party 1 only (a=b=1). ----
  {
    B ra = sess.input<B>(1, party == 1);
    B rb = sess.input<B>(2, party == 2);
    B rz = sess.input<B>(PUBLIC, false);
    B rr = ((ra & rb) ^ (!ra)) ^ rz;
    std::optional<bool> res = sess.reveal(rr, 1);
    if (party == 1) {
      bool ref = ((true & true) ^ (!true)) ^ false;    // = 1
      if (res.value_or(false) != ref) {
        cout << "agmpc_reactive recording out=" << res.value_or(false)
             << " (expected " << ref << ") BAD!" << endl;
        ok = false;
      }
    }
  }

  // ---- 3. reactive core ----
  bool A = true, Bv = true, D = true;
  bool a_in = (party == 1) ? A : false;
  bool b_in = (party == 2) ? Bv : false;
  bool d_in = (party == 1) ? D : false;

  bool got[3];
  reactive(sess, a_in, b_in, d_in, got);
  bool ref3[3];
  reactive_clear(A, Bv, D, ref3);
  if (party == 1)
    ok &= got[0] == ref3[0] && got[1] == ref3[1] && got[2] == ref3[2];

  // ---- 4. RAII scope liveness. a owned by party 1, b by party 2; a=b=1. ----
  {
    B a = sess.input<B>(1, party == 1);   // a=1
    B b = sess.input<B>(2, party == 2);   // b=1
    // Reveal x, then y (both in scope) -- RAII keeps y across reveal(x)
    B x = a & b;   // 1
    B y = a ^ b;   // 0
    auto xv = sess.reveal(x, PUBLIC);
    auto yv = sess.reveal(y, PUBLIC);    // RAII keeps y (in scope) across reveal(x)
    // Reveal a materialized value with pending z in scope -> z survives
    B z = a & b;
    auto av = sess.reveal(a, PUBLIC);    // a materialized; z pending+in-scope
    auto zv = sess.reveal(z, PUBLIC);
    (void)av;
    if (party == 1) {
      bool rok = xv.value_or(0) == 1 && yv.value_or(1) == 0 && zv.value_or(0) == 1;
      cout << "agmpc_reactive RAII: x=" << xv.value_or(9) << " y=" << yv.value_or(9)
           << " ; z=" << zv.value_or(9) << "  " << (rok ? "GOOD!" : "BAD!") << endl;
      ok &= rok;
    }
  }

  if (party == 1) {
    cout << "agmpc_reactive (const-chunk + recording + reactive + RAII): "
         << (ok ? "GOOD!" : "BAD!") << endl;
    return ok ? 0 : 1;
  }
  return 0;
}
