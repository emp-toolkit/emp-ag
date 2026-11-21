// Validate AGMPCEngine::run_program on a hand-built BooleanProgram, with no
// recorder. Exercises: flat input bundle, gates referencing
// inputs, explicit non-tail output id, and decode to a chosen recipient.
#include "emp-ag/backend/garble/protocol.h"
#include "emp-ag/backend/garble/engine.h"
#include "emp-tool/ir/program.h"
using namespace std;
using namespace emp;
using namespace emp::ag;  // white-box test: reaches into the backend (AGMPCProtocol/AGMPCEngine/SecureWires)

const static int nP = 3;

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  NetIOMP<nP> io(party, port);
  ThreadPool pool(ag::default_pool_size(nP));
  AGMPCProtocol<nP> mpc(&io, &pool, party);
  emp::ag::AGMPCEngine<nP> engine{&mpc};
  io.flush();

  // Inputs: a from ALICE at wire 0, b from BOB at wire 1.
  bool a = (party == 1);  // ALICE's input = 1
  bool b = (party == 2);  // BOB's input   = 1
  SecureWires<nP> in = mpc.process_input(&a, 1, /*owner=*/1);
  in.append(mpc.process_input(&b, 1, /*owner=*/2));

  // Program over wires [0,7):
  //   w2 = XOR(w0,w0) = 0
  //   w3 = AND(w0,w1) = a & b
  //   w4 = NOT(w0)    = !a
  //   w5 = XOR(w3,w4) = (a&b) ^ (!a)
  //   w6 = XOR(w5,w2) = w5 ^ 0
  emp::circuit::BooleanProgram prog;
  prog.num_inputs = 2;
  prog.num_wires = 7;
  prog.gates = {
      {0, 0, 2, emp::circuit::Op::Xor},
      {0, 1, 3, emp::circuit::Op::And},
      {0, 0, 4, emp::circuit::Op::Not},
      {3, 4, 5, emp::circuit::Op::Xor},
      {5, 2, 6, emp::circuit::Op::Xor},
  };
  prog.outputs = {6};

  SecureWires<nP> outw = engine.run_program(prog, in);
  vector<bool> res = mpc.decode(outw, /*recipient=*/1);

  bool ok = true;
  if (party == 1) {
    bool ref = ((true & true) ^ (!true)) ^ false;
    ok = (res[0] == ref);
    cout << "BooleanProgram out = " << res[0] << " (expected " << ref << ")  "
         << (ok ? "GOOD!" : "BAD!") << endl;
  }
  return (party == 1 && !ok) ? 1 : 0;   // party-1 verdict must reach ctest (see runN)
}
