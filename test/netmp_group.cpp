// NetIOMPGroup: k meshes over ONE listening port per party, routed by the
// {party, mesh_tag} handshake. Exercises exactly what the tag exists for:
// every party dials all meshes back-to-back, so a fast peer's mesh-1
// connection can reach a slow peer that is still collecting mesh-0 accepts —
// the tag, not arrival order, must route it. Gates:
//   1. raw isolation: distinct (mesh, sender)-stamped payloads exchanged both
//      directions on both meshes arrive on the mesh they were sent on;
//   2. the real consumer: a full AGMPCSession runs on mesh 0 while mesh 1
//      carries an independent byte exchange, and the session's reveal matches
//      cleartext.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include <cstdint>
#include <cstring>
#include <iostream>
using namespace std;
using namespace emp;

const static int nP = 3;

static block stamp(int mesh, int sender) {
  return makeBlock(0xA6A6A6A6ull * (mesh + 1), 0x5151515100ull + sender);
}

int main(int argc, char **argv) {
  int party = parse_party(argv, nP);
  int port = peer_port();
  if (party > nP) return 0;

  NetIOMPGroup<nP> grp(party, port, /*n_meshes=*/2);
  bool ok = true;

  // 1) Both meshes, both directions per pair (each direction rides the socket
  //    its sender dialed, so all four sockets per pair carry data).
  for (int m = 0; m < 2; ++m) {
    NetIOMP<nP> &io = grp.mesh(m);
    block mine = stamp(m, party);
    for (int p = 1; p <= nP; ++p) if (p != party) {
      io.send_data(p, &mine, sizeof(block));
      io.flush(p);
    }
    for (int p = 1; p <= nP; ++p) if (p != party) {
      block got;
      io.recv_data(p, &got, sizeof(block));
      block want = stamp(m, p);
      ok = ok && cmpBlock(&got, &want, 1);
    }
  }

  // 2) A full session on mesh 0, with mesh 1 concurrently carrying its own
  //    traffic (a second stamped round-trip) — the two must not interfere.
  {
    ThreadPool pool(ag::default_pool_size(nP));
    AGMPCSession<nP> sess(&grp.mesh(0), &pool, party);
    ok = ok && &sess.io() == &grp.mesh(0) && sess.group() == nullptr;
    grp.mesh(0).flush();
    using Ctx = AGMPCSession<nP>::ctx_t;
    using U32 = UInt_T<Ctx, 32>;
    const uint32_t xa = 3141592u, yb = 2718281u;
    auto a = sess.input<U32>(1, party == 1 ? xa : 0u);
    auto b = sess.input<U32>(2, party == 2 ? yb : 0u);

    block mine = stamp(7, party);   // fresh stamp domain for round 2
    for (int p = 1; p <= nP; ++p) if (p != party) {
      grp.mesh(1).send_data(p, &mine, sizeof(block));
      grp.mesh(1).flush(p);
    }

    auto z = sess.run([](auto x, auto y) { return x * y + x; }, a, b);
    auto got = sess.reveal(z, 1);
    if (party == 1) {
      const uint32_t ref = xa * yb + xa;
      ok = ok && got.has_value() && (uint32_t)got.value() == ref;
    }

    for (int p = 1; p <= nP; ++p) if (p != party) {
      block gotb;
      grp.mesh(1).recv_data(p, &gotb, sizeof(block));
      block want = stamp(7, p);
      ok = ok && cmpBlock(&gotb, &want, 1);
    }
  }

  // 3) The adopted-group form exposes the borrowed group (and mesh 0) rather
  //    than consulting the null owning pointers. Construction also validates
  //    that grp.mesh(0) is exactly the supplied io.
  {
    ThreadPool pool(ag::default_pool_size(nP));
    AGMPCSession<nP> sess(&grp.mesh(0), &pool, party, 40, &grp);
    ok = ok && &sess.io() == &grp.mesh(0) && sess.group() == &grp;
    ok = ok && sess.lanes() == grp.size();
  }

  if (party == 1) {
    cout << "netmp_group (2 meshes, 1 port, tagged handshake): "
         << (ok ? "GOOD!" : "BAD!") << endl;
    return ok ? 0 : 1;
  }
  return ok ? 0 : 1;
}
