#ifndef EMP_AG_BACKEND_COMMON_LANE_MESH_H__
#define EMP_AG_BACKEND_COMMON_LANE_MESH_H__
//
// The session's meshes as a bulk opening uses them: mesh 0 (io) and, with lanes, the
// other meshes of the group. fan_out() is the one enqueue order of the leaky ANDs' and
// Beaver's bulk openings (the s-bits, the bucket differences, Beaver's x and y).
//
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/common/runtime.h"   // lane_range
#include <algorithm>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

template <int nP>
struct LaneMesh {
  NetIOMP<nP> *io = nullptr;
  NetIOMPGroup<nP> *grp = nullptr;   // null: mesh 0 only
  ThreadPool *pool = nullptr;
  int party = 0;
  int lanes = 1;

  LaneMesh() = default;
  LaneMesh(NetIOMP<nP> *io, NetIOMPGroup<nP> *grp, ThreadPool *pool, int party)
      : io(io), grp(grp), pool(pool), party(party),
        lanes(grp ? std::max(1, grp->size()) : 1) {}

  // The mesh carrying lane t (lane 0 == io == grp->mesh(0)).
  NetIOMP<nP> *mesh(int t) const { return (t == 0) ? io : &grp->mesh(t); }

  // Canonical per-(peer,lane) transfer fan-out over the meshes, into ONE join barrier.
  // Splits [0,n) into T=min(lanes,n) contiguous ag::lane_range slices; lane t rides mesh
  // t (lane 0 == mesh 0). `send_slice(ch,peer,lo,hi)` and `recv_slice(...)` do the
  // transfer for that slice on channel ch. Order = peer-major, lanes 0..T-1, send+recv
  // adjacent: THE deadlock-safe enqueue contract for those openings. n == 0 still runs
  // one (empty) slice on mesh 0, so a caller's bytes riding mesh 0 still go; T == 1 keeps
  // everything on mesh 0.
  template <class SendF, class RecvF>
  void fan_out(int n, SendF &&send_slice, RecvF &&recv_slice) const {
    const int T = std::min(lanes, std::max(1, n));
    vector<future<void>> res;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
      for (int t = 0; t < T; ++t) {
        auto pr = ag::lane_range(t, n, T);
        NetIOMP<nP> *ch = mesh(t);
        res.push_back(pool->enqueue(
            [&send_slice, ch, peer, pr]() { send_slice(ch, peer, pr.first, pr.second); }));
        res.push_back(pool->enqueue(
            [&recv_slice, ch, peer, pr]() { recv_slice(ch, peer, pr.first, pr.second); }));
      }
    }
    joinNclean(res);
  }

  // The two NetIO channels behind NetIOMP for one peer (see netmp.h: the smaller party
  // drives `ios`, the larger drives `ios2`). send_data/recv_data pick these; reaching
  // them directly sends bit vectors through the channel's packed send_bool/recv_bool
  // (8 bits/byte) instead of one byte per bit.
  NetIO *send_ch(int dst) const { return party < dst ? io->ios[dst] : io->ios2[dst]; }
  NetIO *recv_ch(int src) const { return src < party ? io->ios[src] : io->ios2[src]; }
};

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_COMMON_LANE_MESH_H__
