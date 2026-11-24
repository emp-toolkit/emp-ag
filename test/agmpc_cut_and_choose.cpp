// The cut-and-choose triple generator (backend/triple/cut_and_choose_triples.h) at the
// protocol layer: take triples through the bank across several batches, then check that
// every triple is consistently authenticated (check_MAC, which sends Delta in the clear:
// white-box, EMP_AG_DEBUG_CHECKS) and correct (a * b == c on the opened shares), and that
// the bank and the batch count behave as specified. A second bank declares 2^20 batches and
// runs two, both at the declared target (2^-ssp / 2^20 each), which needs larger buckets
// than the per-batch schedule's first batches; with the over_declared argument a bank that declares
// one batch refuses a second. One source; the party count via CNC_NP.
#include "emp-ag/backend/triple/cut_and_choose_triples.h"
#include "test_args.h"
#include <cstdio>
#include <vector>
using namespace emp;
using namespace emp::ag;

#ifndef CNC_NP
#define CNC_NP 3
#endif
constexpr int nP = CNC_NP;
constexpr int64_t kBatch = 1000;

static int party;

// Check n triples: their MACs, then a * b == c on every party's shares, at party 1.
static bool check_triples(NetIOMP<nP> *io, AShareGen<nP> &abit, BlockVec mac[nP + 1],
                          BlockVec key[nP + 1], int64_t n) {
  check_MAC<nP>(io, mac, key, abit.delta(), (int)(3 * n), party);
  const int any_peer = (party == 1) ? 2 : 1;
  std::vector<unsigned char> mine((size_t)(3 * n));
  for (int64_t e = 0; e < 3 * n; ++e) mine[(size_t)e] = (unsigned char)getLSB(mac[any_peer][(size_t)e]);
  bool ok = true;
  if (party == 1) {
    std::vector<unsigned char> v = mine, got((size_t)(3 * n));
    for (int p = 2; p <= nP; ++p) {
      io->recv_data(p, got.data(), got.size());
      for (size_t e = 0; e < got.size(); ++e) v[e] ^= got[e];
    }
    int64_t ones_a = 0;
    for (int64_t i = 0; i < n; ++i) {
      ok = ok && ((v[(size_t)i] & v[(size_t)(n + i)]) == v[(size_t)(2 * n + i)]);
      ones_a += v[(size_t)i];
    }
    // a is uniform: far from all zeros or all ones.
    ok = ok && ones_a > n / 4 && ones_a < 3 * n / 4;
  } else {
    io->send_data(1, mine.data(), mine.size());
    io->flush(1);
  }
  return ok;
}

int main(int argc, char **argv) {
  party = parse_party(argv, nP);
  if (party > nP) return 0;
  NetIOMP<nP> io(party, peer_port());
  ThreadPool pool(ag::default_pool_size(nP));
  AShareGen<nP> abit(&io, &pool, party);
  PRG prg;
  const block sid = sampleRandom<nP>(&io, &prg, &pool, party);
  CutAndChooseTriples<nP> cnc(&io, &pool, party, abit, sid, 40, kBatch);

  BlockVec mac[nP + 1], key[nP + 1];
  bool ok = true;
  // 2500: two full batches and half of a third. 700: the banked 500, then a fourth batch.
  cnc.take(2500, mac, key);
  ok = check_triples(&io, abit, mac, key, 2500) && ok;
  ok = ok && cnc.batches() == 3;
  cnc.take(700, mac, key);
  ok = check_triples(&io, abit, mac, key, 700) && ok;
  ok = ok && cnc.batches() == 4 && cnc.outputs() == 4 * kBatch;
  cnc.take(0, mac, key);
  ok = ok && cnc.batches() == 4;

  // Declared batches, each bank on a session id of its own.
  if (TestArgs(argc, argv, {"over_declared"}).has("over_declared")) {
    CutAndChooseTriples<nP> one(&io, &pool, party, abit, sid ^ makeBlock(0, 1), 40, kBatch, nullptr, 1);
    one.take(kBatch + 1, mac, key);   // the second batch
    return 1;
  }
  constexpr int64_t kDeclared = int64_t(1) << 20;
  const CutAndChooseParams second = cut_and_choose_params(kBatch, cut_and_choose_batch_target(40, 2));
  const CutAndChooseParams declared =
      cut_and_choose_params(kBatch, cut_and_choose_declared_target(40, kDeclared));
  CutAndChooseTriples<nP> many(&io, &pool, party, abit, sid ^ makeBlock(0, 2), 40, kBatch, nullptr,
                               kDeclared);
  many.take(1500, mac, key);
  ok = check_triples(&io, abit, mac, key, 1500) && ok;
  const CutAndChooseParams &D = many.last_params();
  ok = ok && many.batches() == 2 && D.pop == declared.pop && D.B == declared.B &&
       D.T == declared.T && declared.B > second.B;
  const std::vector<int64_t> want = {3 * declared.pop, 3 * declared.pop};
  ok = ok && CutAndChooseTriples<nP>::draws(1500, 40, kBatch, kDeclared) == want;

  if (party == 1) {
    const CutAndChooseParams &P = cnc.last_params();
    std::printf("agmpc_cut_and_choose_np%d: batch 4 of %lld: B=%d T=%d t=%lld cut=%lld, "
                "%.1f aShares per triple: %s\n",
                nP, (long long)P.ell, P.B, P.T, (long long)P.t, (long long)P.cut,
                3.0 * (double)cnc.candidates() / (double)cnc.outputs(), ok ? "GOOD!" : "BAD!");
  }
  return ok ? 0 : 1;
}
