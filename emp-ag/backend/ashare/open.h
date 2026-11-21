#ifndef EMP_AG_BACKEND_ASHARE_OPEN_H__
#define EMP_AG_BACKEND_ASHARE_OPEN_H__
//
// Opening authenticated shares to chosen parties, each opening checked by its
// recipient against its own keys.
//
#include "emp-ag/backend/ashare/share.h"
#include "emp-ag/backend/common/fs_hash.h"
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/common/runtime.h"
#include "emp-tool/runtime/core/utils.h"   // expecting
#include <cstring>
#include <vector>

namespace emp::ag {

// One-round all-to-all authenticated open. targets[t] = wires to open to party t. Every party
// sends each non-empty target t != self ONE message [share bits][MAC digest under t's key]; each
// target verifies every peer (key ^ bit·Δ) and reconstructs λ_w = ⊕_p λ_w^p. Returns the bits
// for targets[self] (empty if self is not a target). One message per directed pair -> the
// per-channel transcript is deterministic and a party sees only shares of wires opened TO IT.
template <int nP>
std::vector<unsigned char> open_to_targets(
    NetIOMP<nP> *io, ThreadPool *pool, int party, const block &Delta,
    const AShareBundle<nP> *base, const std::vector<std::vector<int>> &targets) {
  std::vector<std::vector<unsigned char>> tx(nP + 1);   // share bits I send to target t
  std::vector<std::vector<char>> txd(nP + 1);           // MAC digest I send to target t
  for (int t = 1; t <= nP; ++t) {
    if (t == party || targets[t].empty()) continue;
    int m = (int)targets[t].size();
    tx[t].resize(m);
    txd[t].resize(FsHash::DIGEST_SIZE);
    BlockVec macs(m);
    int slot = peer_slot(party, t);
    for (int j = 0; j < m; ++j) {
#ifdef EMP_AG_TEST_TWO_WORLD
      // TEST-ONLY (never in production): party 2 sends each target the bit it holds
      // toward that target (with EMP_AG_TEST_SPLIT_CHOICE those differ), so every
      // target's MAC check passes.
      tx[t][j] = (unsigned char)getLSB(base[targets[t][j]].mac(party == 2 ? slot : 0));
#else
      tx[t][j] = (unsigned char)getLSB(base[targets[t][j]].mac(0));
#endif
      macs[j] = base[targets[t][j]].mac(slot);
    }
    FsHash::hash_once(txd[t].data(), macs.data(), (size_t)m * sizeof(block));
  }

  const std::vector<int> &mine = targets[party];
  int mm = (int)mine.size();
  std::vector<std::vector<unsigned char>> rx(nP + 1);   // peer p's shares of MY wires
  std::vector<std::vector<char>> rxd(nP + 1);           // peer p's MAC digest
  if (mm > 0)
    for (int p = 1; p <= nP; ++p) if (p != party) {
      rx[p].resize(mm);
      rxd[p].resize(FsHash::DIGEST_SIZE);
    }

  // One round: send to every target + (if I'm a target) recv from every peer, concurrently.
  std::vector<future<void>> res;
  for (int t = 1; t <= nP; ++t) if (t != party && !targets[t].empty()) {
    int tt = t;
    res.push_back(pool->enqueue([io, &tx, &txd, tt]() {
      io->send_bool(tt, (const bool *)tx[tt].data(), (int)tx[tt].size());
      io->send_data(tt, txd[tt].data(), FsHash::DIGEST_SIZE);
      io->flush(tt);
    }));
  }
  if (mm > 0)
    for (int p = 1; p <= nP; ++p) if (p != party) {
      int pp = p;
      res.push_back(pool->enqueue([io, &rx, &rxd, pp, mm]() {
        io->recv_bool(pp, (bool *)rx[pp].data(), mm);
        io->recv_data(pp, rxd[pp].data(), FsHash::DIGEST_SIZE);
      }));
    }
  joinNclean(res);
  if (mm == 0) return {};

  // Verify each peer's shares of MY wires against my keys, then reconstruct λ = ⊕_p λ^p.
  std::vector<unsigned char> my_share(mm);
  for (int j = 0; j < mm; ++j) my_share[j] = (unsigned char)getLSB(base[mine[j]].mac(0));
  BlockVec exp_macs(mm);
  for (int p = 1; p <= nP; ++p) if (p != party) {
    int slot = peer_slot(party, p);
    for (int j = 0; j < mm; ++j)
      exp_macs[j] = base[mine[j]].key(slot) ^ (select_mask[rx[p][j]] & Delta);
    char D_exp[FsHash::DIGEST_SIZE];
    FsHash::hash_once(D_exp, exp_macs.data(), (size_t)mm * sizeof(block));
    expecting(memcmp(D_exp, rxd[p].data(), FsHash::DIGEST_SIZE) == 0,
              "open_to_targets: share-MAC hash mismatch");
  }
  std::vector<unsigned char> lam(mm);
  for (int j = 0; j < mm; ++j) {
    unsigned char v = my_share[j];
    for (int p = 1; p <= nP; ++p) if (p != party) v = v ^ rx[p][j];
    lam[j] = (unsigned char)(v & 1);
  }
  return lam;
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_ASHARE_OPEN_H__
