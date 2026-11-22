#ifndef EMP_AG_BACKEND_TRIPLE_BEAVER_H__
#define EMP_AG_BACKEND_TRIPLE_BEAVER_H__
//
// Beaver multiplication of the AND gates' input masks against authenticated triples
// (a, b, c = a AND b): for gate i the parties open x = lambda_alpha ^ a and
// y = lambda_beta ^ b and set
//   lambda_alpha lambda_beta = c ^ x b ^ y a ^ x y.
// x and y are checked against their MACs in the caller's open check (ashare/open_check.h),
// with whatever the caller opened before them in the same call. Both AND-gate protocols
// end with it (triple/leaky_and_prep.h, triple/cut_and_choose_triples.h).
//
// The triples are a row of aShares (triple/triple_row.h). The input masks are what the draw walk wrote into inputs(L): the share bits, and the
// MACs and keys per peer or the mu's, whichever OpenCheck reads.
//
#include "emp-ag/backend/ashare/ashare_gen.h"   // AShareSource
#include "emp-ag/backend/ashare/share.h"
#include "emp-ag/backend/common/lane_mesh.h"
#include "emp-ag/backend/common/runtime.h"      // parallel_for
#include "emp-ag/backend/triple/and_prep.h"     // AndInputs
#include "emp-ag/backend/triple/triple_row.h"
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/core/block_vector.h"
#include <vector>

namespace emp::ag {

template <int nP, class OpenCheck>
class Beaver {
public:
  Beaver(const LaneMesh<nP> &mesh, block Delta) : mesh_(mesh), party_(mesh.party), Delta_(Delta) {}

  // The walk's buffers for L gates (grow-only, kept across calls).
  AndInputs<nP> inputs(int L) {
    if (alpha_bit_.size() < (size_t)L) {
      alpha_bit_.resize((size_t)L);
      beta_bit_.resize((size_t)L);
    }
    AndInputs<nP> in;
    in.alpha_bit = alpha_bit_.data();
    in.beta_bit = beta_bit_.data();
    if constexpr (OpenCheck::kPerPeerOperands) {
      for (int p = 1; p <= nP; ++p) if (p != party_) {
        for (BlockVec *v : {&alpha_mac_[p], &alpha_key_[p], &beta_mac_[p], &beta_key_[p]})
          if (v->size() < (size_t)L) v->resize((size_t)L);
        in.alpha_mac[p] = alpha_mac_[p].data(); in.alpha_key[p] = alpha_key_[p].data();
        in.beta_mac[p] = beta_mac_[p].data(); in.beta_key[p] = beta_key_[p].data();
      }
    } else {
      if (alpha_mu_.size() < (size_t)L) {
        alpha_mu_.resize((size_t)L);
        beta_mu_.resize((size_t)L);
      }
      in.alpha_mu = alpha_mu_.data();
      in.beta_mu = beta_mu_.data();
    }
    in_ = in;
    return in;
  }

  // Open x and y for the L gates against the triples `t`: this party's shares go to every
  // peer in one flight, lane-split.
  void open(const TripleRow<nP> &t, int L) {
    const int any_peer = (party_ == 1) ? 2 : 1;
    std::vector<unsigned char>(&x)[nP + 1] = x_;
    std::vector<unsigned char>(&y)[nP + 1] = y_;
    for (int p = 1; p <= nP; ++p) {
      if (x[p].size() < (size_t)L) x[p].resize((size_t)L);
      if (y[p].size() < (size_t)L) y[p].resize((size_t)L);
    }
    ag::parallel_for(mesh_.pool, L, [&](int lo, int hi) {
      for (int i = lo; i < hi; ++i) {
        x[party_][i] = (unsigned char)(in_.alpha_bit[i] ^ getLSB(t.mac[0][any_peer][i]));
        y[party_][i] = (unsigned char)(in_.beta_bit[i] ^ getLSB(t.mac[1][any_peer][i]));
      }
    });
#ifdef EMP_AG_TEST_FLIP_XY
    // TEST-ONLY (never in production): a malicious party 2 flips its share of the first
    // x and sends it to everyone, keeping it itself, so every party forms the same
    // wrong x and a validly authenticated σ ⊕ λ_β. The open check must abort.
    if (party_ == 2) x[party_][0] ^= 1;
#endif
    // Lane-split; the combine in finish() runs on the assembled x[]/y[]. Both x and y
    // ride the same slice on each mesh, so P1's window cannot desync.
    mesh_.fan_out(L,
      [this, &x, &y](NetIOMP<nP> *ch, int peer, int lo, int hi) {
        ch->send_bool(peer, (const bool *)(x[party_].data() + lo), hi - lo);
        ch->send_bool(peer, (const bool *)(y[party_].data() + lo), hi - lo);
        ch->flush(peer);
      },
      [&x, &y](NetIOMP<nP> *ch, int peer, int lo, int hi) {
        ch->recv_bool(peer, (bool *)(x[peer].data() + lo), hi - lo);
        ch->recv_bool(peer, (bool *)(y[peer].data() + lo), hi - lo);
      });
  }

  // Check every opening of the call and write out[i] = lambda_alpha_i lambda_beta_i.
  // The caller opened `earlier` values before x and y; their run comes first, and
  // check_earlier(run) feeds their checks into it once the check is sealed. The
  // symmetric check's zero test also agrees on the view of the aShare consistency check
  // of every share minted since the last one; with the pairwise check that view is
  // settled on its own here.
  template <class CheckEarlier>
  void finish(OpenCheck &check, AShareSource<nP> &abit, const TripleRow<nP> &t, int L,
              int64_t earlier, CheckEarlier &&check_earlier, AShareBundleVec<nP> &out) {
    const int any_peer = (party_ == 1) ? 2 : 1;
    std::vector<unsigned char>(&x)[nP + 1] = x_;
    std::vector<unsigned char>(&y)[nP + 1] = y_;
    // x and y are shares of λ_α ⊕ a and λ_β ⊕ b, authenticated by the XOR of those
    // MACs (keys). Every open of this call is in now: the runs start and the check's
    // coin is drawn (the symmetric check's; the pairwise one has none).
    const typename OpenCheck::Run run_e = check.begin(earlier);
    const typename OpenCheck::Run run_x = check.begin(L);
    const typename OpenCheck::Run run_y = check.begin(L);
    check.seal();
    if constexpr (OpenCheck::kAgreesViews) {
      const auto pending = abit.take_pending_check2();
      if (pending.any) check.agree(pending.view);
    }
    check_earlier(run_e);

    out.resize(L);
    block dxor = Delta_ ^ bit0_mask;
    // Branchless Beaver fold, width-split (out[i] is disjoint per i), fused with
    // the combine of x and y and with their open check: every MAC and key of the
    // triple's a and b is loaded once for both. x[p]/y[p] stay as each party sent them.
    ag::parallel_for(mesh_.pool, L, [&](int lo, int hi) {
      auto lane_x = check.lane(run_x), lane_y = check.lane(run_y);
      for (int i = lo; i < hi; ++i) {
        unsigned char xv = 0, yv = 0;
        for (int p = 1; p <= nP; ++p) { xv ^= x[p][i]; yv ^= y[p][i]; }
        // mask each addend by select_mask rather than branching on the two random
        // public selectors.
        const block mx = select_mask[xv], my = select_mask[yv];
        AShareBundle<nP> &sb = out[i];
        [[maybe_unused]] block sum_a = zero_block, sum_b = zero_block;
        for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
          const int slot = peer_slot(party_, peer);
          const block am = t.mac[0][peer][i], bm = t.mac[1][peer][i];
          const block ak = t.key[0][peer][i], bk = t.key[1][peer][i];
          sb.mac(slot) = t.mac[2][peer][i] ^ (bm & mx) ^ (am & my);
          sb.key(slot) = t.key[2][peer][i] ^ (bk & mx) ^ (ak & my);
          if constexpr (OpenCheck::kPerPeerOperands) {
            lane_x.sent(peer, i, in_.alpha_mac[peer][i] ^ am);
            lane_x.expected(peer, i, in_.alpha_key[peer][i] ^ ak, x[peer][i]);
            lane_y.sent(peer, i, in_.beta_mac[peer][i] ^ bm);
            lane_y.expected(peer, i, in_.beta_key[peer][i] ^ bk, y[peer][i]);
          } else {
            sum_a = sum_a ^ am ^ ak;
            sum_b = sum_b ^ bm ^ bk;
          }
        }
        if constexpr (!OpenCheck::kPerPeerOperands) {
          // mu_i(x) = mu_i(λ_α) ^ own_a * Δ_i ^ sum_a, so the residual adds the
          // captured mu_i(λ_α) to the triple's part; y likewise.
          lane_x.put(i, in_.alpha_mu[i] ^ check.residual(
                                             (unsigned char)getLSB(t.mac[0][any_peer][i]) ^ xv, sum_a));
          lane_y.put(i, in_.beta_mu[i] ^ check.residual(
                                            (unsigned char)getLSB(t.mac[1][any_peer][i]) ^ yv, sum_b));
        }
        if (xv && yv) {
          if (party_ != 1) {
            sb.key(peer_slot(party_, 1)) = sb.key(peer_slot(party_, 1)) ^ dxor;
          } else {
            for (int slot = 0; slot < AShareBundle<nP>::K; ++slot)
              sb.mac(slot) = sb.mac(slot) ^ bit0_mask;
          }
        }
      }
      check.merge(lane_x);
      check.merge(lane_y);
    });
    // Settle every open of this call before the products are returned.
    check.check_result();
    if constexpr (!OpenCheck::kAgreesViews) abit.settle_check2();
  }

private:
  LaneMesh<nP> mesh_;
  int party_;
  block Delta_;
  AndInputs<nP> in_{};
  // The walk's input masks (grow-only).
  std::vector<unsigned char> alpha_bit_, beta_bit_;
  BlockVec alpha_mac_[nP + 1], alpha_key_[nP + 1], beta_mac_[nP + 1], beta_key_[nP + 1];
  BlockVec alpha_mu_, beta_mu_;
  // Every party's shares of x and y, as sent.
  std::vector<unsigned char> x_[nP + 1], y_[nP + 1];
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_TRIPLE_BEAVER_H__
