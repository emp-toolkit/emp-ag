#ifndef EMP_AG_BACKEND_TRIPLE_BEAVER_H__
#define EMP_AG_BACKEND_TRIPLE_BEAVER_H__
//
// Beaver multiplication of the AND gates' input masks against authenticated triples
// (a, b, c = a AND b): for gate i the parties open x = lambda_alpha ^ a and
// y = lambda_beta ^ b and set
//   lambda_alpha lambda_beta = c ^ x b ^ y a ^ x y.
// x and y are checked against their MACs in the caller's open check (ashare/open_check.h),
// with whatever the caller opened before them in the same call. Both AND-gate protocols
// end with it (triple/leaky_and_prep.h, triple/cut_and_choose_triples.h), in three steps:
// begin() starts the call's runs, open() sends x (and y), and finish() checks every
// opening and folds the products. With a check whose tags ride the bits
// (PairwiseOpenCheck), x's flight also carries this party's tag over every opening of the
// call, so the call's check costs no flight of its own; the caller folds its earlier
// values' sent() halves before open(), and their expected() halves in finish().
//
// With kBIsBeta, the triple's b is the gate's lambda_beta itself: the leaky ANDs give
// their unrotated row lambda_beta as its b. Then y = 0 is known, only x is opened, and
//   lambda_alpha lambda_beta = c ^ x b.
//
// The triples are a row of aShares (triple/triple_row.h). The input masks are what the
// draw walk wrote into inputs(L): the share bits, and the MACs and keys per peer or the
// mu's, whichever OpenCheck reads.
//
#include "emp-ag/backend/ashare/source.h"       // AShareSource
#include "emp-ag/backend/ashare/share.h"
#include "emp-ag/backend/common/lane_mesh.h"
#include "emp-ag/backend/common/runtime.h"      // parallel_for
#include "emp-ag/backend/triple/and_prep.h"     // AndInputs
#include "emp-ag/backend/triple/triple_row.h"
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/core/block_vector.h"
#include <vector>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

template <int nP, class OpenCheck, bool kBIsBeta = false>
class Beaver {
public:
  Beaver(const LaneMesh<nP> &mesh, block Delta) : mesh_(mesh), party_(mesh.party), Delta_(Delta) {}

  // The walk's buffers for L gates (grow-only, kept across calls), for the masks this
  // step opens: lambda_alpha always, lambda_beta unless kBIsBeta (the caller then places
  // lambda_beta itself, as the triple's b).
  AndInputs<nP> inputs(int L) {
    if (alpha_bit_.size() < (size_t)L) alpha_bit_.resize((size_t)L);
    if (!kBIsBeta && beta_bit_.size() < (size_t)L) beta_bit_.resize((size_t)L);
    AndInputs<nP> in;
    in.alpha_bit = alpha_bit_.data();
    if constexpr (!kBIsBeta) in.beta_bit = beta_bit_.data();
    if constexpr (OpenCheck::kPerPeerOperands) {
      for (int p = 1; p <= nP; ++p) if (p != party_) {
        for (BlockVec *v : {&alpha_mac_[p], &alpha_key_[p]})
          if (v->size() < (size_t)L) v->resize((size_t)L);
        in.alpha_mac[p] = alpha_mac_[p].data(); in.alpha_key[p] = alpha_key_[p].data();
        if constexpr (!kBIsBeta) {
          for (BlockVec *v : {&beta_mac_[p], &beta_key_[p]})
            if (v->size() < (size_t)L) v->resize((size_t)L);
          in.beta_mac[p] = beta_mac_[p].data(); in.beta_key[p] = beta_key_[p].data();
        }
      }
    } else {
      if (alpha_mu_.size() < (size_t)L) alpha_mu_.resize((size_t)L);
      in.alpha_mu = alpha_mu_.data();
      if constexpr (!kBIsBeta) {
        if (beta_mu_.size() < (size_t)L) beta_mu_.resize((size_t)L);
        in.beta_mu = beta_mu_.data();
      }
    }
    in_ = in;
    return in;
  }

  // The runs of one call's openings, in order: `earlier` values the caller opened before
  // x, then x, then y (unless kBIsBeta). Begin them before open(): the symmetric check
  // draws its coin only at seal(), in finish(), and the pairwise one folds x's tags in
  // open().
  struct Runs {
    typename OpenCheck::Run earlier, x, y;
  };
  Runs begin(OpenCheck &check, int64_t earlier, int L) {
    Runs r;
    r.earlier = check.begin(earlier);
    r.x = check.begin(L);
    if constexpr (!kBIsBeta) r.y = check.begin(L);
    return r;
  }

  // Open x (and y, unless kBIsBeta) for the L gates against the triples `t`: this party's
  // shares go to every peer in one flight, lane-split. With OpenCheck::kTagRidesBits, x's
  // (and y's) tags are folded first and this party's tag toward each peer goes out with its
  // bits on mesh 0, so every earlier value's sent() must be merged before this call.
  void open(OpenCheck &check, const Runs &runs, const TripleRow<nP> &t, int L) {
    const int any_peer = (party_ == 1) ? 2 : 1;
    std::vector<unsigned char>(&x)[nP + 1] = x_;
    std::vector<unsigned char>(&y)[nP + 1] = y_;
    for (int p = 1; p <= nP; ++p) {
      if (x[p].size() < (size_t)L) x[p].resize((size_t)L);
      if (!kBIsBeta && y[p].size() < (size_t)L) y[p].resize((size_t)L);
    }
    ag::parallel_for(mesh_.pool, L, [&](int lo, int hi) {
      for (int i = lo; i < hi; ++i) {
        x[party_][i] = (unsigned char)(in_.alpha_bit[i] ^ getLSB(t.mac[0][any_peer][i]));
        if constexpr (!kBIsBeta)
          y[party_][i] = (unsigned char)(in_.beta_bit[i] ^ getLSB(t.mac[1][any_peer][i]));
      }
    });
    if constexpr (kTestHooks) {
      // TEST-ONLY (hook flip_xy): a malicious party 2 flips its share of the first x and
      // sends it to everyone, keeping it itself, so every party forms the same wrong x and
      // a validly authenticated σ ⊕ λ_β. The open check must abort.
      if (hooks().flip_xy && party_ == 2) x[party_][0] ^= 1;
    }
    // x's and y's tags: x's MAC under a peer's key is the XOR of the two MACs.
    if constexpr (OpenCheck::kTagRidesBits) {
      ag::parallel_for(mesh_.pool, L, [&](int lo, int hi) {
        auto lane_x = check.lane(runs.x);
        [[maybe_unused]] auto lane_y = check.lane(runs.y);
        for (int i = lo; i < hi; ++i)
          for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
            lane_x.sent(peer, i, in_.alpha_mac[peer][i] ^ t.mac[0][peer][i]);
            if constexpr (!kBIsBeta) lane_y.sent(peer, i, in_.beta_mac[peer][i] ^ t.mac[1][peer][i]);
          }
        check.merge(lane_x);
        if constexpr (!kBIsBeta) check.merge(lane_y);
      });
    }
    // Lane-split; the combine in finish() runs on the assembled x[]/y[]. Both x and y
    // ride the same slice on each mesh, so P1's window cannot desync.
    mesh_.fan_out(L,
      [this, &x, &y, &check](NetIOMP<nP> *ch, int peer, int lo, int hi) {
        ch->send_bool(peer, (const bool *)(x[party_].data() + lo), hi - lo);
        if constexpr (!kBIsBeta) ch->send_bool(peer, (const bool *)(y[party_].data() + lo), hi - lo);
        if constexpr (OpenCheck::kTagRidesBits)
          if (ch == mesh_.io) {
            block tag = check.tag(peer);
            if constexpr (kTestHooks) {
              // TEST-ONLY (hook flip_tag): party 2 flips the last byte of the tag it sends
              // to P1, which P1 must catch at any tag width.
              if (hooks().flip_tag && party_ == 2 && peer == 1)
                ((unsigned char *)&tag)[check.tag_bytes() - 1] ^= 1;
            }
            ch->send_data(peer, &tag, (size_t)check.tag_bytes());
          }
        ch->flush(peer);
      },
      [this, &x, &y, &check](NetIOMP<nP> *ch, int peer, int lo, int hi) {
        ch->recv_bool(peer, (bool *)(x[peer].data() + lo), hi - lo);
        if constexpr (!kBIsBeta) ch->recv_bool(peer, (bool *)(y[peer].data() + lo), hi - lo);
        if constexpr (OpenCheck::kTagRidesBits)
          if (ch == mesh_.io) {
            peer_tag_[peer] = zero_block;
            ch->recv_data(peer, &peer_tag_[peer], (size_t)check.tag_bytes());
          }
      });
  }

  // Check every opening of the call and write out[i] = lambda_alpha_i lambda_beta_i.
  // check_earlier(runs.earlier) feeds the checks of the values the caller opened before x
  // once the check is sealed (with tags that ride the bits, only their expected() halves).
  // The symmetric check's zero test also agrees on the view of the aShare consistency
  // check of every share minted since the last one; with the pairwise check that view is
  // settled on its own here.
  template <class CheckEarlier>
  void finish(OpenCheck &check, AShareSource<nP> &abit, const Runs &runs,
              const TripleRow<nP> &t, int L, CheckEarlier &&check_earlier,
              AShareBundleVec<nP> &out) {
    const int any_peer = (party_ == 1) ? 2 : 1;
    std::vector<unsigned char>(&x)[nP + 1] = x_;
    std::vector<unsigned char>(&y)[nP + 1] = y_;
    // x and y are shares of λ_α ⊕ a and λ_β ⊕ b, authenticated by the XOR of those
    // MACs (keys). Every open of this call is in now: the check's coin is drawn (the
    // symmetric check's; the pairwise one has none).
    check.seal();
    if constexpr (OpenCheck::kAgreesViews) {
      const auto pending = abit.take_pending_check2();
      if (pending.any) check.agree(pending.view);
    }
    check_earlier(runs.earlier);

    out.resize(L);
    // Branchless Beaver fold, width-split (out[i] is disjoint per i), fused with
    // the combine of x and y and with their open check: every MAC and key of the
    // triple's a and b is loaded once for both. x[p]/y[p] stay as each party sent them.
    ag::parallel_for(mesh_.pool, L, [&](int lo, int hi) {
      auto lane_x = check.lane(runs.x);
      [[maybe_unused]] auto lane_y = check.lane(runs.y);
      for (int i = lo; i < hi; ++i) {
        unsigned char xv = 0, yv = 0;
        for (int p = 1; p <= nP; ++p) {
          xv ^= x[p][i];
          if constexpr (!kBIsBeta) yv ^= y[p][i];
        }
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
            if constexpr (!OpenCheck::kTagRidesBits) lane_x.sent(peer, i, in_.alpha_mac[peer][i] ^ am);
            lane_x.expected(peer, i, in_.alpha_key[peer][i] ^ ak, x[peer][i]);
            if constexpr (!kBIsBeta) {
              if constexpr (!OpenCheck::kTagRidesBits) lane_y.sent(peer, i, in_.beta_mac[peer][i] ^ bm);
              lane_y.expected(peer, i, in_.beta_key[peer][i] ^ bk, y[peer][i]);
            }
          } else {
            sum_a = sum_a ^ am ^ ak;
            if constexpr (!kBIsBeta) sum_b = sum_b ^ bm ^ bk;
          }
        }
        if constexpr (!OpenCheck::kPerPeerOperands) {
          // mu_i(x) = mu_i(λ_α) ^ own_a * Δ_i ^ sum_a, so the residual adds the
          // captured mu_i(λ_α) to the triple's part; y likewise.
          lane_x.put(i, in_.alpha_mu[i] ^ check.residual(
                                             (unsigned char)getLSB(t.mac[0][any_peer][i]) ^ xv, sum_a));
          if constexpr (!kBIsBeta)
            lane_y.put(i, in_.beta_mu[i] ^ check.residual(
                                              (unsigned char)getLSB(t.mac[1][any_peer][i]) ^ yv, sum_b));
        }
        if (xv && yv)
          add_public_one<nP>(party_, Delta_,
                             [&](int p) -> block & { return sb.mac(peer_slot(party_, p)); },
                             [&](int p) -> block & { return sb.key(peer_slot(party_, p)); });
      }
      check.merge(lane_x);
      if constexpr (!kBIsBeta) check.merge(lane_y);
    });
    // Settle every open of this call before the products are returned.
    if constexpr (OpenCheck::kTagRidesBits)
      check.check_result(peer_tag_);
    else
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
  // Every party's shares of x and y, as sent, and each peer's tag as it came with them.
  std::vector<unsigned char> x_[nP + 1], y_[nP + 1];
  block peer_tag_[nP + 1] = {};
};

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_TRIPLE_BEAVER_H__
