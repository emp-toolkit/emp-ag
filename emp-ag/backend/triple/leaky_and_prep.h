#ifndef EMP_AG_BACKEND_TRIPLE_LEAKY_AND_PREP_H__
#define EMP_AG_BACKEND_TRIPLE_LEAKY_AND_PREP_H__
//
// The AND gates' products from leaky AND triples made per call (triple/and_prep.h):
// Pi_LaAND (triple/laand.h) on B rows of L candidates, bucketing (triple/merge.h) of
// the B rows into L authenticated triples, then Beaver against the gates' input masks
// (triple/beaver.h). B comes from the leakage bound at L
// (triple/bucketing.h).
//
// Row 0, which the rotations leave in place, takes gate j's lambda_beta (the mask of its
// second input) as its j-th b. The leaky AND leaks only a, and b enters it only
// linearly; the merge keeps row 0's b, and every opened difference lambda_beta ^ b_m is
// masked by a fresh, leak-free b_m. So bucket j's triple is (a_j, lambda_beta,
// a_j lambda_beta), and Beaver opens only x = lambda_alpha ^ a_j. Every a, every r and
// the b of every other row is fresh in this call; lambda_alpha is read only by Beaver.
// The walk writes gate j's lambda_beta at index j of row 0's b, and row 0's rotation is
// the constant 0, so the alignment holds by construction.
//
// Per call:
//   1. mint every row's fresh shares in one draw, and run the leaky ANDs on the rows:
//      every row's half-gate rows in one flight, and every s-bit in the next
//      (triple/laand.h);
//   2. draw the post-commitment coin, commit-then-open at every nP (at nP == 2 its
//      commitments ride the rows and its openings the s-bits): it folds the consistency
//      check of every share drawn since the last call, gives the rotations, continues as
//      the nP >= 3 leaky-AND challenge, and is the call's coin;
//   3. open every bucket difference in one all-to-all flight (the B-1 rows' openings,
//      batched; at nP == 2 the F_eq commitment rides along), and merge;
//   4. finish the leaky ANDs' check;
//   5. Beaver: open x, and check it and the bucket differences in one open check.
//
#include "emp-ag/backend/ashare/ashare_gen.h"
#include "emp-ag/backend/ashare/open_check.h"   // DefaultOpenCheck
#include "emp-ag/backend/common/bucket_coin.h"
#include "emp-ag/backend/common/feq.h"
#include "emp-ag/backend/common/fs_hash.h"
#include "emp-ag/backend/common/lane_mesh.h"
#include "emp-ag/backend/common/profiling.h"
#include "emp-ag/backend/common/protocols.h"    // sampleRandom
#include "emp-ag/backend/common/runtime.h"
#include "emp-ag/backend/triple/and_prep.h"
#include "emp-ag/backend/triple/beaver.h"
#include "emp-ag/backend/triple/bucketing.h"    // bucket_size
#include "emp-ag/backend/triple/laand.h"
#include "emp-ag/backend/triple/merge.h"
#include "emp-ag/backend/triple/triple_row.h"
#include "emp-tool/runtime/crypto/prg.h"
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <vector>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

template <int nP, class OpenCheck = DefaultOpenCheck<nP>>
class LeakyAndPrep : public AndPrep<nP> {
public:
  explicit LeakyAndPrep(const AndPrepContext<nP> &ctx)
      : mesh_(ctx.io, ctx.grp, ctx.pool, ctx.party), party_(ctx.party),
        ssp_(ag::checked_statistical_security(ctx.ssp)), sid_(ctx.session_id),
        abit_(*ctx.abit), Delta_(abit_.delta()),
        open_check_(ctx.io, ctx.pool, ctx.party, Delta_, ctx.session_id, &prg_, ctx.grp),
        laand_(mesh_, ssp_, sid_, Delta_, &prg_), beaver_(mesh_, Delta_) {}

  // B for n ANDs, and every bucketed size within int.
  void validate(int64_t n) override {
    expecting(n >= 0, "leaky ANDs: negative batch length");
    if (n == 0) return;
    expecting(n <= (int64_t)INT_MAX, "leaky ANDs: chunk too large -- split into chunks");
    const int B = ag::bucket_size((int)n, ssp_);
    // All bucketing arithmetic scales L by up to 3B in int (the (3B-1)*L draw, (B-1)*L
    // differences, the B*L RLC stash). Reject a chunk too large for that to fit int
    // rather than silently wrapping; callers split work into chunks long before this
    // bound for memory reasons anyway.
    expecting((int64_t)3 * B * n <= (int64_t)INT_MAX,
              "leaky ANDs: chunk too large (bucketed size overflows int) -- split into chunks");
  }

  // lambda_alpha for Beaver, and lambda_beta straight into row 0's b.
  AndInputs<nP> inputs(int64_t n) override {
    AndInputs<nP> in = beaver_.inputs((int)n);
    for (int p = 1; p <= nP; ++p) if (p != party_) {
      if (beta_mac_[p].size() < (size_t)n) {
        beta_mac_[p].resize((size_t)n);
        beta_key_[p].resize((size_t)n);
      }
      in.beta_mac[p] = beta_mac_[p].data();
      in.beta_key[p] = beta_key_[p].data();
    }
    return in;
  }

  block run(int64_t n, AShareBundleVec<nP> &out) override {
    validate(n);
    out.clear();
    if (n == 0) return zero_block;
    const int L = (int)n;
    const int B = ag::bucket_size(L, ssp_);
    const int any_peer = (party_ == 1) ? 2 : 1;
#ifdef AG_PROFILE
    g_ag_tp_cot_ns = g_ag_tp_hg_ns = g_ag_tp_sopen_ns = 0;
    g_ag_tp_acheck_ns = g_ag_tp_bkt_ns = g_ag_tp_open_ns = 0;
#endif

    // 1. B rows of L leaky triples, every share but row 0's b fresh, from one draw. At
    //    nP == 2 the bucket coin's commitments ride the half-gate rows and its openings
    //    the s-bits.
    FsHash feq;   // nP == 2: the F_eq transcript over every row's windows
    laand_.begin_call();
    const std::vector<TripleRow<nP>> rows = mint_rows_(B, L);
    [[maybe_unused]] BucketCoin2PC seeds;
    typename LeakyAnd<nP>::Carry carry;
    if constexpr (nP == 2) {
      bucket_coin_commit(seeds, prg_, sid_, party_);
      carry = {seeds.com_mine, seeds.com_peer, FsHash::DIGEST_SIZE,
               &seeds.mine, &seeds.peer, sizeof(block)};
    }
    laand_.produce_rows(rows, L, feq, carry);

    // 2. The post-commitment coin, after every row is fixed: every party holds it here.
    //    It folds check2 of this call's draws (the walk's masks and every row), drawn
    //    before it and not yet bucketed, and seeds the rotations. It is commit-then-open
    //    at every nP, never a hash of the transcript: the rotations must be unpredictable
    //    when the rows fix the leaky triples, and a party's later messages must not move
    //    them. Its s-bits carry its selective-failure guesses, so with a transcript hash
    //    a party could try every guess vector offline and send the one whose rotations
    //    fill a bucket with its leaky triples.
    block coin;
    if constexpr (nP == 2)
      coin = bucket_coin_open(seeds, sid_, party_);
    else
      coin = sampleRandom<nP>(mesh_.io, &prg_, mesh_.pool, party_, sid_);
    abit_.fold_check2(coin);
    PRG cprg(&coin);
    const Buckets bk = ag::draw_buckets(cprg, B, L);

    // 3. Open the differences and merge.
    const int D = (int)bk.differences();
    for (int p = 0; p <= nP; ++p)
      if (d_[p].size() < (size_t)D) d_[p].resize((size_t)D);
    ag::merge_difference_shares(rows, bk, any_peer, d_[party_].data(), mesh_.pool);
    if constexpr (nP == 2) feq2_ = laand_.feq_commit(feq);
#ifdef AG_PROFILE
    uint64_t _b0 = agmpc_now_ns();
#endif
    if constexpr (kTestHooks) {
      // TEST-ONLY (hook flip_d): a malicious party 2 flips its share of the first
      // difference and sends the flipped share to everyone, keeping it itself, so every
      // party combines the same wrong d. The open check must abort.
      if (hooks().flip_d && party_ == 2 && D > 0) d_[party_][0] ^= 1;
    }
    // Lane-split: a plain bit-vector (no keying, no coin reads it), combined below on
    // the assembled d_[] after the one join.
    mesh_.fan_out(D,
      [this](NetIOMP<nP> *ch, int peer, int lo, int hi) {
        ch->send_bool(peer, (const bool *)(d_[party_].data() + lo), hi - lo);
        if constexpr (nP == 2)
          if (ch == mesh_.io) ch->send_data(peer, feq2_.commitment, FsHash::DIGEST_SIZE);
        ch->flush(peer);
      },
      [this](NetIOMP<nP> *ch, int peer, int lo, int hi) {
        ch->recv_bool(peer, (bool *)(d_[peer].data() + lo), hi - lo);
        if constexpr (nP == 2)
          if (ch == mesh_.io) ch->recv_data(peer, feq2_.peer_commitment, FsHash::DIGEST_SIZE);
      });
    // The opened d = XOR over all parties, into d_[0]; every d_[p] stays as sent, for
    // the open check.
    ag::parallel_for(mesh_.pool, D, [this](int j0, int j1) {
      for (int j = j0; j < j1; ++j) {
        unsigned char v = 0;
        for (int p = 1; p <= nP; ++p) v ^= d_[p][j];
        d_[0][j] = v;
      }
    });
    ag::merge_combine(rows, bk, d_[0].data(), party_, mesh_.pool);
#ifdef AG_PROFILE
    g_ag_tp_bkt_ns += agmpc_now_ns() - _b0;
#endif

    // 4. The leaky ANDs' check over every row. It completes before x is opened: this
    //    preparation also runs after inputs are bound (the direct path), where an x sent
    //    on a run whose check then fails could pair with what the guesses revealed.
    laand_.finish_check(cprg, feq2_);

#ifdef AG_PROFILE
    uint64_t _tp_o0 = agmpc_now_ns();
#endif
    // 5. Beaver on the merged triples, in row 0. The differences are checked in the same
    //    open check, as a run before x; with tags that ride the bits, their tags go out
    //    with x, so their sent() halves come first.
    const auto runs = beaver_.begin(open_check_, D, L);
    if constexpr (OpenCheck::kTagRidesBits)
      check_differences_(runs.earlier, rows, bk, /*sent=*/true, /*expected=*/false);
    beaver_.open(open_check_, runs, rows[0], L);
    beaver_.finish(open_check_, abit_, runs, rows[0], L,
                   [&](const typename OpenCheck::Run &run) {
                     check_differences_(run, rows, bk, !OpenCheck::kTagRidesBits, true);
                   },
                   out);
#ifdef AG_PROFILE
    g_ag_tp_open_ns += agmpc_now_ns() - _tp_o0;
    if (party_ == 1) {
      auto ms = [](uint64_t ns) { return (double)ns / 1.0e6; };
      uint64_t sum = g_ag_tp_cot_ns + g_ag_tp_hg_ns + g_ag_tp_sopen_ns +
                     g_ag_tp_acheck_ns + g_ag_tp_bkt_ns + g_ag_tp_open_ns;
      std::printf("[ag-tp]   -- leaky-AND breakdown (B=%d rows, L=%d) --\n", B, L);
      std::printf("[ag-tp]     COT/aShare draw  %9.1f ms\n", ms(g_ag_tp_cot_ns));
      std::printf("[ag-tp]     half-gate phi    %9.1f ms\n", ms(g_ag_tp_hg_ns));
      std::printf("[ag-tp]     s-open           %9.1f ms\n", ms(g_ag_tp_sopen_ns));
      std::printf("[ag-tp]     alpha check      %9.1f ms\n", ms(g_ag_tp_acheck_ns));
      std::printf("[ag-tp]     bucket merge     %9.1f ms\n", ms(g_ag_tp_bkt_ns));
      std::printf("[ag-tp]     final open       %9.1f ms\n", ms(g_ag_tp_open_ns));
      std::printf("[ag-tp]     sub-sum          %9.1f ms\n", ms(sum));
    }
#endif
    return coin;
  }

  // The share draws of a call run(n) at statistical security ssp (AndPrepFactory::draws):
  // one, of (3B - 1) n, in mint_rows_.
  static std::vector<int64_t> draws(int64_t n, int ssp) {
    if (n <= 0) return {};
    expecting(n <= (int64_t)INT_MAX, "leaky ANDs: chunk too large -- split into chunks");
    const int B = ag::bucket_size((int)n, ag::checked_statistical_security(ssp));
    return {(3 * (int64_t)B - 1) * n};
  }

private:
  LaneMesh<nP> mesh_;
  int party_;
  int ssp_;
  block sid_;
  AShareSource<nP> &abit_;   // the session's share pool; its owner outlives this
  block Delta_;
  PRG prg_;
  OpenCheck open_check_;     // checks the differences and x against their MACs
  LeakyAnd<nP> laand_;
  Beaver<nP, OpenCheck, /*kBIsBeta=*/true> beaver_;
  // Reused per-call rows (grow-only), one draw per call: row 0, which the merge turns
  // into the call's triples, [a | r] of L per peer with the walk's lambda_beta as its b;
  // then rows 1..B-1, each [a | b | r].
  BlockVec acc_mac_[nP + 1], acc_key_[nP + 1];
  BlockVec beta_mac_[nP + 1], beta_key_[nP + 1];
  // The differences as each party sent them (d_[p]), and opened (d_[0]).
  std::vector<unsigned char> d_[nP + 1];
  FeqSymmetric2PC feq2_{};   // nP == 2: the leaky ANDs' F_eq, between steps 3 and 4

  // Mint every row's fresh shares in one draw of (3B - 1) L and return the B rows: row 0
  // as [a | r] with the walk's lambda_beta as its b, then every other row as [a | b | r].
  // The draw's check2 waits for the call's coin: the rows stay put until then, changed
  // only by the leaky ANDs' public corrections, and nothing resizes their vectors.
  std::vector<TripleRow<nP>> mint_rows_(int B, int L) {
#ifdef AG_PROFILE
    uint64_t _tp_c0 = agmpc_now_ns();
#endif
    abit_.compute_deferred(acc_mac_, acc_key_, (3 * B - 1) * L);
#ifdef AG_PROFILE
    g_ag_tp_cot_ns += agmpc_now_ns() - _tp_c0;
#endif
    std::vector<TripleRow<nP>> rows((size_t)B);
    for (int p = 1; p <= nP; ++p) if (p != party_) {
      rows[0].mac[0][p] = acc_mac_[p].data();
      rows[0].key[0][p] = acc_key_[p].data();
      rows[0].mac[1][p] = beta_mac_[p].data();
      rows[0].key[1][p] = beta_key_[p].data();
      rows[0].mac[2][p] = acc_mac_[p].data() + L;
      rows[0].key[2][p] = acc_key_[p].data() + L;
    }
    for (int k = 1; k < B; ++k)
      rows[(size_t)k] = strided_row<nP>(acc_mac_, acc_key_, (int64_t)(3 * k - 1) * L, L, party_);
    return rows;
  }

  // The differences' checks, in `run`: the pairwise check's tags from this party's MACs
  // (`sent`) and from its keys and the bits it received (`expected`) on the two b's, or
  // the symmetric check's residuals (this party's share XOR the opened bit, against the
  // same MACs and keys), which need both flags. The b's are untouched since the opening.
  void check_differences_(const typename OpenCheck::Run &run,
                          const std::vector<TripleRow<nP>> &rows, const Buckets &bk,
                          bool sent, bool expected) {
    const int L = (int)bk.ell;
    for (int m = 1; m < bk.B; ++m) {
      const size_t off = (size_t)(m - 1) * L;
      ag::parallel_for(mesh_.pool, L, [&, m, off](int i0, int i1) {
        auto lane = open_check_.lane(run);
        for (int i = i0; i < i1; ++i) {
          const size_t j = off + (size_t)i;
          if constexpr (OpenCheck::kPerPeerOperands) {
            for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
              if (sent) lane.sent(peer, (int64_t)j, merge_diff_mac(rows, bk, m, i, peer));
              if (expected)
                lane.expected(peer, (int64_t)j, merge_diff_key(rows, bk, m, i, peer), d_[peer][j]);
            }
          } else {
            block s = zero_block;
            for (int peer = 1; peer <= nP; ++peer) if (peer != party_)
              s = s ^ merge_diff_mac(rows, bk, m, i, peer) ^ merge_diff_key(rows, bk, m, i, peer);
            lane.put((int64_t)j, open_check_.residual(d_[party_][j] ^ d_[0][j], s));
          }
        }
        open_check_.merge(lane);
      });
    }
  }
};

// The factory for LeakyAndPrep (AGMPCSession's constructor takes one): the default, with
// kLeakyAndPrepId. It runs the open checker the session's options choose
// (AndPrepContext::open_check), which the session binds into its id.
template <int nP>
AndPrepFactory<nP> leaky_and_prep() {
  return {std::string(kLeakyAndPrepId),
          [](const AndPrepContext<nP> &c) -> std::unique_ptr<AndPrep<nP>> {
            if (open_check_pairwise(c.open_check, nP))
              return std::make_unique<LeakyAndPrep<nP, PairwiseOpenCheck<nP>>>(c);
            return std::make_unique<LeakyAndPrep<nP, SymmetricOpenCheck<nP>>>(c);
          },
          [](int64_t n, int ssp) { return LeakyAndPrep<nP>::draws(n, ssp); }};
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_TRIPLE_LEAKY_AND_PREP_H__
