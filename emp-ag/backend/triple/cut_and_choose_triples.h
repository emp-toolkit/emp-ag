#ifndef EMP_AG_BACKEND_TRIPLE_CUT_AND_CHOOSE_TRIPLES_H__
#define EMP_AG_BACKEND_TRIPLE_CUT_AND_CHOOSE_TRIPLES_H__
//
// Authenticated random AND triples by cut-and-choose: the TinyOT triple pipeline of FKOS15
// (ePrint 2015/901, Fig. 15 and 23) on BDOZ aShares, for large batches over cheap COTs. A
// batch of ell outputs:
//   1. draws 3 * pop random aShares a, b, r and finishes the COT consistency check;
//   2. multiplies: for each ordered pair (s, r), s sends one bit per candidate,
//        LSB H(K, g) ^ LSB H(K ^ Delta_s, g) ^ b_s,
//      K its key on r's share of a and g the candidate's tweak, and r adds
//      LSB H(M, g) ^ a_r * bit, M its MAC on that share; with the local a_i * b_i these
//      are XOR shares of z = a * b;
//   3. opens z ^ r and sets c = r ^ (z ^ r);
//   4. draws one coin for the cut, the sacrifice and the combine (triple/cut_and_choose_bound.h)
//      and opens every value they need in one round;
//   5. checks every opened value, and every sacrifice residual against its claim, in one
//      open check, whose zero test also agrees on the pending aShare consistency view;
//   6. combines the heads into the ell outputs by bucketing (triple/merge.h).
//
// Where it departs from FKOS15:
//   - H hashes the correlation that authenticates a itself, where FKOS15 hashes a second,
//     fresh half of a doubled correlation (its footnote 4 leaves the reuse unproven). The
//     correction is a one-bit half-gate row with b_s in place of the second operand, the
//     reuse of the half-gate leaky AND (KRRW18, ePrint 2018/578, Fig. 5); it rests on a
//     hash that stays pseudorandom on inputs correlated by Delta (TCCR; the leakage-aware
//     form is the S-TCCRL notion of ePrint 2025/1818) and on a distinct tweak per hashed
//     pair: here a MITCCRH stream per ordered pair, each gid used once. Hashing the
//     authenticating correlation also binds the hashed choice bit to the authenticated
//     one: from M = K ^ a * Delta a receiver cannot form its share of a' * b_s for a' != a
//     without b_s, so a corrupt receiver adds only an error independent of b, a corrupt
//     sender only a_r * e, and only a can leak. (A second COT stream derandomized to a
//     would not bind it: a corrupt receiver could flip its hashed bit and make the error
//     b_s, which the combine does not hide.)
//   - z is authenticated by opening z ^ r against a random authenticated r: a wrong share is
//     an additive error on c, which the cut and the sacrifice catch.
//   - Rotation bucketing instead of random permutations, and BDOZ MACs checked by emp-ag's
//     open check (ashare/open_check.h) instead of the SPDZ MAC check.
//
// Openings go through kings at nP > 2 with the symmetric check: every party sends a value's
// king its share, and the king sends everyone the XOR, 2(n-1) bits per value instead of
// n(n-1). The symmetric check needs only the opened value at each party, and a king that
// sends different parties different values leaves each of them a residual that is a
// multiple of its own Delta, which no coalition cancels. The pairwise check needs every
// share, so with it values are opened all to all, and a sacrifice residual, never opened
// otherwise, has its shares exchanged at nP > 2.
//
// z ^ r is opened without an echo: each party digests the opened vector, and the batch
// aborts unless every party saw the same one (the symmetric check carries the digests with
// its zero test's commitments; with the pairwise check at nP > 2 they are exchanged). At
// nP == 2 there is no second honest view.
//
// Outputs are banked: take(n) serves n triples, generating batches of `batch` outputs as
// the bank runs dry. Batch i of the session is held to 2^-ssp / (i (i + 1)), or, when the
// session declares how many batches it will run, each to 2^-ssp / batches, and a batch
// beyond the declared count is refused. A batch keeps the MAC and key of all 3 pop
// candidates toward every peer until its outputs are built, 32 (nP - 1) bytes per aShare,
// and pop is about B T times the batch.
//
// CutAndChoosePrep (below) computes the AND gates' products from the bank
// (triple/and_prep.h): it takes a triple per gate, draws the call's coin, and runs Beaver
// (triple/beaver.h).
//
#include "emp-ag/backend/triple/cut_and_choose_bound.h"
#include "emp-ag/backend/triple/merge.h"            // the combine
#include "emp-ag/backend/common/feq.h"          // fs_coin_pair_group
#include "emp-ag/backend/common/fs_hash.h"
#include "emp-ag/backend/ashare/open_check.h"
#include "emp-ag/backend/common/protocols.h"    // sampleRandom
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/ashare/ashare_gen.h"
#include "emp-ag/backend/triple/and_prep.h"
#include "emp-ag/backend/triple/beaver.h"
#include "emp-ag/backend/common/lane_mesh.h"
#include "emp-ag/backend/common/runtime.h"             // parallel_for
#include "emp-tool/runtime/crypto/mitccrh.h"
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <utility>
#include <vector>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

template <int nP, class OpenCheck = DefaultOpenCheck<nP>>
class CutAndChooseTriples : public TripleBank<nP> {
public:
  // Opens through kings (else all to all).
  static constexpr bool kKings = nP > 2 && !OpenCheck::kPerPeerOperands;

  // `abit` mints the candidates; its Delta is the triples' Delta. All parties construct
  // the generator with the same ssp, batch and declared batch count (`batches`, 0 for the
  // per-batch schedule) and call take() at the same points.
  CutAndChooseTriples(NetIOMP<nP> *io, ThreadPool *pool, int party, AShareSource<nP> &abit,
                      block session_id, int ssp, int64_t batch,
                      NetIOMPGroup<nP> *grp = nullptr, int64_t batches = 0)
      : io_(io), pool_(pool), party_(party), abit_(abit), Delta_(abit.delta()),
        sid_(RO("emp-ag:cut-and-choose", session_id).squeeze_block()),
        ssp_(checked_statistical_security(ssp)), batch_(batch), declared_(batches), grp_(grp),
        check_(make_check_(io, pool, party, abit.delta(), sid_, &prg_, grp)) {
    expecting(batch >= 1, "cut-and-choose: batch must be positive");
    expecting(batches >= 0, "cut-and-choose: a negative declared batch count");
  }

  CutAndChooseTriples(const CutAndChooseTriples &) = delete;
  CutAndChooseTriples &operator=(const CutAndChooseTriples &) = delete;

  // Write n triples into mac[peer] and key[peer], resized to 3n: a at [0, n), b at [n, 2n),
  // c at [2n, 3n), this party's share in bit 0 of its MACs, as AShareGen's aShares.
  void take(int64_t n, BlockVec mac[nP + 1], BlockVec key[nP + 1]) override {
    expecting(n >= 0, "cut-and-choose: negative count");
    for (int p = 1; p <= nP; ++p) if (p != party_) {
      mac[p].resize((size_t)(3 * n));
      key[p].resize((size_t)(3 * n));
    }
    int64_t filled = 0;
    while (filled < n) {
      if (bank_pos_ == bank_ell_) generate_(batch_);
      const int64_t k = std::min(n - filled, bank_ell_ - bank_pos_);
      for (int p = 1; p <= nP; ++p) if (p != party_)
        for (int r = 0; r < 3; ++r) {
          memcpy(mac[p].data() + r * n + filled, bank_mac_[p].data() + r * bank_ell_ + bank_pos_,
                 (size_t)k * sizeof(block));
          memcpy(key[p].data() + r * n + filled, bank_key_[p].data() + r * bank_ell_ + bank_pos_,
                 (size_t)k * sizeof(block));
        }
      filled += k;
      bank_pos_ += k;
    }
  }

  // The share draws a fresh bank makes to serve its first n triples at statistical
  // security ssp: 3 pop for each batch generate_() runs, batch i at its own target (all at
  // the declared target when `batches` > 0).
  static std::vector<int64_t> draws(int64_t n, int ssp, int64_t batch, int64_t batches = 0) {
    expecting(n >= 0 && batch >= 1, "cut-and-choose: negative count or non-positive batch");
    expecting(batches >= 0, "cut-and-choose: a negative declared batch count");
    const int s = checked_statistical_security(ssp);
    std::vector<int64_t> out;
    for (int64_t i = 1, banked = 0; banked < n; ++i, banked += batch) {
      expecting(batches == 0 || i <= batches, "cut-and-choose: more batches than declared");
      out.push_back(3 * cut_and_choose_params(batch, target_(s, i, batches)).pop);
    }
    return out;
  }

  // The parameters of the last batch, and totals over the session's batches.
  const CutAndChooseParams &last_params() const { return params_; }
  int64_t batches() const { return batches_; }
  int64_t candidates() const { return candidates_; }
  int64_t outputs() const { return outputs_; }

private:
  // Candidates per MITCCRH stream: (pair seed, direction, chunk) keys a stream, so chunks
  // hash in parallel. A public constant: both ends of a pair must cut the same chunks.
  static constexpr int64_t kStreamChunk = int64_t(1) << 14;

  NetIOMP<nP> *io_;
  ThreadPool *pool_;
  int party_;
  AShareSource<nP> &abit_;
  block Delta_;
  PRG prg_;
  block sid_;
  int ssp_;
  int64_t batch_;
  int64_t declared_;   // the declared batch count, 0 for the per-batch schedule
  NetIOMPGroup<nP> *grp_;
  OpenCheck check_;
  CutAndChooseParams params_;
  int64_t batches_ = 0, candidates_ = 0, outputs_ = 0;
  // The bank: bank_ell_ triples, a|b|c at stride bank_ell_; [bank_pos_, bank_ell_) unused.
  BlockVec bank_mac_[nP + 1], bank_key_[nP + 1];
  int64_t bank_ell_ = 0, bank_pos_ = 0;

  static double target_(int ssp, int64_t batch, int64_t batches) {
    return batches > 0 ? cut_and_choose_declared_target(ssp, batches)
                       : cut_and_choose_batch_target(ssp, batch);
  }

  static OpenCheck make_check_(NetIOMP<nP> *io, ThreadPool *pool, int party, block Delta,
                               block sid, PRG *prg, NetIOMPGroup<nP> *grp) {
    if constexpr (std::is_same_v<OpenCheck, SymmetricOpenCheck<nP>>)
      return OpenCheck(io, pool, party, Delta, sid, prg, grp, "emp-ag:cut-and-choose",
                       "cut-and-choose: opened values do not match their MACs",
                       "cut-and-choose: commit-open mismatch",
                       "cut-and-choose: parties saw different values opened without an echo");
    else   // the bank's sid is its own, so it keeps the default purpose
      return OpenCheck(io, pool, party, Delta, sid, prg, grp, "emp-ag:open-check",
                       "cut-and-choose: MAC tag mismatch");
  }

  // A uniform k-subset of [0, n), ascending (Floyd's algorithm).
  static std::vector<int64_t> uniform_subset_(PRG &prg, int64_t n, int64_t k) {
    std::vector<int64_t> out;
    out.reserve((size_t)k);
    for (int64_t j = n - k; j < n; ++j) {
      const int64_t x = uniform_index(prg, j + 1);
      out.push_back(std::find(out.begin(), out.end(), x) == out.end() ? x : j);
    }
    std::sort(out.begin(), out.end());
    return out;
  }

  // One send task and one receive task per peer, peer-major, send before receive.
  template <class Send, class Recv>
  void exchange_(Send &&send, Recv &&recv) {
    vector<future<void>> res;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
      res.push_back(pool_->enqueue([&send, this, peer]() {
        send(peer);
        io_->flush(peer);
      }));
      res.push_back(pool_->enqueue([&recv, peer]() { recv(peer); }));
    }
    joinNclean(res);
  }

  // The first value king p opens out of n: king p opens [first(p), first(p + 1)).
  static int64_t king_first_(int64_t n, int p) { return n * (p - 1) / nP; }

  // Open n bits, mine[v] this party's share of value v, into out[v] = the XOR of every
  // party's share. Through kings when kKings; else all to all, and by_peer (if given)
  // receives each peer's shares. `split` (TEST-ONLY hooks): party 2 sends party 3 a
  // different opening of the first value it sends there.
  void open_(const uint8_t *mine, int64_t n, uint8_t *out, std::vector<uint8_t> *by_peer,
             [[maybe_unused]] bool split = false) {
    if (n == 0) return;
    if constexpr (kKings) {
      const int64_t lo = king_first_(n, party_), hi = king_first_(n, party_ + 1);
      std::vector<uint8_t> in[nP + 1];
      for (int p = 1; p <= nP; ++p) if (p != party_) in[p].resize((size_t)(hi - lo));
      exchange_(
          [&](int peer) {
            const int64_t a = king_first_(n, peer), b = king_first_(n, peer + 1);
            io_->send_bool(peer, (const bool *)(mine + a), b - a);
          },
          [&](int peer) { io_->recv_bool(peer, (bool *)in[peer].data(), hi - lo); });
      for (int64_t v = lo; v < hi; ++v) {
        uint8_t x = mine[v];
        for (int p = 1; p <= nP; ++p) if (p != party_) x ^= in[p][(size_t)(v - lo)];
        out[v] = x;
      }
      std::vector<uint8_t> flipped;
      if constexpr (kTestHooks) {
        // TEST-ONLY (split, from hooks cnc_split_zr / cnc_king_split): as a king, party 2
        // sends party 3 a different opening of its first value than it sends everyone else.
        if (split && party_ == 2 && hi > lo) {
          flipped.assign(out + lo, out + hi);
          flipped[0] ^= 1;
        }
      }
      exchange_(
          [&](int peer) {
            const uint8_t *src = (peer == 3 && !flipped.empty()) ? flipped.data() : out + lo;
            io_->send_bool(peer, (const bool *)src, hi - lo);
          },
          [&](int peer) {
            const int64_t a = king_first_(n, peer), b = king_first_(n, peer + 1);
            io_->recv_bool(peer, (bool *)(out + a), b - a);
          });
    } else {
      std::vector<uint8_t> local[nP + 1];
      std::vector<uint8_t> *got = by_peer != nullptr ? by_peer : local;
      for (int p = 1; p <= nP; ++p) if (p != party_) got[p].resize((size_t)n);
      std::vector<uint8_t> flipped;
      if constexpr (kTestHooks) {
        if (split && party_ == 2 && nP >= 3) {
          flipped.assign(mine, mine + n);
          flipped[0] ^= 1;
        }
      }
      exchange_(
          [&](int peer) {
            const uint8_t *src = (peer == 3 && !flipped.empty()) ? flipped.data() : mine;
            io_->send_bool(peer, (const bool *)src, n);
          },
          [&](int peer) { io_->recv_bool(peer, (bool *)got[peer].data(), n); });
      parallel_for(pool_, (int)n, [&](int a, int b) {
        for (int v = a; v < b; ++v) {
          uint8_t x = mine[v];
          for (int p = 1; p <= nP; ++p) if (p != party_) x ^= got[p][(size_t)v];
          out[v] = x;
        }
      });
    }
  }

  // Every party must hold the same digest; exchanged directly (the pairwise check's
  // substitute for carrying it with a zero test).
  void agree_directly_(const char *view) {
    char got[nP + 1][FsHash::DIGEST_SIZE];
    exchange_([&](int peer) { io_->send_data(peer, view, FsHash::DIGEST_SIZE); },
              [&](int peer) { io_->recv_data(peer, got[peer], FsHash::DIGEST_SIZE); });
    for (int p = 1; p <= nP; ++p) if (p != party_)
      expecting(memcmp(got[p], view, FsHash::DIGEST_SIZE) == 0,
                "cut-and-choose: parties saw different values opened without an echo");
  }

  // This party's share of every candidate's z = a * b, XORed with its share of r.
  std::vector<uint8_t> masked_products_(BlockVec mac[nP + 1], BlockVec key[nP + 1],
                                        const std::vector<uint8_t> &bit, int64_t pop) {
    // One stream start per pair: a Fiat-Shamir coin over the pair's transcripts, now that
    // every candidate is fixed. The direction and the chunk ride the key's free low qword.
    block seed[nP + 1];
    for (int p = 1; p <= nP; ++p) if (p != party_)
      seed[p] = fs_coin_pair_group<nP>(io_, grp_, p, "emp-ag:cut-and-choose:product", sid_);
    std::vector<uint8_t> u_out[nP + 1], u_in[nP + 1], part[nP + 1];
    for (int p = 1; p <= nP; ++p) if (p != party_) {
      u_out[p].resize((size_t)pop);
      u_in[p].resize((size_t)pop);
      part[p].resize((size_t)pop);
    }
    const int64_t chunks = (pop + kStreamChunk - 1) / kStreamChunk;
    vector<future<void>> res;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_)
      for (int64_t c = 0; c < chunks; ++c)
        res.push_back(pool_->enqueue([&, peer, c]() {
          // Ordered pair (s, r) is direction 0 when s < r.
          const uint64_t to_peer = party_ < peer ? 0 : 1, from_peer = peer < party_ ? 0 : 1;
          MITCCRH<> hs, hr;
          hs.setS(seed[peer] ^ makeBlock(0, ((uint64_t)c << 1) | to_peer));
          hr.setS(seed[peer] ^ makeBlock(0, ((uint64_t)c << 1) | from_peer));
          const block *K = key[peer].data(), *M = mac[peer].data();   // a: [0, pop)
          const int64_t lo = c * kStreamChunk, hi = std::min(lo + kStreamChunk, pop);
          block pk[16], pm[8];
          for (int64_t g = lo; g < hi; g += 8) {
            const int n = (int)std::min<int64_t>(8, hi - g);
            for (int j = 0; j < 8; ++j) {
              pk[2 * j] = j < n ? K[g + j] : zero_block;
              pk[2 * j + 1] = j < n ? (K[g + j] ^ Delta_) : zero_block;
              pm[j] = j < n ? M[g + j] : zero_block;
            }
            hs.hash_cir<8, 2>(pk);   // as sender: H(K), H(K ^ Delta)
            hr.hash_cir<8, 1>(pm);   // as receiver: H(M) under the peer's same gid
            for (int j = 0; j < n; ++j) {
              const int64_t q = g + j;
              const uint8_t v0 = (uint8_t)getLSB(pk[2 * j]);
              u_out[peer][(size_t)q] = v0 ^ (uint8_t)getLSB(pk[2 * j + 1]) ^ bit[(size_t)(pop + q)];
              part[peer][(size_t)q] = v0 ^ (uint8_t)getLSB(pm[j]);
            }
          }
          if constexpr (kTestHooks) {
            // TEST-ONLY (hook cnc_flip_product): party 2 flips every product correction it
            // sends party 1, a selective failure on party 1's shares of a.
            if (hooks().cnc_flip_product && party_ == 2 && peer == 1)
              for (int64_t q = lo; q < hi; ++q) u_out[peer][(size_t)q] ^= 1;
          }
        }));
    joinNclean(res);
    exchange_([&](int peer) { io_->send_bool(peer, (const bool *)u_out[peer].data(), pop); },
              [&](int peer) { io_->recv_bool(peer, (bool *)u_in[peer].data(), pop); });
    std::vector<uint8_t> zr((size_t)pop);
    // TEST-ONLY (hook cnc_flip_receiver): as party 1's receiver, party 2 takes every
    // correction under the other choice bit, a ^ 1. Read once, outside the loop.
    [[maybe_unused]] bool flip_receiver = false;
    if constexpr (kTestHooks) flip_receiver = hooks().cnc_flip_receiver && party_ == 2;
    parallel_for(pool_, (int)pop, [&](int lo, int hi) {
      for (int q = lo; q < hi; ++q) {
        const uint8_t a = bit[(size_t)q];
        uint8_t z = a & bit[(size_t)(pop + q)];
        for (int p = 1; p <= nP; ++p) if (p != party_)
          z ^= part[p][(size_t)q] ^ (a & u_in[p][(size_t)q]);
        if constexpr (kTestHooks)
          if (flip_receiver) z ^= u_in[1][(size_t)q];
        zr[(size_t)q] = z ^ bit[(size_t)(2 * pop + q)];
      }
    });
    return zr;
  }

  void generate_(int64_t ell) {
    ++batches_;
    expecting(declared_ == 0 || batches_ <= declared_, "cut-and-choose: more batches than declared");
    const CutAndChooseParams P = cut_and_choose_params(ell, target_(ssp_, batches_, declared_));
    expecting(P.pop > 0, "cut-and-choose: no parameters meet the batch's statistical target");
    expecting(3 * P.pop <= (int64_t)INT_MAX, "cut-and-choose: batch too large for one draw");
    params_ = P;
    candidates_ += P.pop;
    outputs_ += ell;
    const int64_t pop = P.pop, t = P.t, body = P.t * P.T;
    const int T = P.T, B = P.B;
    const int any_peer = (party_ == 1) ? 2 : 1;

    // 1. The candidates: a at [0, pop), b at [pop, 2 pop), r at [2 pop, 3 pop). The COT
    //    check completes before anything is hashed or opened. Their check2 waits for the
    //    coin of step 4; until then they change only by step 3's public corrections.
    BlockVec mac[nP + 1], key[nP + 1];
    abit_.compute_deferred(mac, key, (int)(3 * pop));
    abit_.maybe_flush_cot_check();
    std::vector<uint8_t> bit((size_t)(3 * pop));
    parallel_for(pool_, (int)(3 * pop), [&](int lo, int hi) {
      for (int e = lo; e < hi; ++e) bit[(size_t)e] = (uint8_t)getLSB(mac[any_peer][(size_t)e]);
    });

    // 2-3. Products, then c = r ^ (z ^ r): party 1 moves its share, everyone else its key
    //      on party 1's share.
    std::vector<uint8_t> zr = masked_products_(mac, key, bit, pop);
    [[maybe_unused]] bool split_zr = false;
    if constexpr (kTestHooks) {
      // TEST-ONLY (hook cnc_flip_zr): party 2 flips its share of candidate 0's z ^ r and
      // sends it to everyone, so every party holds the same wrong c.
      if (hooks().cnc_flip_zr && party_ == 2) zr[0] ^= 1;
      // TEST-ONLY (hook cnc_flip_all_zr): party 2 flips its share of every candidate's
      // z ^ r. Every candidate is then wrong in the same way, which every sacrifice passes:
      // only the cut catches it.
      if (hooks().cnc_flip_all_zr && party_ == 2)
        for (int64_t q = 0; q < pop; ++q) zr[(size_t)q] ^= 1;
      // TEST-ONLY (hook cnc_split_zr): open_'s split, on the opening of z ^ r.
      split_zr = hooks().cnc_split_zr;
    }
    std::vector<uint8_t> zr_open((size_t)pop);
    open_(zr.data(), pop, zr_open.data(), nullptr, split_zr);
    char zr_view[FsHash::DIGEST_SIZE];
    FsHash::hash_once(zr_view, zr_open.data(), zr_open.size());
    parallel_for(pool_, (int)pop, [&](int lo, int hi) {
      for (int q = lo; q < hi; ++q) {
        if (!zr_open[(size_t)q]) continue;
        const size_t e = (size_t)(2 * pop + q);
        if (party_ == 1) bit[e] ^= 1;   // party 1's own copy of its share
        add_public_one<nP>(party_, Delta_, [&](int p) -> block & { return mac[p][e]; },
                           [&](int p) -> block & { return key[p][e]; });
      }
    });

    // 4. One coin: check2 of every draw before it (these candidates, and the masks of a
    //    draw walk waiting for its triples), then the cut, then the sacrifice shifts, then
    //    the combine shifts. check2 folds before the cut moves any candidate.
    const block coin = sampleRandom<nP>(
        io_, &prg_, pool_, party_,
        RO("emp-ag:cut-and-choose:coin", sid_).absorb((uint64_t)batches_).squeeze_block());
    abit_.fold_check2(coin);
    PRG cp(&coin);
    const std::vector<int64_t> subset = uniform_subset_(cp, pop, P.cut);
    std::vector<int64_t> s((size_t)T, 0);
    for (int k = 1; k < T; ++k) s[(size_t)k] = uniform_index(cp, t);
    const Buckets bk = draw_buckets(cp, B, ell);
    // Move the cut to the tail [body, pop), so sacrifice group k is [k t, (k + 1) t).
    for (const auto &[q, w] : cut_and_choose_tail_swaps(pop, body, subset))
      for (int r = 0; r < 3; ++r) {
        const size_t e = (size_t)(r * pop + q), f = (size_t)(r * pop + w);
        std::swap(bit[e], bit[f]);
        for (int p = 1; p <= nP; ++p) if (p != party_) {
          std::swap(mac[p][e], mac[p][f]);
          std::swap(key[p][e], key[p][f]);
        }
      }
    auto partner = [&](int64_t h, int k) {
      const int64_t q = h + s[(size_t)k];
      return k * t + (q < t ? q : q - t);
    };
    // Combine member m of output j: row m of the merge (triple/merge.h) is group m of the
    // heads, [m ell, (m + 1) ell).
    auto head = [&](int64_t j, int m) { return m * ell + bk.member(m, j); };

    // The values opened: the cut's a, b, c; each sacrifice pair's a_h ^ a_k and b_h ^ b_k;
    // the combine's differences b_head ^ b_member, row-major as merge.h orders them. Value v
    // is entry e0, XOR entry e1 if e1 >= 0.
    const int64_t n_cut = 3 * P.cut, n_sac = 2 * t * (T - 1), n_cmb = ell * (B - 1);
    const int64_t n_open = n_cut + n_sac + n_cmb, n_res = t * (T - 1);
    auto entries = [&](int64_t v) -> std::pair<int64_t, int64_t> {
      if (v < n_cut) return {(v % 3) * pop + body + v / 3, -1};
      v -= n_cut;
      if (v < n_sac) {
        const int64_t pr = v / 2, h = pr / (T - 1), off = (v % 2) * pop;
        return {off + h, off + partner(h, (int)(pr % (T - 1)) + 1)};
      }
      v -= n_sac;
      const int m = (int)(v / ell) + 1;
      const int64_t j = v % ell;
      return {pop + head(j, 0), pop + head(j, m)};
    };
    std::vector<uint8_t> mine((size_t)n_open), opened((size_t)n_open);
    parallel_for(pool_, (int)n_open, [&](int lo, int hi) {
      for (int v = lo; v < hi; ++v) {
        const auto [e0, e1] = entries(v);
        mine[(size_t)v] = bit[(size_t)e0] ^ (e1 >= 0 ? bit[(size_t)e1] : 0);
      }
    });
    [[maybe_unused]] bool king_split = false;
    if constexpr (kTestHooks) {
      // TEST-ONLY (hook cnc_flip_open): party 2 flips its share of the first sacrifice
      // difference and sends it to everyone.
      if (hooks().cnc_flip_open && party_ == 2) mine[(size_t)n_cut] ^= 1;
      // TEST-ONLY (hook cnc_king_split): open_'s split, on the cut and sacrifice openings.
      king_split = hooks().cnc_king_split;
    }
    std::vector<uint8_t> shares[nP + 1];   // all to all: what each peer sent
    open_(mine.data(), n_open, opened.data(), shares, king_split);

    // Sacrifice residual pr (pair h, k): L = c_h ^ c_k ^ rho b_k ^ sigma a_k, which a
    // correct pair, or a pair with equal errors, opens to rho sigma.
    auto rho = [&](int64_t pr) { return opened[(size_t)(n_cut + 2 * pr)]; };
    auto sigma = [&](int64_t pr) { return opened[(size_t)(n_cut + 2 * pr + 1)]; };
    auto res_comb = [&](const block *x, int64_t h, int64_t q, uint8_t r, uint8_t g) {
      block o = x[2 * pop + h] ^ x[2 * pop + q];
      if (r) o = o ^ x[pop + q];
      if (g) o = o ^ x[q];
      return o;
    };
    auto res_bit = [&](int64_t pr) {
      const int64_t h = pr / (T - 1), q = partner(h, (int)(pr % (T - 1)) + 1);
      return (uint8_t)(bit[(size_t)(2 * pop + h)] ^ bit[(size_t)(2 * pop + q)] ^
                       (rho(pr) & bit[(size_t)(pop + q)]) ^ (sigma(pr) & bit[(size_t)q]));
    };
    // With the pairwise check at nP > 2 the residuals' shares are exchanged, so that each
    // peer's can be checked against its MACs, and their XOR must be the claim.
    std::vector<uint8_t> res_shares[nP + 1];
    bool res_sums_ok = true;
    if constexpr (OpenCheck::kPerPeerOperands && nP > 2) {
      std::vector<uint8_t> own((size_t)n_res), sum((size_t)n_res);
      parallel_for(pool_, (int)n_res, [&](int lo, int hi) {
        for (int pr = lo; pr < hi; ++pr) own[(size_t)pr] = res_bit(pr);
      });
      if constexpr (kTestHooks) {
        // TEST-ONLY (hook cnc_flip_residual): party 2 sends everyone a wrong share of the
        // first sacrifice residual.
        if (hooks().cnc_flip_residual && party_ == 2) own[0] ^= 1;
      }
      open_(own.data(), n_res, sum.data(), res_shares);
      for (int64_t pr = 0; pr < n_res; ++pr)
        res_sums_ok = res_sums_ok && sum[(size_t)pr] == (rho(pr) & sigma(pr));
      agree_directly_(zr_view);
    }

    // 5. One open check over the opened values and the residuals.
    const auto run_open = check_.begin(n_open);
    const auto run_res = check_.begin(n_res);
    check_.seal();
    if constexpr (OpenCheck::kAgreesViews) {
      const auto pending = abit_.take_pending_check2();
      if (pending.any) check_.agree(pending.view);
      if constexpr (nP > 2) check_.agree(zr_view);
    }
    parallel_for(pool_, (int)n_open, [&](int lo, int hi) {
      auto lane = check_.lane(run_open);
      for (int v = lo; v < hi; ++v) {
        const auto [e0, e1] = entries(v);
        if constexpr (OpenCheck::kPerPeerOperands) {
          for (int p = 1; p <= nP; ++p) if (p != party_) {
            block m = mac[p][(size_t)e0], k = key[p][(size_t)e0];
            if (e1 >= 0) {
              m = m ^ mac[p][(size_t)e1];
              k = k ^ key[p][(size_t)e1];
            }
            lane.sent(p, v, m);
            lane.expected(p, v, k, shares[p][(size_t)v]);
          }
        } else {
          block sum = zero_block;
          for (int p = 1; p <= nP; ++p) if (p != party_) {
            sum = sum ^ mac[p][(size_t)e0] ^ key[p][(size_t)e0];
            if (e1 >= 0) sum = sum ^ mac[p][(size_t)e1] ^ key[p][(size_t)e1];
          }
          lane.put(v, check_.residual(mine[(size_t)v] ^ opened[(size_t)v], sum));
        }
      }
      check_.merge(lane);
    });
    parallel_for(pool_, (int)n_res, [&](int lo, int hi) {
      auto lane = check_.lane(run_res);
      for (int pr = lo; pr < hi; ++pr) {
        const int64_t h = pr / (T - 1), q = partner(h, (int)(pr % (T - 1)) + 1);
        const uint8_t r = rho(pr), g = sigma(pr), own = res_bit(pr), claim = r & g;
        if constexpr (OpenCheck::kPerPeerOperands) {
          for (int p = 1; p <= nP; ++p) if (p != party_) {
            lane.sent(p, pr, res_comb(mac[p].data(), h, q, r, g));
            // At nP == 2 the peer's share is the claim XOR this party's.
            const uint8_t theirs = (nP == 2) ? (uint8_t)(own ^ claim) : res_shares[p][(size_t)pr];
            lane.expected(p, pr, res_comb(key[p].data(), h, q, r, g), theirs);
          }
        } else {
          block sum = zero_block;
          for (int p = 1; p <= nP; ++p) if (p != party_)
            sum = sum ^ res_comb(mac[p].data(), h, q, r, g) ^ res_comb(key[p].data(), h, q, r, g);
          lane.put(pr, check_.residual(own ^ claim, sum));
        }
      }
      check_.merge(lane);
    });
    check_.check_result();
    if constexpr (!OpenCheck::kAgreesViews) abit_.settle_check2();
    // The public checks, on values the open check has now authenticated (so which check
    // fails says nothing about the shares behind a forged opening).
    expecting(res_sums_ok, "cut-and-choose: a sacrificed pair does not match");
    for (int64_t i = 0; i < P.cut; ++i)
      expecting((opened[(size_t)(3 * i)] & opened[(size_t)(3 * i + 1)]) == opened[(size_t)(3 * i + 2)],
                "cut-and-choose: a cut triple is incorrect");

    // 6. The combine (triple/merge.h): output j merges head j of group 0 with its members
    //    in groups 1..B-1, in place into group 0, which is then banked.
    std::vector<TripleRow<nP>> rows((size_t)B);
    for (int m = 0; m < B; ++m) rows[(size_t)m] = strided_row<nP>(mac, key, m * ell, pop, party_);
    merge_combine(rows, bk, opened.data() + n_cut + n_sac, party_, pool_);
    for (int p = 1; p <= nP; ++p) if (p != party_) {
      bank_mac_[p].resize((size_t)(3 * ell));
      bank_key_[p].resize((size_t)(3 * ell));
      for (int r = 0; r < 3; ++r) {
        memcpy(bank_mac_[p].data() + (size_t)r * ell, mac[p].data() + (size_t)r * pop,
               (size_t)ell * sizeof(block));
        memcpy(bank_key_[p].data() + (size_t)r * ell, key[p].data() + (size_t)r * pop,
               (size_t)ell * sizeof(block));
      }
    }
    bank_ell_ = ell;
    bank_pos_ = 0;
  }
};

// The AND gates' products from cut-and-choose triples (triple/and_prep.h). Per call: take
// one banked triple per gate, draw the call's coin (Fiat-Shamir at nP == 2,
// commit-then-open at nP > 2) and fold at it the consistency check of the shares drawn
// since the last call (a no-op when a batch generated in take() folded them at its own
// coin), then Beaver (triple/beaver.h). Every banked triple was checked before it was
// banked, and none is served twice.
template <int nP, class OpenCheck = DefaultOpenCheck<nP>>
class CutAndChoosePrep : public AndPrep<nP> {
public:
  // Triples generated `batch` at a time, over `batches` declared batches (0: the
  // per-batch schedule; CutAndChooseTriples).
  CutAndChoosePrep(const AndPrepContext<nP> &ctx, int64_t batch, int64_t batches = 0)
      : mesh_(ctx.io, ctx.grp, ctx.pool, ctx.party), party_(ctx.party),
        sid_(ctx.session_id), abit_(*ctx.abit), Delta_(abit_.delta()),
        check_(ctx.io, ctx.pool, ctx.party, Delta_, ctx.session_id, &prg_, ctx.grp),
        bank_(ctx.io, ctx.pool, ctx.party, abit_, ctx.session_id,
              checked_statistical_security(ctx.ssp), batch, ctx.grp, batches),
        beaver_(mesh_, Delta_) {}

  void validate(int64_t n) override {
    expecting(n >= 0, "cut-and-choose: negative batch length");
    expecting(3 * n <= (int64_t)INT_MAX, "cut-and-choose: chunk too large -- split into chunks");
  }

  AndInputs<nP> inputs(int64_t n) override { return beaver_.inputs((int)n); }

  block run(int64_t n, AShareBundleVec<nP> &out) override {
    validate(n);
    out.clear();
    if (n == 0) return zero_block;
    const int L = (int)n;
    bank_.take(n, mac_, key_);
    const int any_peer = (party_ == 1) ? 2 : 1;
    block coin;
    if constexpr (nP == 2)
      coin = fs_coin_pair_group<nP>(mesh_.io, mesh_.grp, any_peer, "AGMPC halfgate coin", sid_);
    else
      coin = sampleRandom<nP>(mesh_.io, &prg_, mesh_.pool, party_, sid_);
    abit_.fold_check2(coin);
    const TripleRow<nP> t = strided_row<nP>(mac_, key_, 0, L, party_);
    const auto runs = beaver_.begin(check_, 0, L);
    beaver_.open(check_, runs, t, L);
    beaver_.finish(check_, abit_, runs, t, L, [](const typename OpenCheck::Run &) {}, out);
    return coin;
  }

  // The bank's parameters and totals (CutAndChooseTriples).
  const CutAndChooseTriples<nP, OpenCheck> &bank() const { return bank_; }
  // The bank itself, for the session's other users of triples.
  TripleBank<nP> *triples() override { return &bank_; }

private:
  LaneMesh<nP> mesh_;
  int party_;
  block sid_;
  AShareSource<nP> &abit_;   // the session's share pool; its owner outlives this
  block Delta_;
  PRG prg_;
  OpenCheck check_;          // checks x and y against their MACs
  CutAndChooseTriples<nP, OpenCheck> bank_;
  Beaver<nP, OpenCheck> beaver_;
  BlockVec mac_[nP + 1], key_[nP + 1];   // the call's triples, a | b | c
};

// The factory for CutAndChoosePrep with batches of `batch`, and `batches` of them declared
// up front (0: the per-batch schedule), which AGMPCSession's constructor takes. Its id
// carries the batch and a declared count, since the triples served depend on them. A call
// run(n) takes n triples from the bank, so its draws are the bank's. It runs the open
// checker the session's options choose (AndPrepContext::open_check), which the session
// binds into its id.
template <int nP>
AndPrepFactory<nP> cut_and_choose_prep(int64_t batch, int64_t batches = 0) {
  expecting(batch >= 1, "cut-and-choose: batch must be positive");
  expecting(batches >= 0, "cut-and-choose: a negative declared batch count");
  std::string id = "emp-ag:cut-and-choose:" + std::to_string(batch);
  if (batches > 0) id += ":" + std::to_string(batches);
  return {std::move(id),
          [batch, batches](const AndPrepContext<nP> &c) -> std::unique_ptr<AndPrep<nP>> {
            if (open_check_pairwise(c.open_check, nP))
              return std::make_unique<CutAndChoosePrep<nP, PairwiseOpenCheck<nP>>>(c, batch, batches);
            return std::make_unique<CutAndChoosePrep<nP, SymmetricOpenCheck<nP>>>(c, batch, batches);
          },
          [batch, batches](int64_t n, int ssp) {
            return CutAndChooseTriples<nP>::draws(n, ssp, batch, batches);
          }};
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_TRIPLE_CUT_AND_CHOOSE_TRIPLES_H__
