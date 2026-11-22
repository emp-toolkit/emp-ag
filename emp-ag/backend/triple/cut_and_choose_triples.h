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
//      open check, whose zero test also takes the pending aShare consistency residuals;
//   6. builds the ell outputs.
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
// Outputs are banked: take(n), the TripleSource interface (triple/triple_source.h), serves
// n triples, generating batches of `batch` outputs as the bank runs dry. Batch i of the
// session is held to 2^-ssp / (i (i + 1)). A batch keeps the MAC and key of all 3 pop
// candidates toward every peer until its outputs are built, 32 (nP - 1) bytes per aShare,
// and pop is about B T times the batch.
//
#include "emp-ag/backend/triple/cut_and_choose_bound.h"
#include "emp-ag/backend/common/feq.h"          // fs_coin_pair_group
#include "emp-ag/backend/common/fs_hash.h"
#include "emp-ag/backend/ashare/open_check.h"
#include "emp-ag/backend/common/protocols.h"    // sampleRandom
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/ashare/ashare_gen.h"
#include "emp-ag/backend/triple/triple_source.h"
#include "emp-ag/backend/common/runtime.h"             // parallel_for
#include "emp-tool/runtime/crypto/mitccrh.h"
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <type_traits>
#include <utility>
#include <vector>

namespace emp::ag {

template <int nP, class OpenCheck = DefaultOpenCheck<nP>>
class CutAndChooseTriples : public TripleSource<nP> {
public:
  // Opens through kings (else all to all).
  static constexpr bool kKings = nP > 2 && !OpenCheck::kPerPeerOperands;

  // `abit` mints the candidates; its Delta is the triples' Delta. All parties construct
  // the generator with the same ssp and batch and call take() at the same points.
  CutAndChooseTriples(NetIOMP<nP> *io, ThreadPool *pool, int party, AShareSource<nP> &abit,
                      block session_id, int ssp, int64_t batch,
                      NetIOMPGroup<nP> *grp = nullptr)
      : io_(io), pool_(pool), party_(party), abit_(abit), Delta_(abit.delta()),
        sid_(RO("emp-ag:cut-and-choose", session_id).squeeze_block()),
        ssp_(checked_statistical_security(ssp)), batch_(batch), grp_(grp),
        check_(make_check_(io, pool, party, abit.delta(), sid_, &prg_, grp)) {
    expecting(batch >= 1, "cut-and-choose: batch must be positive");
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
  NetIOMPGroup<nP> *grp_;
  OpenCheck check_;
  CutAndChooseParams params_;
  int64_t batches_ = 0, candidates_ = 0, outputs_ = 0;
  // The bank: bank_ell_ triples, a|b|c at stride bank_ell_; [bank_pos_, bank_ell_) unused.
  BlockVec bank_mac_[nP + 1], bank_key_[nP + 1];
  int64_t bank_ell_ = 0, bank_pos_ = 0;

  static OpenCheck make_check_(NetIOMP<nP> *io, ThreadPool *pool, int party, block Delta,
                               block sid, PRG *prg, NetIOMPGroup<nP> *grp) {
    if constexpr (std::is_same_v<OpenCheck, SymmetricOpenCheck<nP>>)
      return OpenCheck(io, pool, party, Delta, sid, prg, grp, "emp-ag:cut-and-choose",
                       "cut-and-choose: opened values or absorbed shares do not match their MACs",
                       "cut-and-choose: commit-open mismatch",
                       "cut-and-choose: parties saw different values opened without an echo");
    else
      return OpenCheck(io, pool, party, Delta, sid, prg, grp, "cut-and-choose: MAC tag mismatch");
  }

  // An exactly uniform integer in [0, bound), by threshold rejection.
  static int64_t uniform_(PRG &prg, int64_t bound) {
    const uint64_t n = (uint64_t)bound, threshold = (uint64_t(0) - n) % n;
    uint64_t x;
    do {
      unsigned char bytes[8];
      prg.random_data_unaligned(bytes, sizeof(bytes));
      x = 0;
      for (int i = 0; i < 8; ++i) x |= (uint64_t)bytes[i] << (8 * i);
    } while (x < threshold);
    return (int64_t)(x % n);
  }

  // A uniform k-subset of [0, n), ascending (Floyd's algorithm).
  static std::vector<int64_t> uniform_subset_(PRG &prg, int64_t n, int64_t k) {
    std::vector<int64_t> out;
    out.reserve((size_t)k);
    for (int64_t j = n - k; j < n; ++j) {
      const int64_t x = uniform_(prg, j + 1);
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
#if defined(EMP_AG_TEST_CNC_SPLIT_ZR) || defined(EMP_AG_TEST_CNC_KING_SPLIT)
      // TEST-ONLY (never in production): as a king, party 2 sends party 3 a different
      // opening of its first value than it sends everyone else.
      if (split && party_ == 2 && hi > lo) {
        flipped.assign(out + lo, out + hi);
        flipped[0] ^= 1;
      }
#endif
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
#if defined(EMP_AG_TEST_CNC_SPLIT_ZR) || defined(EMP_AG_TEST_CNC_KING_SPLIT)
      if (split && party_ == 2 && nP >= 3) {
        flipped.assign(mine, mine + n);
        flipped[0] ^= 1;
      }
#endif
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
#ifdef EMP_AG_TEST_CNC_FLIP_PRODUCT
          // TEST-ONLY (never in production): party 2 flips every product correction it
          // sends party 1, a selective failure on party 1's shares of a.
          if (party_ == 2 && peer == 1)
            for (int64_t q = lo; q < hi; ++q) u_out[peer][(size_t)q] ^= 1;
#endif
        }));
    joinNclean(res);
    exchange_([&](int peer) { io_->send_bool(peer, (const bool *)u_out[peer].data(), pop); },
              [&](int peer) { io_->recv_bool(peer, (bool *)u_in[peer].data(), pop); });
    std::vector<uint8_t> zr((size_t)pop);
    parallel_for(pool_, (int)pop, [&](int lo, int hi) {
      for (int q = lo; q < hi; ++q) {
        const uint8_t a = bit[(size_t)q];
        uint8_t z = a & bit[(size_t)(pop + q)];
        for (int p = 1; p <= nP; ++p) if (p != party_)
          z ^= part[p][(size_t)q] ^ (a & u_in[p][(size_t)q]);
#ifdef EMP_AG_TEST_CNC_FLIP_RECEIVER
        // TEST-ONLY (never in production): as party 1's receiver, party 2 takes every
        // correction under the other choice bit, a ^ 1.
        if (party_ == 2) z ^= u_in[1][(size_t)q];
#endif
        zr[(size_t)q] = z ^ bit[(size_t)(2 * pop + q)];
      }
    });
    return zr;
  }

  void generate_(int64_t ell) {
    ++batches_;
    const CutAndChooseParams P =
        cut_and_choose_params(ell, cut_and_choose_batch_target(ssp_, batches_));
    expecting(P.pop > 0, "cut-and-choose: no parameters meet the batch's statistical target");
    expecting(3 * P.pop <= (int64_t)INT_MAX, "cut-and-choose: batch too large for one draw");
    params_ = P;
    candidates_ += P.pop;
    outputs_ += ell;
    const int64_t pop = P.pop, t = P.t, body = P.t * P.T;
    const int T = P.T, B = P.B;
    const int any_peer = (party_ == 1) ? 2 : 1;

    // 1. The candidates: a at [0, pop), b at [pop, 2 pop), r at [2 pop, 3 pop). The COT
    //    check completes before anything is hashed or opened.
    BlockVec mac[nP + 1], key[nP + 1];
    abit_.compute(mac, key, (int)(3 * pop));
    abit_.maybe_flush_cot_check();
    std::vector<uint8_t> bit((size_t)(3 * pop));
    parallel_for(pool_, (int)(3 * pop), [&](int lo, int hi) {
      for (int e = lo; e < hi; ++e) bit[(size_t)e] = (uint8_t)getLSB(mac[any_peer][(size_t)e]);
    });

    // 2-3. Products, then c = r ^ (z ^ r): party 1 moves its share, everyone else its key
    //      on party 1's share.
    std::vector<uint8_t> zr = masked_products_(mac, key, bit, pop);
#ifdef EMP_AG_TEST_CNC_FLIP_ZR
    // TEST-ONLY (never in production): party 2 flips its share of candidate 0's z ^ r and
    // sends it to everyone, so every party holds the same wrong c.
    if (party_ == 2) zr[0] ^= 1;
#endif
#ifdef EMP_AG_TEST_CNC_FLIP_ALL_ZR
    // TEST-ONLY (never in production): party 2 flips its share of every candidate's z ^ r.
    // Every candidate is then wrong in the same way, which every sacrifice passes: only
    // the cut catches it.
    if (party_ == 2)
      for (int64_t q = 0; q < pop; ++q) zr[(size_t)q] ^= 1;
#endif
    std::vector<uint8_t> zr_open((size_t)pop);
#ifdef EMP_AG_TEST_CNC_SPLIT_ZR
    open_(zr.data(), pop, zr_open.data(), nullptr, /*split=*/true);
#else
    open_(zr.data(), pop, zr_open.data(), nullptr);
#endif
    char zr_view[FsHash::DIGEST_SIZE];
    FsHash::hash_once(zr_view, zr_open.data(), zr_open.size());
    const block dxor = Delta_ ^ bit0_mask;
    parallel_for(pool_, (int)pop, [&](int lo, int hi) {
      for (int q = lo; q < hi; ++q) {
        if (!zr_open[(size_t)q]) continue;
        const size_t e = (size_t)(2 * pop + q);
        if (party_ == 1) {
          bit[e] ^= 1;
          for (int p = 2; p <= nP; ++p) mac[p][e] = mac[p][e] ^ bit0_mask;
        } else {
          key[1][e] = key[1][e] ^ dxor;
        }
      }
    });

    // 4. One coin: the cut, then the sacrifice shifts, then the combine shifts.
    const block coin = sampleRandom<nP>(
        io_, &prg_, pool_, party_,
        RO("emp-ag:cut-and-choose:coin", sid_).absorb((uint64_t)batches_).squeeze_block());
    PRG cp(&coin);
    const std::vector<int64_t> subset = uniform_subset_(cp, pop, P.cut);
    std::vector<int64_t> s((size_t)T, 0), rot((size_t)B, 0);
    for (int k = 1; k < T; ++k) s[(size_t)k] = uniform_(cp, t);
    for (int m = 1; m < B; ++m) rot[(size_t)m] = uniform_(cp, ell);
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
    auto head = [&](int64_t j, int m) {
      const int64_t q = j + rot[(size_t)m];
      return m * ell + (q < ell ? q : q - ell);
    };

    // The values opened: the cut's a, b, c; each sacrifice pair's a_h ^ a_k and b_h ^ b_k;
    // each combine member's b_head ^ b_member. Value v is entry e0, XOR entry e1 if e1 >= 0.
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
      const int64_t j = v / (B - 1);
      return {pop + head(j, 0), pop + head(j, (int)(v % (B - 1)) + 1)};
    };
    std::vector<uint8_t> mine((size_t)n_open), opened((size_t)n_open);
    parallel_for(pool_, (int)n_open, [&](int lo, int hi) {
      for (int v = lo; v < hi; ++v) {
        const auto [e0, e1] = entries(v);
        mine[(size_t)v] = bit[(size_t)e0] ^ (e1 >= 0 ? bit[(size_t)e1] : 0);
      }
    });
#ifdef EMP_AG_TEST_CNC_FLIP_OPEN
    // TEST-ONLY (never in production): party 2 flips its share of the first sacrifice
    // difference and sends it to everyone.
    if (party_ == 2) mine[(size_t)n_cut] ^= 1;
#endif
    std::vector<uint8_t> shares[nP + 1];   // all to all: what each peer sent
#ifdef EMP_AG_TEST_CNC_KING_SPLIT
    open_(mine.data(), n_open, opened.data(), shares, /*split=*/true);
#else
    open_(mine.data(), n_open, opened.data(), shares);
#endif

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
#ifdef EMP_AG_TEST_CNC_FLIP_RESIDUAL
      // TEST-ONLY (never in production): party 2 sends everyone a wrong share of the first
      // sacrifice residual.
      if (party_ == 2) own[0] ^= 1;
#endif
      open_(own.data(), n_res, sum.data(), res_shares);
      for (int64_t pr = 0; pr < n_res; ++pr)
        res_sums_ok = res_sums_ok && sum[(size_t)pr] == (rho(pr) & sigma(pr));
      agree_directly_(zr_view);
    }

    // 5. One open check over the opened values and the residuals.
    const auto run_open = check_.begin(n_open);
    const auto run_res = check_.begin(n_res);
    check_.seal();
    if constexpr (OpenCheck::kAbsorbsZeroShares) {
      const auto pending = abit_.take_pending_check2();
      check_.absorb(pending.residuals, pending.view);
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
    if constexpr (!OpenCheck::kAbsorbsZeroShares) abit_.settle_check2();
    // The public checks, on values the open check has now authenticated (so which check
    // fails says nothing about the shares behind a forged opening).
    expecting(res_sums_ok, "cut-and-choose: a sacrificed pair does not match");
    for (int64_t i = 0; i < P.cut; ++i)
      expecting((opened[(size_t)(3 * i)] & opened[(size_t)(3 * i + 1)]) == opened[(size_t)(3 * i + 2)],
                "cut-and-choose: a cut triple is incorrect");

    // 6. Output j: a = XOR of its members' a, b = b_head, c = c_head ^ XOR over members m
    //    of c_m ^ (b_head ^ b_m) a_m.
    for (int p = 1; p <= nP; ++p) if (p != party_) {
      bank_mac_[p].resize((size_t)(3 * ell));
      bank_key_[p].resize((size_t)(3 * ell));
    }
    const uint8_t *d = opened.data() + n_cut + n_sac;
    parallel_for(pool_, (int)ell, [&](int lo, int hi) {
      for (int j = lo; j < hi; ++j) {
        for (int p = 1; p <= nP; ++p) if (p != party_) {
          const block *M = mac[p].data(), *K = key[p].data();
          const int64_t h0 = j;   // head(j, 0)
          block am = M[h0], ak = K[h0], cm = M[2 * pop + h0], ck = K[2 * pop + h0];
          for (int m = 1; m < B; ++m) {
            const int64_t hm = head(j, m);
            am = am ^ M[hm];
            ak = ak ^ K[hm];
            cm = cm ^ M[2 * pop + hm];
            ck = ck ^ K[2 * pop + hm];
            if (d[(size_t)j * (B - 1) + (m - 1)]) {
              cm = cm ^ M[hm];
              ck = ck ^ K[hm];
            }
          }
          bank_mac_[p][(size_t)j] = am;
          bank_key_[p][(size_t)j] = ak;
          bank_mac_[p][(size_t)(ell + j)] = M[pop + h0];
          bank_key_[p][(size_t)(ell + j)] = K[pop + h0];
          bank_mac_[p][(size_t)(2 * ell + j)] = cm;
          bank_key_[p][(size_t)(2 * ell + j)] = ck;
        }
      }
    });
    bank_ell_ = ell;
    bank_pos_ = 0;
  }
};

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_TRIPLE_CUT_AND_CHOOSE_TRIPLES_H__
