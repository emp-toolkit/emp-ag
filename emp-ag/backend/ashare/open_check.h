#ifndef EMP_AG_BACKEND_ASHARE_OPEN_CHECK_H__
#define EMP_AG_BACKEND_ASHARE_OPEN_CHECK_H__
//
// Checking opened authenticated bits. Parties open a vector of BDOZ-authenticated bits
// by sending each other their share bits; the opened values can be trusted only once
// every share has been checked against its MACs. Both checkers below are stateful:
// values are recorded as they are opened, check_result() settles everything recorded
// since the last call and aborts on a mismatch, and the caller settles before anything
// computed from the opened values is revealed. Every party starts the same runs in the
// same order and calls seal() and check_result() at the same points.
//
// Values are recorded from inside the caller's own loops, so the check reads each MAC
// and key while the caller has it loaded anyway: begin() starts a run of n values,
// every worker thread feeds a Lane, and merge() folds the lane into the checker.
// seal() comes after every value of the runs it covers is opened (sent and received)
// and before their first lane; add() does all of this for one vector.
//
// PairwiseOpenCheck: for each directed pair, the opener's tag is the XOR, over its
//   MACs M under the verifier's key, of F(M ^ T(i)), where F is AES under a key
//   derived from the session id and T(i) is the value's position. The verifier
//   recomputes the XOR from its keys and the bits it received. This is the batched
//   opening of TinyTable (ePrint 2016/695, Sec. 3.3) with a position tweak: without
//   it, two copies of one value would cancel, and flipping both would leave the tag
//   unchanged. A flipped bit needs F(M ^ Delta ^ T(i)), and that takes the verifier's
//   Delta. F is used as a random function; no output of it on a secret input is ever
//   sent, only compared. No coin: seal() does nothing, and lanes may run before the
//   bits they check arrive (the sender's half needs none). Lanes AES sixteen values at
//   a time; check_result() is one flight of one block per directed pair. A party's tag
//   depends only on its own MACs, so it is final before its bits go out and can ride the
//   flight of the last bits it covers (kTagRidesBits): check_result(peer_tags) then
//   compares with no flight of its own. A tag may be sent truncated to tag_bytes (at
//   least 10, i.e. 80 bits): a forged one then passes with probability 2^-(8 tag_bytes).
//
// SymmetricOpenCheck: each party turns every opened bit into its share of zero,
//   r_i = mu_i(x) ^ v * Delta_i, where mu_i is its SPDZ collapse of the bit's BDOZ
//   sharing x and v is the opened value, so that XOR_i r_i = (x ^ v) * Delta. Value k
//   of run j is folded with coefficient c_{j,k} = AES_K(j, k), where K is a coin that
//   seal() draws once the values are fixed: at nP == 2 a Fiat-Shamir hash of the
//   channel transcripts, which binds the session and every message sent, the opened
//   shares included; at nP > 2, where no transcript is common to all parties and the
//   coefficients must be, a commit-then-open coin. A wrong value then survives only
//   with probability about 2^-128. Residuals are folded as the caller computes them
//   after seal(), so nothing is stored per value; one gfmul per opened bit per party
//   at any nP. Rounds: the coin (none at nP == 2, two above) and check_result()'s
//   commit-then-open zero test (two). agree() adds to that zero test a digest of values
//   another check opened without an echo (the aShare consistency check's hash values);
//   the parties must agree on it, and its comparison rides with the commitments.
//
// Both checkers verify, per receiver, that the bit a party sent it matches that party's
// MAC toward it. That the bits a party sent different receivers agree comes from the
// aShare consistency check: a party holds the same share toward every peer.
//
// DefaultOpenCheck is the pairwise checker at nP == 2 and the symmetric one above.
// EMP_AG_OPEN_CHECK_PAIRWISE or EMP_AG_OPEN_CHECK_SYMMETRIC forces one at every nP;
// all parties must use the same checker.
//
#include "emp-ag/backend/common/feq.h"         // fs_coin_pair_group, symmetric F_eq
#include "emp-ag/backend/common/protocols.h"   // sampleRandom, check_shared_zero_p2p
#include "emp-ag/backend/common/netmp.h"
#include "emp-ag/backend/common/runtime.h"            // parallel_for
#include "emp-tool/emp-tool.h"
#include <algorithm>
#include <climits>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <type_traits>
#include <vector>
#include "emp-ag/backend/common/test_hooks.h"

// The width, in bytes, of share evaluation's tags (triple/share_eval.h): 16 by default.
// Any other width changes the wire, so it binds the session id (garble/protocol.h).
#ifndef EMP_AG_SHARE_TAG_BYTES
#define EMP_AG_SHARE_TAG_BYTES 16
#endif

EMP_AG_NAMESPACE_BEGIN

template <int nP>
class PairwiseOpenCheck {
public:
  // Needs each opened value's MAC and key per peer, not just its SPDZ collapse.
  static constexpr bool kPerPeerOperands = true;
  // No zero test to carry other checks' views: their callers agree on them separately.
  static constexpr bool kAgreesViews = false;
  // A tag can ride the flight of the bits it covers (tag(), check_result(peer_tags)).
  static constexpr bool kTagRidesBits = true;

  // `purpose` is the domain of the tag key, as it is of SymmetricOpenCheck's coin: two
  // instances on one session id need different ones, since positions restart at 0 in
  // each. fail_msg is the abort message of a tag mismatch. tag_bytes is the width a tag
  // goes out at, in [10, 16].
  PairwiseOpenCheck(NetIOMP<nP> *io, ThreadPool *pool, int party, block Delta,
                    block session_id, PRG * /*prg*/, NetIOMPGroup<nP> * /*grp*/,
                    const char *purpose = "emp-ag:open-check",
                    const char *fail_msg = "open check: MAC tag mismatch",
                    int tag_bytes = (int)sizeof(block))
      : io_(io), pool_(pool), party_(party), Delta_(Delta), fail_msg_(fail_msg),
        tag_bytes_(tag_bytes) {
    expecting(tag_bytes >= 10 && tag_bytes <= (int)sizeof(block),
              "open check: a tag is 10 to 16 bytes");
    AES_set_encrypt_key(RO(purpose, session_id).squeeze_block(), &aes_);
    for (int p = 0; p <= nP; ++p) sent_[p] = expected_[p] = zero_block;
  }

  // A run of opened values: value k of the run is tagged at position start + k, and
  // positions never repeat.
  struct Run { uint64_t start = 0; };
  Run begin(int64_t n) {
    Run run{pos_};
    if (n > 0) { pos_ += (uint64_t)n; pending_ = true; }
    return run;
  }
  void seal() {}   // no coin

  // One worker's partial tags, AES-ed sixteen values at a time.
  class Lane {
  public:
    Lane(const PairwiseOpenCheck &c, const Run &run) : c_(&c), start_(run.start) {
      for (int j = 0; j < kW; ++j) in_[j] = zero_block;
      for (auto &a : acc_) a = zero_block;
    }
    // This party's MAC on its share of value k, under peer's key.
    void sent(int peer, int64_t k, const block &mac) {
      push_(mac ^ makeBlock(start_ + (uint64_t)k, 0), 2 * peer);
    }
    // This party's key on peer's share of value k, and the bit peer sent for it.
    void expected(int peer, int64_t k, const block &key, unsigned char bit) {
      push_(key ^ (select_mask[bit & 1] & c_->Delta_) ^ makeBlock(start_ + (uint64_t)k, 0),
            2 * peer + 1);
    }

  private:
    friend class PairwiseOpenCheck;
    static constexpr int kW = 16;
    const PairwiseOpenCheck *c_;
    uint64_t start_;
    block in_[kW];
    int slot_[kW] = {};
    int n_ = 0;
    block acc_[2 * (nP + 1)];
    void push_(const block &x, int slot) {
      in_[n_] = x;
      slot_[n_] = slot;
      if (++n_ == kW) drain_();
    }
    void drain_() {
      if (n_ == 0) return;
      block out[kW];
      ParaEnc<1, kW>(out, in_, &c_->aes_);   // all kW; only the first n_ count
      for (int j = 0; j < n_; ++j) acc_[slot_[j]] = acc_[slot_[j]] ^ out[j];
      n_ = 0;
    }
  };
  Lane lane(const Run &run) const { return Lane(*this, run); }
  void merge(Lane &lane) {
    lane.drain_();
    std::lock_guard<std::mutex> lock(mu_);
    for (int p = 1; p <= nP; ++p) {
      sent_[p] = sent_[p] ^ lane.acc_[2 * p];
      expected_[p] = expected_[p] ^ lane.acc_[2 * p + 1];
    }
  }

  // Record one opened vector of n bits, already sent and received. bits[p][k] is party
  // p's share of value k as this party holds it: its own, and what each peer sent it.
  // mac(peer, k) is this party's MAC on its share under peer's key; key(peer, k) is its
  // key on peer's share.
  template <class Mac, class Key>
  void add(int64_t n, const unsigned char *const bits[nP + 1], const Mac &mac,
           const Key &key) {
    if (n <= 0) return;
    expecting(n <= (int64_t)INT_MAX, "open check: vector too long");
    const Run run = begin(n);
    seal();
    parallel_for(pool_, (int)n, [&](int lo, int hi) {
      Lane l = lane(run);
      for (int peer = 1; peer <= nP; ++peer) if (peer != party_)
        for (int k = lo; k < hi; ++k) {
          l.sent(peer, k, mac(peer, k));
          l.expected(peer, k, key(peer, k), bits[peer][k]);
        }
      merge(l);
    });
  }

  // This party's tag toward peer over every value recorded since the last check_result():
  // final once every one of them has its sent() merged, so it can go out with the last
  // of their bits.
  block tag(int peer) const { return sent_[peer]; }
  // The bytes of a tag that go on the wire: the first tag_bytes() of tag().
  int tag_bytes() const { return tag_bytes_; }

  // Exchange one tag per directed pair and compare each peer's with the one this
  // party expects from it.
  void check_result() {
    if (!pending_) return;
    block got[nP + 1];
    vector<future<void>> res;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
      got[peer] = zero_block;
      res.push_back(pool_->enqueue([this, peer]() {
        io_->send_data(peer, &sent_[peer], (size_t)tag_bytes_);
        io_->flush(peer);
      }));
      res.push_back(pool_->enqueue([this, &got, peer]() {
        io_->recv_data(peer, &got[peer], (size_t)tag_bytes_);
      }));
    }
    joinNclean(res);
    compare_(got);
  }

  // check_result(), with the tags the peers sent with their bits (tag()): no flight.
  void check_result(const block peer_tag[nP + 1]) {
    if (!pending_) return;
    compare_(peer_tag);
  }

private:
  void compare_(const block got[nP + 1]) {
    bool good = true;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_)
      good = good && memcmp(&got[peer], &expected_[peer], (size_t)tag_bytes_) == 0;
    for (int p = 0; p <= nP; ++p) sent_[p] = expected_[p] = zero_block;
    pending_ = false;
    expecting(good, fail_msg_);
  }

  NetIOMP<nP> *io_;
  ThreadPool *pool_;
  int party_;
  block Delta_;
  const char *fail_msg_;
  int tag_bytes_;
  AES_KEY aes_;
  uint64_t pos_ = 0;       // position of the next value; never reused
  bool pending_ = false;   // something recorded since the last check_result()
  block sent_[nP + 1], expected_[nP + 1];
  std::mutex mu_;
};

template <int nP>
class SymmetricOpenCheck {
public:
  // Needs only each opened value's SPDZ collapse mu_i, not its MACs per peer.
  static constexpr bool kPerPeerOperands = false;
  // Its zero test can carry other checks' views (agree()).
  static constexpr bool kAgreesViews = true;
  // Its residuals need the opened values, so nothing of it rides the bits.
  static constexpr bool kTagRidesBits = false;

  // `purpose` separates this check's coin and commitments from every other use;
  // fail_msg, commit_fail_msg and agree_fail_msg are the abort messages of its zero
  // test (a nonzero sum, a commitment mismatch, disagreeing views).
  SymmetricOpenCheck(NetIOMP<nP> *io, ThreadPool *pool, int party, block Delta,
                     block session_id, PRG *prg, NetIOMPGroup<nP> *grp,
                     const char *purpose = "emp-ag:open-check",
                     const char *fail_msg = "open check: opened values do not match their MACs",
                     const char *commit_fail_msg = "open check: commit-open mismatch",
                     const char *agree_fail_msg = "open check: parties saw different values opened without an echo")
      : io_(io), pool_(pool), party_(party), Delta_(Delta), session_id_(session_id),
        prg_(prg), grp_(grp), purpose_(purpose), fail_msg_(fail_msg),
        commit_fail_msg_(commit_fail_msg), agree_fail_msg_(agree_fail_msg) {}

  // A run of opened values: value k of run j gets coefficient c_{j,k} = AES_K(j, k).
  struct Run { uint64_t index = 0; };
  Run begin(int64_t n) {
    Run run{runs_++};
    if (n > 0) pending_ = true;
    return run;
  }

  // Draw the coin K for every run begun since the last check_result(). Every value of
  // those runs must be opened by now; lanes come after.
  void seal() {
    if (!pending_) return;
    block coin;
    if constexpr (nP == 2)
      coin = fs_coin_pair_group<nP>(io_, grp_, party_ == 1 ? 2 : 1, purpose_, session_id_);
    else
      coin = sampleRandom<nP>(io_, prg_, pool_, party_, session_id_);
    AES_set_encrypt_key(coin, &key_);
    sealed_ = true;
  }

  // Add `view` (FsHash::DIGEST_SIZE bytes) to this check's zero test: a digest of values
  // another check opened without an echo. check_result() aborts unless every party
  // added the same views. Call it after the values behind the view are fixed, and
  // before check_result(); with nothing begun, it draws the coin itself.
  void agree(const char *view) {
    if (!sealed_) {
      pending_ = true;
      seal();
    }
    std::lock_guard<std::mutex> lock(mu_);
    views_.put(view, FsHash::DIGEST_SIZE);
    has_views_ = true;
  }

  // The residual r_i of one value from its parts: own_xor_v is this party's share XOR
  // the opened value, and mac_key_sum is XOR_peer (mac ^ key); add mu_i of any part
  // already collapsed.
  block residual(unsigned char own_xor_v, const block &mac_key_sum) const {
    return mac_key_sum ^ (select_mask[own_xor_v & 1] & Delta_);
  }

  // One worker's partial fold sum c_{j,k} * r_k, unreduced, eight values at a time.
  class Lane {
  public:
    Lane(const SymmetricOpenCheck &c, const Run &run) : key_(&c.key_), run_(run.index) {
      expecting(c.sealed_, "open check: lane before seal()");
      for (int j = 0; j < kW; ++j) ctr_[j] = r_[j] = zero_block;
    }
    void put(int64_t k, const block &r) {
      ctr_[n_] = makeBlock(run_, (uint64_t)k);
      r_[n_] = r;
      if (++n_ == kW) drain_();
    }

  private:
    friend class SymmetricOpenCheck;
    static constexpr int kW = 8;
    const AES_KEY *key_;
    uint64_t run_;
    block ctr_[kW], r_[kW];
    int n_ = 0;
    block lo_ = zero_block, hi_ = zero_block;
    void drain_() {
      if (n_ == 0) return;
      block c[kW];
      ParaEnc<1, kW>(c, ctr_, key_);   // all kW; only the first n_ count
      for (int j = 0; j < n_; ++j) {
        block l, h;
        mul128(c[j], r_[j], &l, &h);
        lo_ = lo_ ^ l;
        hi_ = hi_ ^ h;
      }
      n_ = 0;
    }
  };
  Lane lane(const Run &run) const { return Lane(*this, run); }
  void merge(Lane &lane) {
    lane.drain_();
    std::lock_guard<std::mutex> lock(mu_);
    lo_ = lo_ ^ lane.lo_;
    hi_ = hi_ ^ lane.hi_;
  }

  // Same contract as PairwiseOpenCheck::add.
  template <class Mac, class Key>
  void add(int64_t n, const unsigned char *const bits[nP + 1], const Mac &mac,
           const Key &key) {
    if (n <= 0) return;
    expecting(n <= (int64_t)INT_MAX, "open check: vector too long");
    const Run run = begin(n);
    seal();
    parallel_for(pool_, (int)n, [&](int lo, int hi) {
      Lane l = lane(run);
      for (int k = lo; k < hi; ++k) {
        unsigned char others = 0;   // own share ^ v
        block s = zero_block;
        for (int p = 1; p <= nP; ++p) if (p != party_) {
          others ^= bits[p][k];
          s = s ^ mac(p, k) ^ key(p, k);
        }
        l.put(k, residual(others, s));
      }
      merge(l);
    });
  }

  // One zero test on the folded residuals: XOR_i m_i = (sum c_{j,k} (x ^ v)) * Delta.
  void check_result() {
    if (!pending_) return;
    expecting(sealed_, "open check: check_result() before seal()");
    const block m = reduce(lo_, hi_);
    lo_ = hi_ = zero_block;
    pending_ = sealed_ = false;
    char agree[FsHash::DIGEST_SIZE];   // the views added, which every party must share
    const bool has_views = has_views_;
    if (has_views) views_.digest(agree);   // and resets
    has_views_ = false;
    if constexpr (nP == 2) {
      // XOR_i m_i = 0 <=> m_1 == m_2: the symmetric F_eq on H(m_i), with the views.
      char dme[FsHash::DIGEST_SIZE];
      FsHash hm;
      hm.put(&m, sizeof(block));
      if (has_views) hm.put(agree, FsHash::DIGEST_SIZE);
      hm.digest(dme);
      const int peer = (party_ == 1) ? 2 : 1;
      NetIO *sch = (party_ < peer) ? io_->ios[peer] : io_->ios2[peer];
      NetIO *rch = (peer < party_) ? io_->ios[peer] : io_->ios2[peer];
      FeqSymmetric2PC eq = feq_prepare_symmetric_2pc(prg_, session_id_, purpose_, party_, dme);
      sch->send_data(eq.commitment, FsHash::DIGEST_SIZE);
      sch->flush();
      rch->recv_data(eq.peer_commitment, FsHash::DIGEST_SIZE);
      feq_finish_symmetric_2pc(sch, rch, session_id_, purpose_, party_, eq, fail_msg_);
    } else {
      check_shared_zero_p2p<nP>(io_, pool_, prg_, party_, m, session_id_, purpose_,
                                fail_msg_, commit_fail_msg_,
                                has_views ? agree : nullptr, agree_fail_msg_);
    }
  }

private:
  NetIOMP<nP> *io_;
  ThreadPool *pool_;
  int party_;
  block Delta_;
  block session_id_;
  PRG *prg_;
  NetIOMPGroup<nP> *grp_;
  const char *purpose_, *fail_msg_, *commit_fail_msg_, *agree_fail_msg_;
  AES_KEY key_;            // the coin K, set by seal()
  uint64_t runs_ = 0;      // runs started; a run's index enters its coefficients
  bool pending_ = false;   // something recorded since the last check_result()
  bool sealed_ = false;    // the coin for the pending runs is drawn
  block lo_ = zero_block, hi_ = zero_block;   // folded residuals, unreduced
  FsHash views_;           // the views added since the last check_result(), in order
  bool has_views_ = false;
  std::mutex mu_;
};

#if defined(EMP_AG_OPEN_CHECK_PAIRWISE) && defined(EMP_AG_OPEN_CHECK_SYMMETRIC)
#error "EMP_AG_OPEN_CHECK_PAIRWISE and EMP_AG_OPEN_CHECK_SYMMETRIC are exclusive"
#endif
#if defined(EMP_AG_OPEN_CHECK_PAIRWISE)
template <int nP> using DefaultOpenCheck = PairwiseOpenCheck<nP>;
#elif defined(EMP_AG_OPEN_CHECK_SYMMETRIC)
template <int nP> using DefaultOpenCheck = SymmetricOpenCheck<nP>;
#else
template <int nP>
using DefaultOpenCheck =
    std::conditional_t<nP == 2, PairwiseOpenCheck<nP>, SymmetricOpenCheck<nP>>;
#endif

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_ASHARE_OPEN_CHECK_H__
