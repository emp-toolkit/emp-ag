#ifndef EMP_AG_BACKEND_PREPROC_TRIPLE_POOL_H__
#define EMP_AG_BACKEND_PREPROC_TRIPLE_POOL_H__
#include "emp-ag/backend/preproc/auth_share_pool.h"
#include "emp-ag/backend/crypto/fs_hash.h"  // FsHash (FS/check digests)
#include "emp-ag/backend/crypto/feq.h"     // fs_coin_pair, symmetric F_eq
#include "emp-ag/backend/crypto/fzero.h"   // fzero_xor
#include "emp-ag/backend/crypto/laand_window.h"
#include "emp-ag/backend/crypto/open_check.h"  // DefaultOpenCheck (d and x/y opens)
#include "emp-ag/backend/crypto/protocols.h"   // sampleRandom
#include "emp-ag/backend/netmp.h"
#include "emp-ag/backend/profiling.h"
#include "emp-ag/backend/runtime.h"        // parallel_for, lane_range
#include "emp-ag/backend/crypto/bucketing.h"   // emp::ag::bucket_size (shared)
#include "emp-tool/runtime/crypto/mitccrh.h"
#include <climits>
#include <cstdint>
#include <thread>
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/crypto/prg.h"      // PRG
#include <vector>
#include "emp-tool/runtime/crypto/hash.h"
#include <algorithm>
#include <cstring>
#include <functional>
#include <memory>

namespace emp::ag {

// ---- Bucketing leaves used only by TriplePool: the cyclic-shift fold, the batched
//      schedule (run_bucketing_core), and the windowed F_eq. bucket_size lives in
//      backend/crypto/bucketing.h so its pure-math unit test (test/bucketing_test.cpp)
//      can include it standalone.

// ===== cyclic-shift bucket fold =====
// Source index of layer element i under cyclic shift r in [0,L): the wraparound
// splits at i==L-r. THE byte-identity tripwire — an off-by-one here drifts every
// downstream transcript — so it is single-sourced and used by all three leaves.
inline int bucket_fold_src(int i, int L, int r) {
  const int cut = L - r;
  return (i < cut) ? i + r : i + r - L;
}

// Draw an exactly uniform cyclic-shift index. A plain `word % L` is biased
// unless L divides the word range; widening that word to 128 bits only makes
// the mismatch tiny, while the bucketing proof assumes a uniform rotation.
// Lemire-style threshold rejection over a fixed little-endian uint64_t is exact,
// deterministic across architectures, and rejects with probability < 2^-33 for
// the supported L<=INT_MAX. Each attempt consumes one PRG block.
inline int bucket_uniform_shift(PRG &prg, int L) {
  expecting(L > 0, "bucket_uniform_shift: L must be positive");
  const uint64_t bound = (uint64_t)L;
  const uint64_t threshold = (uint64_t(0) - bound) % bound;
  uint64_t raw;
  do {
    unsigned char bytes[8];
    prg.random_data_unaligned(bytes, sizeof(bytes));
    raw = 0;
    for (int i = 0; i < 8; ++i) raw |= (uint64_t)bytes[i] << (8 * i);
  } while (raw < threshold);
  return (int)(raw % bound);
}

// Phase 1: a/c XOR fold. acc.a ^= layer.a[src]; acc.c ^= layer.c[src] over the
// (mac,key) pair; b is untouched. No d, no IO. [i0, i1) bounds the OUTPUT index
// range so the caller can width-split one peer's fold across pool workers: the
// per-element XOR-RMW makes ranges of the same (peer, layer) race-free, while
// two LAYERS of the same peer must stay ordered (both RMW the same acc slots).
inline void bucket_fold_pre_ac(block *am, block *ak, const block *lm,
                               const block *lk, int L, int r, int i0, int i1) {
  for (int i = i0; i < i1; ++i) {
    const int src = bucket_fold_src(i, L, r);
    am[i]         = am[i]         ^ lm[src];
    am[2 * L + i] = am[2 * L + i] ^ lm[2 * L + src];
    ak[i]         = ak[i]         ^ lk[src];
    ak[2 * L + i] = ak[2 * L + i] ^ lk[2 * L + src];
  }
}

// The public d-bit: bit0 of the b-region MAC of acc vs the shifted layer. Filled
// ONCE from the chosen peer slot (b is never written by the a/c fold, so it may
// run concurrently with any bucket_fold_pre_ac range, including that peer's own).
// The caller exchanges d over its own transport and combines (XOR for 2PC; the
// cross-peer fold for n-party). [i0, i1) as above.
inline void bucket_fold_dbit(const block *am, const block *lm, int L, int r,
                             unsigned char *d_out, int i0, int i1) {
  for (int i = i0; i < i1; ++i) {
    const int src = bucket_fold_src(i, L, r);
    d_out[i] = (unsigned char)(getLSB(am[L + i]) ^ getLSB(lm[L + src]));
  }
}

// Phase 3: masked c-correction, keyed on the ALREADY-COMBINED public d (d[1] after the
// cross-peer fold; d_me^d_peer at nP==2). d_comb is read-only and shared across peers.
// [i0, i1) as above.
inline void bucket_fold_post(block *am, block *ak, const block *lm,
                             const block *lk, int L, int r,
                             const unsigned char *d_comb, int i0, int i1) {
  for (int i = i0; i < i1; ++i) {
    const int src = bucket_fold_src(i, L, r);
    const block m = select_mask[d_comb[i]];
    am[2 * L + i] = am[2 * L + i] ^ (lm[src] & m);
    ak[2 * L + i] = ak[2 * L + i] ^ (lk[src] & m);
  }
}

// ===== batched bucketing schedule =====
template <class BucketPolicy>
void run_bucketing_core(BucketPolicy &pol, int B, int L) {
  // ---- Pass 1: generate + COMMIT all B layers. nP==2 batches their row flight
  // and dependent s flight; nP>=3 builds each layer separately.
  // No coin yet, so the entire B*L set is fixed before draw_coins. ----
  pol.generate_layers();

  // ---- The ONE post-commitment coin -> the B-1 cyclic shifts. One PRG stream from
  // one seed (so the shifts are jointly pseudorandom). The PRG outlives the shift
  // draw and is handed to finalize_check: nP>=3 CONTINUES this exact stream for its
  // batched-RLC challenge phi_cat (so the challenge is drawn from the same post-commitment
  // coin, right after the shifts); nP==2 ignores it (feq_check). ----
  block coin = pol.draw_coins();
  PRG prg(&coin);
  std::vector<int> shift(B, 0);
  for (int k = 1; k < B; ++k) shift[k] = bucket_uniform_shift(prg, L);

  // ---- Pass 2: shifts known -> fold each layer's a/c + the b-region d-bit (local),
  // exchange ALL (B-1)*L d-bits in ONE round, then apply the masked c-correction. ----
  for (int k = 1; k < B; ++k) pol.fold_pre_and_dbit(k, shift[k]);
  pol.exchange_all_d();
  for (int k = 1; k < B; ++k) pol.fold_post(k, shift[k]);

  // ---- ONE terminal check over all B layers (the batched F_eq / RLC zero-sum).
  pol.finalize_check(prg);
}

// ===== windowed F_eq (leaky-AND) =====
// Fixed stripe width (in elements) for the parallel F_eq window fold below. It
// shapes the CHECK VALUE (stripe digests are what the running hash binds), so it
// must be identical at both parties: a compile-time constant, never a function of
// the local pool size.
inline constexpr int kFeqStripeElems = 1 << 16;

// Fold one bucket layer's L-vector into the running F_eq hash, restricted to the
// low `bits` bits of each element (the transmitted window), zero-padded locally
// to `gb` bytes. The fold is a fixed two-level hash: the window bytes are
// gathered and hashed per kFeqStripeElems-element stripe (independent stripes,
// so gather and hashing run pool-parallel), and the ordered stripe digests feed
// the running feq. Collision resistance composes across the levels, so this
// binds exactly the window bytes; both parties use the same stripe constant and
// derive the same stripe count from the common L. One terminal symmetric F_eq
// fires per bucket; the caller owns it.
inline void accumulate_leaky_and_window(FsHash &feq, const block *src, int L, int bits,
                                        std::vector<unsigned char> &scratch,
                                        ThreadPool *pool) {
  const int gb = (bits + 7) / 8;
  // Caller-owned grow-only scratch (a plain member, passed by ref -- no per-access
  // overhead): this runs B x per chunk, so a fresh L*gb buffer each
  // call is mmap/fault/munmap churn. Stripes write disjoint ranges.
  const size_t need = (size_t)L * gb;
  if (scratch.size() < need) scratch.resize(need);
  const int ns = (L + kFeqStripeElems - 1) / kFeqStripeElems;
  std::vector<char> dg((size_t)ns * FsHash::DIGEST_SIZE);
  vector<future<void>> res;
  for (int s = 0; s < ns; ++s) {
    res.push_back(pool->enqueue([&, s]() {
      const int k0 = s * kFeqStripeElems;
      const int k1 = std::min(L, k0 + kFeqStripeElems);
      unsigned char *dst = scratch.data() + (size_t)k0 * gb;
      for (int k = k0; k < k1; ++k) {
        memcpy(scratch.data() + (size_t)k * gb, &src[k], gb);
        scratch[(size_t)(k + 1) * gb - 1] &= laand_last_byte_mask(bits);
      }
      FsHash::hash_once(dg.data() + (size_t)s * FsHash::DIGEST_SIZE, dst,
                      (size_t)(k1 - k0) * gb);
    }));
  }
  joinNclean(res);
  feq.put(dg.data(), dg.size());
}

// Batched nP==2 production already keeps each zero-padded bit window contiguous, so
// preserve the exact same stripe-hash construction without gathering blocks
// through a second scratch buffer.
inline void accumulate_leaky_and_window_bytes(FsHash &feq,
                                              const unsigned char *src,
                                              int L, int gb, ThreadPool *pool) {
  const int ns = (L + kFeqStripeElems - 1) / kFeqStripeElems;
  std::vector<char> dg((size_t)ns * FsHash::DIGEST_SIZE);
  vector<future<void>> res;
  for (int s = 0; s < ns; ++s) {
    res.push_back(pool->enqueue([&, s]() {
      const int k0 = s * kFeqStripeElems;
      const int k1 = std::min(L, k0 + kFeqStripeElems);
      FsHash::hash_once(dg.data() + (size_t)s * FsHash::DIGEST_SIZE,
                        src + (size_t)k0 * gb,
                        (size_t)(k1 - k0) * gb);
    }));
  }
  joinNclean(res);
  feq.put(dg.data(), dg.size());
}

// The AND gates' input-mask shares as the draw walk captured them, a for the first
// input's mask and b for the second's: this party's share bits always, and what the
// open check needs (OpenCheck::kPerPeerOperands) -- either, one array per peer, this
// party's MAC (under peer's key) and key (on peer's share), or the SPDZ collapse mu_i.
template <int nP>
struct BeaverOperands {
  const unsigned char *a_bit = nullptr, *b_bit = nullptr;
  const block *a_mac[nP + 1] = {}, *a_key[nP + 1] = {};
  const block *b_mac[nP + 1] = {}, *b_key[nP + 1] = {};
  const block *a_mu = nullptr, *b_mu = nullptr;
};

// Π_LaAND followed by Π_Prep bucketing: AND-triple generation via half-gate
// garbled-AND + phi-based triple check, then circular-shift bucketing to remove
// leakage.
//
// Implementation choices:
//
// (1) FZero is implemented via pairwise seed-and-expand
//     under the ICM assumption on the AES-based PRG: each pair shares a
//     λ-bit seed, both expand into LB+1 blocks via PRG, XOR into local
//     (z^i, u^i). Each seed contributes to exactly two parties so
//     Σ_p z^p_k = 0 and Σ_p u^p = 0. (Same construction as
//     AuthSharePool::check1.)
//
// (2) F_Com is collapsed to a single send for both d^i and
//     α^i.  No value derived from the committed bits is
//     sent before the matching open, so equivocation is impossible —
//     the commitment phase is redundant.  α^i is hash-committed first
//     (one round) and then opened, since the α-check needs binding.
//
// (3) The B-1 sequential OpenToAll calls of the bucket combine (one per
//     non-first leaky triple in each bucket) are batched into a single
//     all-to-all exchange of the full d-vector, dropping the bucket
//     combine to one round. The opened d-vector is checked against its MACs by
//     the open check, together with the Beaver x/y, before compute_and_shares
//     returns.
//
// This is the per-call triple / AND-share generator (no pool): compute_and_shares
// first generates B independent leaky triples per AND and buckets them into one
// authenticated random triple. Only then does it open the Beaver differences to
// the circuit masks and produce σ = λ_α∧λ_β. No circuit mask enters leaky-AND
// generation or bucketing. Both opens of a call -- the bucket d-vector and the
// Beaver x/y -- go through OpenCheck (crypto/open_check.h), settled once before
// compute_and_shares returns.
template <int nP, class OpenCheck = DefaultOpenCheck<nP>>
class TriplePool {
public:
  using open_check_t = OpenCheck;
  ThreadPool *pool;
  int party;
  int ssp;              // statistical security parameter (default 40)
  NetIOMP<nP> *io;
  block session_id;
  AuthSharePool<nP> abit;
  block Delta;
  PRG prg;
  OpenCheck open_check_;   // checks the d and x/y opens against their MACs
  // Half-gate hash seed (every sender's MITCCRH stream starts from it), piggybacked off
  // the per-chunk post-commitment bucket coin in BucketPolicy::draw_coins (one extra
  // domain-separated squeeze, no dedicated coin round). AGMPCProtocol::draw_and_seed
  // copies it into ctx.halfgate_seed after compute_and_shares; refreshed on every
  // compute_and_shares that has ANDs.
  block halfgate_seed_ = zero_block;
  // Batched LaAND alpha-check stash (nP>=3): each layer's windowed RLC vector +
  // its FZero u_zero are accumulated here across all B layers of a bucket; the ONE
  // B*L RLC zero-sum runs in compute_and_shares. Cleared per compute_and_shares.
  BlockVec alpha_masked_cat_;
  std::vector<block> alpha_uzero_;
  // Reused per-chunk bucketing scratch (grow-only). compute_and_shares runs once per
  // protocol chunk; these per-peer random-triple accumulator buffers and the
  // B-1 sacrifice layers (3*L each) + d-vectors
  // are kept resident across chunks instead of being mmap/first-touch-fault/munmap'd
  // every chunk. Bytes overwritten each chunk; grow-only => no realloc once the
  // steady-state chunk size is reached.
  BlockVec bkt_accMAC_[nP + 1], bkt_accKEY_[nP + 1];
  std::vector<std::vector<BlockVec>> bkt_sac_macs_, bkt_sac_keys_;
  std::vector<unsigned char> bkt_bd_[nP + 1];
  std::vector<int> bkt_shift_;   // each layer's cyclic shift, kept for the open check
  // produce_leaky_ands_halfgate scratch (per-layer, B x per chunk; grow-only). All
  // assigned/explicitly-zeroed before read except z_u (XOR-accumulated by fzero_xor
  // -> caller re-zeros via std::fill each call). + the per-chunk RLC challenge phi_cat
  // (nP>=3 finalize_check) and the compute_and_shares reveal buffers x/y.
  BlockVec bkt_tKEYphi_[nP + 1], bkt_tMACphi_[nP + 1];
  BlockVec bkt_phi_, bkt_z_u_, bkt_phi_cat_;
  std::vector<unsigned char> bkt_s_[nP + 1];
  std::vector<unsigned char> bkt_x_[nP + 1], bkt_y_[nP + 1];
  std::vector<unsigned char> bkt_window_;   // accumulate_leaky_and_window scratch
  BlockVec bkt_fzero_;                       // fzero_xor contribution scratch
  // grp (optional): a NetIOMPGroup (mesh(0) == io) enabling lane-parallel COT in
  // AuthSharePool AND the leaky-AND garbled-AND row transfer here; null => single
  // mesh. L_lanes = the shared lane count.
  NetIOMPGroup<nP> *grp = nullptr;
  int L_lanes = 1;
  TriplePool(NetIOMP<nP> *io, ThreadPool *pool, int party, int ssp = 40,
             NetIOMPGroup<nP> *grp_in = nullptr,
             block session_id_in = zero_block,
             BaseOtKind base_ot_kind = BaseOtKind::CSW,
             int64_t planned_sender_cots = -1,
             int64_t planned_receiver_cots = -1)
      : pool(pool), party(party), ssp(ag::checked_statistical_security(ssp)), io(io),
        session_id(session_id_in),
        abit(io, pool, party, nullptr, grp_in, session_id_in, base_ot_kind,
             planned_sender_cots, planned_receiver_cots),
        Delta(abit.Delta),
        open_check_(io, pool, party, abit.Delta, session_id_in, &prg, grp_in),
        grp(grp_in), L_lanes(grp_in ? std::max(1, grp_in->size()) : 1) {}

  // The mesh carrying lane t (lane 0 == io == grp->mesh(0)); see AuthSharePool.
  NetIOMP<nP> *lane_mesh(int t) { return (t == 0) ? io : &grp->mesh(t); }

  // Canonical per-(peer,lane) transfer fan-out over the group meshes, into ONE join
  // barrier. Splits [0,n) into T=min(L_lanes,n) contiguous ag::lane_range slices; lane t
  // rides mesh t (lane 0 == mesh 0). `send_slice(ch,peer,lo,hi)` and `recv_slice(...)` do
  // the transfer for that slice on channel ch. Order = peer-major, lanes 0..T-1, send+recv
  // adjacent — THE deadlock-safe enqueue contract, defined once here for every bulk open
  // (d-vector, s-open, x/y). n==0 is a no-op; T==1 keeps everything on mesh 0.
  template <class SendF, class RecvF>
  void lane_fan_out(int n, SendF &&send_slice, RecvF &&recv_slice) {
    const int T = std::min(L_lanes, std::max(1, n));
    vector<future<void>> res;
    for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
      for (int t = 0; t < T; ++t) {
        auto pr = ag::lane_range(t, n, T);
        NetIOMP<nP> *ch = lane_mesh(t);
        res.push_back(pool->enqueue([&send_slice, ch, peer, pr]() { send_slice(ch, peer, pr.first, pr.second); }));
        res.push_back(pool->enqueue([&recv_slice, ch, peer, pr]() { recv_slice(ch, peer, pr.first, pr.second); }));
      }
    }
    joinNclean(res);
  }

  // The two NetIO channels behind NetIOMP for one peer (see netmp.h: the
  // smaller party drives `ios`, the larger drives `ios2`). send_data/recv_data
  // pick these; we reach them directly to send bit vectors via the channel's
  // packed send_bool/recv_bool (8 bits/byte) instead of one byte per bit.
  NetIO *send_ch(int dst) { return party < dst ? io->ios[dst] : io->ios2[dst]; }
  NetIO *recv_ch(int src) { return src < party ? io->ios[src] : io->ios2[src]; }

  // Bucket size B vs. batch length ℓ, provisioned from the independent-triple
  // first-moment leakage bound in crypto/bucketing.h. The same rule governs
  // every party count; functional correctness tests alone do not validate it.
  int get_bucket_size(int size) {
    return ag::bucket_size(size, ssp);
  }
  // Multi-party half-gate leaky-AND over one layer of L candidates. The layer is
  // laid out as a=[0,L), b=[L,2L), r/c=[2L,3L). On return r has been folded into
  // c=a AND b in the same scratch region. This layer's consistency-check
  // material is accumulated here; the caller finalizes the check over all layers.
  void produce_leaky_ands_halfgate(BlockVec tMAC[nP + 1],
                                   BlockVec tKEY[nP + 1], int L, FsHash &feq) {
    // Per-layer leaky-AND generator, generic in nP; the schedule calls it at nP>=3
    // (nP==2 runs produce_leaky_ands_halfgate_batch_2pc). FZero and the cross-party phi sum blind
    // the half-gate row, and every peer's row folds into tKEYphi[party] (the shared
    // result buffer) for the s-open, the d-combine, and the terminal-check
    // accumulation below.
    BlockVec(&tKEYphi)[nP + 1] = bkt_tKEYphi_;
    std::vector<unsigned char>(&s)[nP + 1] = bkt_s_;
    const int any_peer = (party == 1) ? 2 : 1;
    const int gb = ag::laand_window_bytes(ssp);
    const int gw = ag::laand_window_bits(ssp);
    block u_zero = zero_block;   // FZero blind (nP>2 only; bound by the batched check)
    for (int i = 0; i <= nP; ++i)
      if (s[i].size() < (size_t)L) s[i].resize((size_t)L);
    if (tKEYphi[party].size() < (size_t)L) tKEYphi[party].resize((size_t)L);

#ifdef AG_PROFILE
    uint64_t _tp_hg0 = agmpc_now_ns();
#endif
    // --- phi: the half-gate row correction (the blind C, generalized). At nP>2 it
    // starts from the FZero zero-share (carrying u_zero, bound by the batched check);
    // at nP==2 there is no FZero (z_u=0), so phi reduces to the bare local blind C. Then
    // add the (sel&Delta) term + the cross-peer key/mac sum (one peer at nP==2). ---
    BlockVec &phi = bkt_phi_;
    if (phi.size() < (size_t)L) phi.resize((size_t)L);
    if constexpr (nP > 2) {
      BlockVec &z_u = bkt_z_u_;
      if (z_u.size() < (size_t)(L + 1)) z_u.resize((size_t)(L + 1));
      std::fill(z_u.begin(), z_u.begin() + (L + 1), zero_block);  // fzero_xor XOR-accumulates
      fzero_xor<nP>(io, &prg, pool, party, z_u.data(), L + 1, bkt_fzero_);
      for (int k = 0; k < L; ++k) phi[k] = z_u[k];
      u_zero = z_u[L];
    } else {
      std::fill(phi.begin(), phi.begin() + L, zero_block);
    }
    int width = (L + pool->size() - 1) / pool->size();
    {
      vector<future<void>> res;
      for (int wi = 0; wi < (int)pool->size(); ++wi) {
        int st = wi * width, ed = std::min((wi + 1) * width, L);
        res.push_back(pool->enqueue([this, st, ed, L, any_peer, &tKEY, &tMAC, &phi]() {
          for (int k = st; k < ed; ++k) {
            phi[k] ^= (select_mask[getLSB(tMAC[any_peer][L + k])] & Delta);
            for (int j = 1; j <= nP; ++j) if (j != party) {
              phi[k] ^= tKEY[j][L + k];
              phi[k] ^= tMAC[j][L + k];
            }
          }
        }));
      }
      joinNclean(res);
    }

    // --- per-peer fused half-gate (MITCCRH hash_cir under the per-pair FS seed): one
    // peer at nP==2, n-1 in parallel at nP>2. The garbler ships row = H(key)^H(key^Delta)^phi
    // (low gw bits; F_eq / the windowed alpha check covers exactly that window). The
    // evaluator hashes [mac,key] -> HM,HK and folds the per-peer term HK ^ (HM ^ (w&sel))
    // ^ key[2L] ^ mac[2L] into tMACphi[peer]. ---
    BlockVec(&tMACphi)[nP + 1] = bkt_tMACphi_;
    for (int i = 1; i <= nP; ++i)
      if (i != party && tMACphi[i].size() < (size_t)L) tMACphi[i].resize((size_t)L);
    const int hg_chunk = ag::kLaandRowChunkRows;
#ifdef AG_PROFILE
    int64_t _phi0 = io->count();
#endif
    {
      // Per-lane CCR key salt in the FREE low 64:
      // MITCCRH derives its AES key as start_point ^ makeBlock(gid>>ReuseShift, 0) -- the gid
      // COUNTER marches through the HIGH 64 bits of the key, the LOW 64 are always 0 (free).
      // So salt each lane's seed in that free low 64: setS(seed ^ makeBlock(0, lane)) => key =
      // seed ^ makeBlock(bucket, lane) -- counter in the high 64, lane in the low 64, a
      // DISJOINT field, unique per (lane, bucket), no key reuse. Blackbox, one call, no
      // gid-range constraint; lane 0 salts by 0. The AND-index range [0,L) is split into
      // T=min(L_lanes,L) contiguous slices; lane t transfers slice t on mesh t (lane 0 ==
      // mesh 0), assembling into the disjoint tMACphi range so the check folds on the full
      // [0,L). Only the bulk row bytes move; control-message flights stay on mesh 0, while
      // local FS challenges snapshot every lane transcript before deriving one shared seed.

      // Sender half-gate row transfer for AND-index range [lo,hi) under lane `lane`, on ch.
      auto laand_send = [this, &tKEY, &phi, hg_chunk, gb, gw](NetIOMP<nP> *ch, int peer, block seed, int lo, int hi, int lane) {
        MITCCRH<> mitc;
        mitc.setS(seed ^ makeBlock(0, (uint64_t)lane));   // lane in the free low 64 of the key
        block pad[16];
        const int len = hi - lo;
        std::vector<unsigned char> gbuf((size_t)std::min(hg_chunk, len) * gb);
        std::vector<unsigned char> packed(ag::laand_row_wire_bytes(std::min(hg_chunk, len), gw));
        for (int ci = 0; ci < (len + hg_chunk - 1) / hg_chunk; ++ci) {
          int st = lo + hg_chunk * ci, ed = std::min(lo + hg_chunk * (ci + 1), hi);
          for (int k0 = st; k0 < ed; k0 += 8) {
            int batch = std::min(8, ed - k0);
            for (int j = 0; j < 8; ++j) {
              block kk = (j < batch) ? tKEY[peer][k0 + j] : zero_block;
              pad[2 * j]     = kk;
              pad[2 * j + 1] = kk ^ Delta;
            }
            mitc.hash_cir<8, 2>(pad);
            for (int j = 0; j < batch; ++j) {
              block row = pad[2 * j] ^ pad[2 * j + 1] ^ phi[k0 + j];   // full G row
              memcpy(gbuf.data() + (size_t)(k0 + j - st) * gb, &row, gb); // packed to gw bits below
            }
          }
#ifdef EMP_AG_TEST_FLIP_LAAND
          // TEST-ONLY (never in production): a malicious party 2 flips bit 0 of EVERY leaky-AND
          // row it ships to party 1, so P1's tKEYphi diverges. The leaky-AND consistency check
          // (the batched windowed-alpha RLC) must abort during preprocessing. Every row, because
          // P1 folds a row in only when its own selector bit for that AND is 1: a single faulty
          // row is masked away half the time, while with every row faulty the fault stays hidden
          // only if all B*L of P1's selectors are 0. Only ONE sender flips: P1 folds every
          // sender's row under the same selector bit, so if all nP-1 senders flipped, the copies
          // would cancel in the XOR-combined tKEYphi whenever nP-1 is even (nP = 3 here), a
          // false negative that hides the fault.
          if (party == 2 && peer == 1)
            for (int r = 0; r < ed - st; ++r) gbuf[(size_t)r * gb] ^= 0x1;
#endif
          ag::pack_laand_rows(packed.data(), gbuf.data(), ed - st, gw);
          ch->send_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
          ch->flush(peer);
        }
      };

      // Receiver: recompute tMACphi[peer][k] for k in [lo,hi) from the shipped rows on ch.
      auto laand_recv = [this, &tMAC, &tKEY, &tMACphi, any_peer, L, hg_chunk, gb, gw](NetIOMP<nP> *ch, int peer, block seed, int lo, int hi, int lane) {
        MITCCRH<> mitc;
        mitc.setS(seed ^ makeBlock(0, (uint64_t)lane));   // lane in the free low 64 of the key
        block pad[16];
        const int len = hi - lo;
        BlockVec wire(std::min(hg_chunk, len));
        std::vector<unsigned char> gbuf((size_t)std::min(hg_chunk, len) * gb);
        std::vector<unsigned char> packed(ag::laand_row_wire_bytes(std::min(hg_chunk, len), gw));
        for (int ci = 0; ci < (len + hg_chunk - 1) / hg_chunk; ++ci) {
          int st = lo + hg_chunk * ci, ed = std::min(lo + hg_chunk * (ci + 1), hi);
          ch->recv_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
          expecting(ag::unpack_laand_rows(gbuf.data(), packed.data(), ed - st, gw),
                    "LaAND row has nonzero padding");
          for (int r = 0; r < ed - st; ++r) {   // zero-extend each gb-byte row to a block
            wire[r] = zero_block;
            memcpy(&wire[r], gbuf.data() + (size_t)r * gb, gb);
          }
          for (int k0 = st; k0 < ed; k0 += 8) {
            int batch = std::min(8, ed - k0);
            for (int j = 0; j < 8; ++j) {
              pad[2 * j]     = (j < batch) ? tMAC[peer][k0 + j] : zero_block;  // -> H(M)
              pad[2 * j + 1] = (j < batch) ? tKEY[peer][k0 + j] : zero_block;  // -> H(K)
            }
            mitc.hash_cir<8, 2>(pad);
            for (int j = 0; j < batch; ++j) {
              int k = k0 + j;
              block HM = pad[2 * j], HK = pad[2 * j + 1];
              block E = HM ^ (wire[k - st] & select_mask[getLSB(tMAC[any_peer][k])]);
              tMACphi[peer][k] = HK ^ E ^ tKEY[peer][2 * L + k] ^ tMAC[peer][2 * L + k];
            }
          }
        }
      };

      // The leaky-AND transfer keeps its own fan-out (one per-peer seed shared by all
      // lanes) rather than lane_fan_out, but uses the shared ag::lane_range.
      int T = std::min(L_lanes, std::max(1, L));   // T_eff = min(lanes, L): no empty slice

      vector<future<void>> res;
      for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
        // Snapshot both directed transcripts from every mesh, then share the resulting
        // per-peer seed across lanes (the lane id further domain-separates the CCR key).
        block seed = fs_coin_pair_group<nP>(
            io, grp, peer, "AGMPC laand seed", session_id);
        for (int t = 0; t < T; ++t) {   // canonical order: peer-major, lanes 0..T-1, dir-adjacent
          auto [lo, hi] = ag::lane_range(t, L, T);
          NetIOMP<nP> *ch = lane_mesh(t);
          res.push_back(pool->enqueue([&laand_send, ch, peer, seed, lo, hi, t]() { laand_send(ch, peer, seed, lo, hi, t); }));
          res.push_back(pool->enqueue([&laand_recv, ch, peer, seed, lo, hi, t]() { laand_recv(ch, peer, seed, lo, hi, t); }));
        }
      }
      joinNclean(res);   // all-lane flush barrier: every lane's send+recv joined before draw_coins
    }
#ifdef AG_PROFILE
    g_ag_phi_bytes += (uint64_t)(io->count() - _phi0);
#endif

    // --- combine: sum the per-peer terms (one peer at nP==2) + the global phi/Delta
    // correction -> the leaky-AND result in tKEYphi[party]. ---
    {
      vector<future<void>> res;
      for (int wi = 0; wi < (int)pool->size(); ++wi) {
        int st = wi * width, ed = std::min((wi + 1) * width, L);
        res.push_back(pool->enqueue([this, st, ed, L, any_peer, &tKEYphi, &tMACphi, &tMAC, &phi]() {
          for (int k = st; k < ed; ++k) {
            block t = zero_block;
            for (int j = 1; j <= nP; ++j) if (j != party) t = t ^ tMACphi[j][k];
            t = t ^ (phi[k] & select_mask[getLSB(tMAC[any_peer][k])]);
            t = t ^ (Delta & select_mask[getLSB(tMAC[any_peer][2 * L + k])]);
            tKEYphi[party][k] = t;
          }
        }));
      }
      joinNclean(res);
    }
#ifdef AG_PROFILE
    g_ag_tp_hg_ns += agmpc_now_ns() - _tp_hg0;
    uint64_t _tp_so0 = agmpc_now_ns();
#endif

    // s-open (shared): d = LSB1(result). Exchange this party's s with every peer,
    // lane-split across the meshes. This runs before draw_coins and is covered by the
    // same all-bytes-on-wire-before-draw_coins ordering as the leaky-AND rows above
    // (this join completes before produce_leaky_ands_halfgate returns). Combine stays
    // on assembled s[].
    {
      for (int k = 0; k < L; ++k)
        s[party][k] = LSB1(tKEYphi[party][k]);
      lane_fan_out(L,
        [this, &s](NetIOMP<nP> *ch, int peer, int lo, int hi) {
          ch->send_bool(peer, (const bool *)(s[party].data() + lo), hi - lo);
          ch->flush(peer);
        },
        [this, &s](NetIOMP<nP> *ch, int peer, int lo, int hi) {
          ch->recv_bool(peer, (bool *)(s[peer].data() + lo), hi - lo);
        });
    }

#ifdef AG_PROFILE
    g_ag_tp_sopen_ns += agmpc_now_ns() - _tp_so0;
    uint64_t _tp_ac0 = agmpc_now_ns();
#endif
    // d-combine (shared): fold d = ⊕_p s_p into region 2 (r -> c) and the result
    // vector. Width-split: every write is k-indexed (s[0][k], the 2L+k share slots,
    // T[k]) and every read is done, so ranges are race-free and the split matches
    // the serial loop.
    {
      block *T = tKEYphi[party].data();
      block dxor = Delta ^ bit0_mask;
      ag::parallel_for(pool, L, [&](int lo, int hi) {
        for (int k = lo; k < hi; ++k) {
          s[0][k] = 0;
          for (int i = 1; i <= nP; ++i)
            s[0][k] = (s[0][k] != s[i][k]);
          block mask_s = select_mask[s[0][k]];
          if (party == 1) {
            if (s[0][k]) {
              for (int j = 1; j <= nP; ++j) if (j != party)
                tMAC[j][2 * L + k] = tMAC[j][2 * L + k] ^ bit0_mask;
            }
          } else {
            tKEY[1][2 * L + k] = tKEY[1][2 * L + k] ^ (dxor & mask_s);
          }
          T[k] = T[k] ^ (Delta & mask_s);
        }
      });
    }

    // Terminal-check accumulation: batched per bucket. Each layer accumulates its
    // windowed check object; ONE terminal check fires per bucket in compute_and_shares,
    // with its coin drawn only after every layer is generated.
    if constexpr (nP == 2) {
      // F_eq: fold the low-gw-bit window of this layer's L-vector into the running hash;
      // one terminal feq_check fires in compute_and_shares. The hash over the whole
      // windowed vector IS the check.
      ag::accumulate_leaky_and_window(feq, &tKEYphi[party][0], L, gw, bkt_window_, pool);
    } else {
      // nP>=3: STASH this layer's windowed RLC vector (the high bits are not
      // reconciled cross-party once G is truncated; both ends zero them) + its
      // FZero u_zero. The single B*L GF(2^128) RLC zero-sum runs once per bucket in
      // compute_and_shares over ALL B layers -- tighter than B per-layer checks by a
      // factor B, and the challenge is drawn post-commitment (after the whole B*L
      // set is on the wire).
      const block window_mask = ag::laand_window_mask(ssp);
      size_t off = alpha_masked_cat_.size();
      alpha_masked_cat_.resize(off + (size_t)L);
      for (int k = 0; k < L; ++k)
        alpha_masked_cat_[off + k] = tKEYphi[party][k] & window_mask;
#ifdef EMP_AG_TEST_FLIP_LAAND_HIGH
      // TEST-ONLY: corrupt the highest retained coordinate of exactly one
      // local check input. Unlike a shipped-row fault, no selector masks it away.
      if (party == 1 && off == 0 && L > 0) {
        unsigned char fault[sizeof(block)] = {};
        fault[(gw - 1) / 8] = 1u << ((gw - 1) % 8);
        block delta;
        memcpy(&delta, fault, sizeof(delta));
        alpha_masked_cat_[off] ^= delta;
      }
#endif
      alpha_uzero_.push_back(u_zero);
    }
#ifdef AG_PROFILE
    g_ag_tp_acheck_ns += agmpc_now_ns() - _tp_ac0;
#endif
  }

  // Two-party batched LaAND schedule: every layer's COTs are fixed first, one
  // transcript root domain-separates the B row seeds, all rows cross in one
  // flight, and all dependent s bits cross in the next.
  void produce_leaky_ands_halfgate_batch_2pc(
      BlockVec accMAC[nP + 1], BlockVec accKEY[nP + 1],
      std::vector<std::vector<BlockVec>> &sac_macs,
      std::vector<std::vector<BlockVec>> &sac_keys,
      int B, int L, FsHash &feq) {
    if constexpr (nP == 2) {
      const int peer = (party == 1) ? 2 : 1;
      const int gb = ag::laand_window_bytes(ssp);
      const int gw = ag::laand_window_bits(ssp);
      const int BL = B * L;
      auto layer_mac = [&](int k) -> BlockVec * {
        return k == 0 ? accMAC : sac_macs[k].data();
      };
      auto layer_key = [&](int k) -> BlockVec * {
        return k == 0 ? accKEY : sac_keys[k].data();
      };

      // Once all COT material is fixed, snapshot one transcript root and RO-expand
      // it by the public batch shape and layer index.  Each layer restarts MITCCRH's
      // gid, so the layer separation is load-bearing.
      const block root = fs_coin_pair_group<nP>(
          io, grp, peer, "AGMPC laand batch seed", session_id);
      std::vector<block> layer_seed(B);
      for (int k = 0; k < B; ++k)
        layer_seed[k] =
            RO("emp-ag:laand-layer-seed", session_id)
                .absorb(root)
                .absorb((uint64_t)B)
                .absorb((uint64_t)L)
                .absorb((uint64_t)k)
                .squeeze_block();

      // Keep only the gb-byte T window needed after the bulk s open. phi is a
      // cheap local expression over resident layer material, so each direction
      // recomputes it instead of retaining B*L extra blocks.
      if (bkt_window_.size() < (size_t)BL * gb)
        bkt_window_.resize((size_t)BL * gb);
      std::vector<unsigned char>(&s)[nP + 1] = bkt_s_;
      for (int p = 1; p <= nP; ++p)
        if (s[p].size() < (size_t)BL) s[p].resize((size_t)BL);

#ifdef AG_PROFILE
      uint64_t _tp_hg0 = agmpc_now_ns();
      int64_t _phi0 = io->count();
#endif
      // One task per (lane,direction) walks every layer in canonical order.
      // Do not enqueue per-layer tasks on one NetIO: their writes could interleave.
      const int hg_chunk = ag::kLaandRowChunkRows;
      int T = std::min(L_lanes, std::max(1, L));
      vector<future<void>> rows;
      for (int lane = 0; lane < T; ++lane) {
        auto [lo, hi] = ag::lane_range(lane, L, T);
        NetIOMP<nP> *ch = lane_mesh(lane);
        rows.push_back(pool->enqueue([&, ch, lane, lo, hi]() {
          const int len = hi - lo;
          std::vector<unsigned char> gbuf((size_t)std::min(hg_chunk, len) * gb);
          std::vector<unsigned char> packed(ag::laand_row_wire_bytes(std::min(hg_chunk, len), gw));
          block pad[16];
          for (int layer = 0; layer < B; ++layer) {
            BlockVec *mac = layer_mac(layer);
            BlockVec *key = layer_key(layer);
            MITCCRH<> mitc;
            mitc.setS(layer_seed[layer] ^ makeBlock(0, (uint64_t)lane));
            for (int st = lo; st < hi; st += hg_chunk) {
              const int ed = std::min(st + hg_chunk, hi);
              for (int k0 = st; k0 < ed; k0 += 8) {
                const int batch = std::min(8, ed - k0);
                for (int j = 0; j < 8; ++j) {
                  const block kk = (j < batch) ? key[peer][k0 + j] : zero_block;
                  pad[2 * j] = kk;
                  pad[2 * j + 1] = kk ^ Delta;
                }
                mitc.hash_cir<8, 2>(pad);
                for (int j = 0; j < batch; ++j) {
                  const int k = k0 + j;
                  const block phi =
                      (select_mask[getLSB(mac[peer][L + k])] & Delta) ^
                      key[peer][L + k] ^ mac[peer][L + k];
                  const block row = pad[2 * j] ^ pad[2 * j + 1] ^ phi;
                  memcpy(gbuf.data() + (size_t)(k0 + j - st) * gb, &row, gb);
                }
              }
              ag::pack_laand_rows(packed.data(), gbuf.data(), ed - st, gw);
              ch->send_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
            }
          }
          ch->flush(peer);
        }));
        rows.push_back(pool->enqueue([&, ch, lane, lo, hi]() {
          const int len = hi - lo;
          std::vector<unsigned char> gbuf((size_t)std::min(hg_chunk, len) * gb);
          std::vector<unsigned char> packed(ag::laand_row_wire_bytes(std::min(hg_chunk, len), gw));
          BlockVec wire(std::min(hg_chunk, len));
          block pad[16];
          for (int layer = 0; layer < B; ++layer) {
            BlockVec *mac = layer_mac(layer);
            BlockVec *key = layer_key(layer);
            MITCCRH<> mitc;
            mitc.setS(layer_seed[layer] ^ makeBlock(0, (uint64_t)lane));
            for (int st = lo; st < hi; st += hg_chunk) {
              const int ed = std::min(st + hg_chunk, hi);
              ch->recv_data(peer, packed.data(), ag::laand_row_wire_bytes(ed - st, gw));
              expecting(ag::unpack_laand_rows(gbuf.data(), packed.data(), ed - st, gw),
                        "LaAND row has nonzero padding");
              for (int r = 0; r < ed - st; ++r) {
                wire[r] = zero_block;
                memcpy(&wire[r], gbuf.data() + (size_t)r * gb, gb);
              }
              for (int k0 = st; k0 < ed; k0 += 8) {
                const int batch = std::min(8, ed - k0);
                for (int j = 0; j < 8; ++j) {
                  pad[2 * j] = (j < batch) ? mac[peer][k0 + j] : zero_block;
                  pad[2 * j + 1] =
                      (j < batch) ? key[peer][k0 + j] : zero_block;
                }
                mitc.hash_cir<8, 2>(pad);
                for (int j = 0; j < batch; ++j) {
                  const int k = k0 + j;
                  const block E =
                      pad[2 * j] ^
                      (wire[k - st] & select_mask[getLSB(mac[peer][k])]);
                  block value = pad[2 * j + 1] ^ E ^ key[peer][2 * L + k] ^
                                mac[peer][2 * L + k];
                  const block phi =
                      (select_mask[getLSB(mac[peer][L + k])] & Delta) ^
                      key[peer][L + k] ^ mac[peer][L + k];
                  value ^= phi & select_mask[getLSB(mac[peer][k])];
                  value ^= Delta & select_mask[getLSB(mac[peer][2 * L + k])];
#ifdef EMP_AG_TEST_FLIP_LAAND
                  // Deterministically corrupt ONE late-layer receiver value.
                  // Flipping a shipped row is masked away when its random selector
                  // is zero, which makes an ell==1 adversarial test probabilistic.
                  if (layer == B - 1 && k == 0 && party == 1 && lane == 0)
                    value ^= bit0_mask;
#endif
#ifdef EMP_AG_TEST_FLIP_LAAND_HIGH
                  // TEST-ONLY: the partial last byte must remain covered by F_eq.
                  if (layer == B - 1 && k == 0 && party == 1 && lane == 0) {
                    unsigned char fault[sizeof(block)] = {};
                    fault[(gw - 1) / 8] = 1u << ((gw - 1) % 8);
                    block delta;
                    memcpy(&delta, fault, sizeof(delta));
                    value ^= delta;
                  }
#endif
                  const size_t flat = (size_t)layer * L + k;
                  s[party][flat] = LSB1(value);
                  memcpy(bkt_window_.data() + flat * gb, &value, gb);
                }
              }
            }
          }
        }));
      }
      joinNclean(rows);
#ifdef AG_PROFILE
      g_ag_phi_bytes += (uint64_t)(io->count() - _phi0);
      g_ag_tp_hg_ns += agmpc_now_ns() - _tp_hg0;
      uint64_t _tp_so0 = agmpc_now_ns();
#endif

      // The single dependent flight: open every layer's s vector together.
      lane_fan_out(BL,
        [this, &s](NetIOMP<nP> *ch, int dst, int lo, int hi) {
          ch->send_bool(dst, (const bool *)(s[party].data() + lo), hi - lo);
          ch->flush(dst);
        },
        [this, &s](NetIOMP<nP> *ch, int src, int lo, int hi) {
          ch->recv_bool(src, (bool *)(s[src].data() + lo), hi - lo);
        });
#ifdef AG_PROFILE
      g_ag_tp_sopen_ns += agmpc_now_ns() - _tp_so0;
      uint64_t _tp_ac0 = agmpc_now_ns();
#endif

      const block dxor = Delta ^ bit0_mask;
      unsigned char delta_bytes[sizeof(block)];
      memcpy(delta_bytes, &Delta, sizeof(block));
      for (int layer = 0; layer < B; ++layer) {
        BlockVec *mac = layer_mac(layer);
        BlockVec *key = layer_key(layer);
        unsigned char *window =
            bkt_window_.data() + (size_t)layer * L * gb;
        ag::parallel_for(pool, L, [&](int lo, int hi) {
          for (int k = lo; k < hi; ++k) {
            const size_t flat = (size_t)layer * L + k;
            const unsigned char opened = s[1][flat] ^ s[2][flat];
            if (opened) {
              if (party == 1)
                mac[peer][2 * L + k] ^= bit0_mask;
              else
                key[1][2 * L + k] ^= dxor;
              for (int j = 0; j < gb; ++j)
                window[(size_t)k * gb + j] ^= delta_bytes[j];
            }
            // The equality check must bind exactly the transmitted bit window,
            // including after the local Delta correction above.
            window[(size_t)(k + 1) * gb - 1] &= ag::laand_last_byte_mask(gw);
          }
        });
        ag::accumulate_leaky_and_window_bytes(feq, window, L, gb, pool);
      }
#ifdef AG_PROFILE
      g_ag_tp_acheck_ns += agmpc_now_ns() - _tp_ac0;
#endif
    }
  }

  void mint_random_leaky_layer(BlockVec layerMAC[nP + 1],
                               BlockVec layerKEY[nP + 1], int L) {
#ifdef AG_PROFILE
    uint64_t _tp_c0 = agmpc_now_ns();
#endif
    abit.compute(layerMAC, layerKEY, 3 * L);
#ifdef AG_PROFILE
    g_ag_tp_cot_ns += agmpc_now_ns() - _tp_c0;
#endif
  }

  void generate_random_leaky_layer(BlockVec layerMAC[nP + 1],
                                   BlockVec layerKEY[nP + 1], int L, FsHash &feq) {
    mint_random_leaky_layer(layerMAC, layerKEY, L);
    produce_leaky_ands_halfgate(layerMAC, layerKEY, L, feq);
  }

  // The BucketPolicy: the n-party seams behind the shared batched schedule
  // (run_bucketing_core, above). This policy generates all B independent random
  // layers, using accMAC/accKEY for layer 0 and separate per-peer buffers for the
  // B-1 sacrifice layers. It also owns the NetIOMP mesh d-exchange + cross-peer
  // fold, the F_coin (fs_coin_pair / sampleRandom), and the terminal check.
  // nP==2 finalizes with feq_check; nP>=3 with the ONE batched RLC zero-sum over
  // the stashed windowed alpha vectors, its
  // challenge phi_cat CONTINUING the post-shift PRG stream (so it rides the same
  // post-commitment coin as the shifts).
  struct BucketPolicy {
    TriplePool *tp;
    BlockVec *accMAC, *accKEY;   // layer 0 (per-peer accumulator slots)
    int L, B, any_peer;
    FsHash *feq;
    std::vector<std::vector<BlockVec>> &sac_macs, &sac_keys;  // tp's reused [B][nP+1]
    // tp's reused (B-1)*L d-vectors: d[p] is party p's shares as sent, d[0] the
    // combined public d (the parties' shares stay intact for the open check).
    std::vector<unsigned char> (&d)[nP + 1];
    FeqSymmetric2PC feq2;                                     // nP==2 only
    std::vector<int> &shift_;   // tp's: layer k's cyclic shift, for checking its d-bits
    typename OpenCheck::Run d_run_{};   // pairwise check: its run over all (B-1)*L d-bits

    BucketPolicy(TriplePool *tp, BlockVec *accMAC, BlockVec *accKEY, int L, int B,
                 FsHash &feq, int any_peer)
        : tp(tp), accMAC(accMAC), accKEY(accKEY), L(L), B(B), any_peer(any_peer),
          feq(&feq), sac_macs(tp->bkt_sac_macs_), sac_keys(tp->bkt_sac_keys_),
          d(tp->bkt_bd_), shift_(tp->bkt_shift_) {
      shift_.assign(B, 0);
      if ((int)sac_macs.size() < B) { sac_macs.resize(B); sac_keys.resize(B); }
      for (int p = 0; p <= nP; ++p)
        if (d[p].size() < (size_t)(B - 1) * L) d[p].resize((size_t)(B - 1) * L);
    }

    void ensure_layer_(int k) {
      if ((int)sac_macs[k].size() < nP + 1) {
        sac_macs[k].resize(nP + 1);
        sac_keys[k].resize(nP + 1);
      }
    }

    // Generate all B layers independently: each receives 3L fresh shares,
    // including layer 0. At nP==2, mint every COT first and batch all layers into
    // two flights. Multiparty keeps its per-layer FZero/check schedule.
    void generate_layers() {
      if constexpr (nP == 2) {
        tp->mint_random_leaky_layer(accMAC, accKEY, L);
        for (int k = 1; k < B; ++k) {
          ensure_layer_(k);
          tp->mint_random_leaky_layer(sac_macs[k].data(), sac_keys[k].data(), L);
        }
        tp->produce_leaky_ands_halfgate_batch_2pc(
            accMAC, accKEY, sac_macs, sac_keys, B, L, *feq);
      } else {
        tp->generate_random_leaky_layer(accMAC, accKEY, L, *feq);
        for (int k = 1; k < B; ++k) {
          ensure_layer_(k);
          tp->generate_random_leaky_layer(sac_macs[k].data(), sac_keys[k].data(),
                                          L, *feq);
        }
      }
    }

    // ONE post-commitment coin: FS (nP==2) / sampleRandom (nP>=3).
    block draw_coins() {
      block c;
      if constexpr (nP == 2)
        c = fs_coin_pair_group<nP>(tp->io, tp->grp, any_peer,
                                   "AGMPC bucket", tp->session_id);
      else c = sampleRandom<nP>(tp->io, &tp->prg, tp->pool, tp->party,
                                tp->session_id);
      // Piggyback the half-gate hash seed off this ONE post-commitment coin: a single
      // extra domain-separated squeeze, no new round and no dedicated seed coin. Every
      // party folds the SAME coin here, so the evaluator's half-gate re-hash matches
      // each garbler. Consumed by AGMPCProtocol::draw_and_seed via ctx.halfgate_seed.
      tp->halfgate_seed_ = fs_coin("AGMPC halfgate seed", c, zero_block);
      return c;
    }

    // Width-split one layer's folds across the pool, peer-major: each task owns
    // one peer's [i0, i1) output range (streams only that peer's acc/sac arrays),
    // and the d-bit fill rides alongside (it reads the b-region, which no fold
    // writes). One join per layer; layers stay ordered because both RMW the same
    // acc slots.
    void fold_ranges_(int L_, const std::function<void(int, int, int)> &body) {
      const int nPeers = nP - 1;
      const int per_peer = std::max(1, (int)tp->pool->size() / nPeers);
      const int step = (L_ + per_peer - 1) / per_peer;
      vector<future<void>> fres;
      for (int peer = 1; peer <= nP; ++peer) if (peer != tp->party)
        for (int i0 = 0; i0 < L_; i0 += step) {
          const int i1 = std::min(i0 + step, L_);
          fres.push_back(tp->pool->enqueue([&body, peer, i0, i1]() {
            body(peer, i0, i1);
          }));
        }
      joinNclean(fres);
    }
    void fold_pre_and_dbit(int k, int sh) {
      shift_[k] = sh;
      if constexpr (OpenCheck::kPerPeerOperands)
        if (k == 1) d_run_ = tp->open_check_.begin((int64_t)(B - 1) * L);
      unsigned char *dk = d[tp->party].data() + (size_t)(k - 1) * L;
      fold_ranges_(L, [this, k, sh, dk](int peer, int i0, int i1) {
        ag::bucket_fold_pre_ac(accMAC[peer].data(), accKEY[peer].data(),
                               sac_macs[k][peer].data(), sac_keys[k][peer].data(), L,
                               sh, i0, i1);
        if constexpr (OpenCheck::kPerPeerOperands) {
          // One load of the two b-region MACs gives both the d-bit (their bit 0) and
          // this party's open-check tag on it to peer.
          auto lane = tp->open_check_.lane(d_run_);
          const block *am = accMAC[peer].data() + L, *lm = sac_macs[k][peer].data() + L;
          const int64_t base = (int64_t)(k - 1) * L;
          for (int i = i0; i < i1; ++i) {
            const block m = am[i] ^ lm[ag::bucket_fold_src(i, L, sh)];
            if (peer == any_peer) dk[i] = (unsigned char)getLSB(m);
            lane.sent(peer, base + i, m);
          }
          tp->open_check_.merge(lane);
        } else if (peer == any_peer) {
          ag::bucket_fold_dbit(accMAC[any_peer].data(), sac_macs[k][any_peer].data(),
                               L, sh, dk, i0, i1);
        }
      });
    }
    // ONE all-to-all mesh exchange of the full (B-1)*L d-vector + cross-peer fold.
    void exchange_all_d() {
      const int BLd = (B - 1) * L;
      if constexpr (nP == 2) {
        char Dme[FsHash::DIGEST_SIZE];
        feq->digest(Dme);
        feq2 = feq_prepare_symmetric_2pc(
            &tp->prg, tp->session_id, "emp-ag:laand", tp->party, Dme);
      }
#ifdef AG_PROFILE
      uint64_t _b0 = agmpc_now_ns();
#endif
#ifdef EMP_AG_TEST_FLIP_D
      // TEST-ONLY (never in production): a malicious party 2 flips its share of the
      // first d-bit and sends the flipped share to everyone, keeping it itself, so every
      // party combines the same wrong d. The open check must abort.
      if (tp->party == 2 && BLd > 0) d[tp->party][0] ^= 1;
#endif
      // Lane-split the d-vector transfer across the group meshes: it is a plain
      // bit-vector (no keying, no coin reads it), and the XOR-combine below runs on the
      // assembled d[] after the one join.
      tp->lane_fan_out(BLd,
        [this](NetIOMP<nP> *ch, int peer, int lo, int hi) {
          ch->send_bool(peer, (const bool *)(d[tp->party].data() + lo), hi - lo);
          if constexpr (nP == 2)
            if (ch == tp->io)
              ch->send_data(peer, feq2.commitment, FsHash::DIGEST_SIZE);
          ch->flush(peer);
        },
        [this](NetIOMP<nP> *ch, int peer, int lo, int hi) {
          ch->recv_bool(peer, (bool *)(d[peer].data() + lo), hi - lo);
          if constexpr (nP == 2)
            if (ch == tp->io)
              ch->recv_data(peer, feq2.peer_commitment, FsHash::DIGEST_SIZE);
        });
      // Combined public d = XOR over all parties, into d[0]; every d[p] stays as sent,
      // for the open check. Layer k's d-bit at position i is a share of
      // b_acc[i] ^ b_k[src], authenticated by the XOR of those two MACs (keys). The
      // pairwise check took this party's tags in fold_pre_and_dbit and takes the
      // peers' in fold_post; the symmetric check folds the d-bits after its coin, in
      // compute_and_shares. Plain range split (NOT fold_ranges_, which is peer-major);
      // d[0] ranges are disjoint across tasks.
      ag::parallel_for(tp->pool, BLd, [this](int j0, int j1) {
        for (int j = j0; j < j1; ++j) {
          unsigned char v = 0;
          for (int p = 1; p <= nP; ++p) v ^= d[p][j];
          d[0][j] = v;
        }
      });
#ifdef AG_PROFILE
      g_ag_tp_bkt_ns += agmpc_now_ns() - _b0;
#endif
    }
    void fold_post(int k, int sh) {
      const unsigned char *dk = d[0].data() + (size_t)(k - 1) * L;
      fold_ranges_(L, [this, k, sh, dk](int peer, int i0, int i1) {
        ag::bucket_fold_post(accMAC[peer].data(), accKEY[peer].data(),
                             sac_macs[k][peer].data(), sac_keys[k][peer].data(), L, sh,
                             dk, i0, i1);
        if constexpr (OpenCheck::kPerPeerOperands) {
          // The tag peer owes this party on its d shares, from this party's keys on
          // the two b-regions and the bits peer sent.
          auto lane = tp->open_check_.lane(d_run_);
          const block *ak = accKEY[peer].data() + L, *lk = sac_keys[k][peer].data() + L;
          const unsigned char *pb = d[peer].data() + (size_t)(k - 1) * L;
          const int64_t base = (int64_t)(k - 1) * L;
          for (int i = i0; i < i1; ++i)
            lane.expected(peer, base + i, ak[i] ^ lk[ag::bucket_fold_src(i, L, sh)], pb[i]);
          tp->open_check_.merge(lane);
        }
      });
    }
    // nP>=3: ONE batched RLC zero-sum over all B layers' stashed windowed alpha
    // vectors (phi_cat continues the post-shift PRG). nP==2: terminal feq_check.
    void finalize_check(PRG &prg) {
      const int party = tp->party;
      if constexpr (nP >= 3) {
        const int BL = (int)tp->alpha_masked_cat_.size();   // = B * L
        BlockVec &phi_cat = tp->bkt_phi_cat_;
        if (phi_cat.size() < (size_t)BL) phi_cat.resize((size_t)BL);
        prg.random_block(phi_cat.data(), BL);
        BlockVec ip[nP + 1];
        for (int i = 0; i <= nP; ++i) ip[i].resize(2);
        // Batched-RLC inner product over all B*L stashed alpha vectors.
        // Split into partial (lo,hi) sums and XOR-combine: GF(2^128) addition is
        // XOR and the product sum has no reduction here, so the split is
        // byte-identical to the sequential inner product.
        {
          const int W = std::max(1, (int)tp->pool->size());
          const int width = (BL + W - 1) / W;
          std::vector<block> acc_lo(W, zero_block), acc_hi(W, zero_block);
          vector<future<void>> rres;
          int t = 0;
          for (int a = 0; a < BL; a += width, ++t) {
            const int b = std::min(a + width, BL);
            rres.push_back(tp->pool->enqueue([&, a, b, t]() {
              block part[2];
              vector_inn_prdt_sum_no_red(part, phi_cat.data() + a,
                                         tp->alpha_masked_cat_.data() + a, b - a);
              acc_lo[t] = part[0];
              acc_hi[t] = part[1];
            }));
          }
          joinNclean(rres);
          ip[party][0] = zero_block;
          ip[party][1] = zero_block;
          for (int w = 0; w < t; ++w) {
            ip[party][0] = ip[party][0] ^ acc_lo[w];
            ip[party][1] = ip[party][1] ^ acc_hi[w];
          }
        }
        block uz = zero_block;
        for (block u : tp->alpha_uzero_) uz = uz ^ u;   // all B layers, incl. rep
        ip[party][0] = ip[party][0] ^ uz;
        char dgst[nP + 1][FsHash::DIGEST_SIZE];
        role_bound_commitment(dgst[party], tp->session_id,
                              "emp-ag:laand-alpha", party,
                              ip[party].data(), sizeof(block) * 2);
        vector<future<void>> ares;
        for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
          ares.push_back(tp->pool->enqueue([this, &dgst, peer, party]() {
            tp->io->send_data(peer, dgst[party], FsHash::DIGEST_SIZE);
            tp->io->flush(peer);
          }));
          ares.push_back(tp->pool->enqueue([this, &dgst, peer]() {
            tp->io->recv_data(peer, dgst[peer], FsHash::DIGEST_SIZE);
          }));
        }
        joinNclean(ares);
        char view_digest[FsHash::DIGEST_SIZE];
        FsHash::hash_once(view_digest, dgst[1], nP * FsHash::DIGEST_SIZE);
        char peer_view[nP + 1][FsHash::DIGEST_SIZE];
        vector<future<bool>> ares2;
        for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
          ares.push_back(tp->pool->enqueue([this, &ip, &view_digest, peer, party]() {
            tp->io->send_data(peer, ip[party].data(), sizeof(block) * 2);
            tp->io->send_data(peer, view_digest, FsHash::DIGEST_SIZE);
            tp->io->flush(peer);
          }));
          ares2.push_back(tp->pool->enqueue(
              [this, &ip, &dgst, &peer_view, &view_digest, peer]() -> bool {
            tp->io->recv_data(peer, ip[peer].data(), sizeof(block) * 2);
            tp->io->recv_data(peer, peer_view[peer], FsHash::DIGEST_SIZE);
            char chk[FsHash::DIGEST_SIZE];
            role_bound_commitment(chk, tp->session_id,
                                  "emp-ag:laand-alpha", peer,
                                  ip[peer].data(), sizeof(block) * 2);
            return memcmp(chk, dgst[peer], FsHash::DIGEST_SIZE) != 0 ||
                   memcmp(view_digest, peer_view[peer],
                          FsHash::DIGEST_SIZE) != 0;
          }));
        }
        joinNclean(ares);
        expecting(!joinNcleanCheat(ares2), "LaAND alpha: commit-open mismatch");
        for (int i = 2; i <= nP; ++i)
          xorBlocks_arr(ip[1].data(), ip[1].data(), ip[i].data(), 2);
        expecting(cmpBlock(&ip[1][0], &zero_block, 1) &&
                  cmpBlock(&ip[1][1], &zero_block, 1),
                  "LaAND alpha: Sigma alpha != 0");
      }
      if constexpr (nP == 2) {
        feq_finish_symmetric_2pc(
            tp->send_ch(any_peer), tp->recv_ch(any_peer), tp->session_id,
            "emp-ag:laand", party, feq2,
            "AGMPC LaAND F_eq: leaky-AND check failed");
      }
    }
  };

  // Validate before the circuit walk draws output masks, and again at the
  // standalone compute_and_shares entry point. This has no preprocessing state.
  int validate_batch_length(int length) {
    expecting(length >= 0, "triple_pool: negative batch length");
    if (length == 0) return 0;
    const int B = get_bucket_size(length);
    // All bucketing arithmetic scales L by up to max(3,B) in int (3*L layer
    // mints, (B-1)*L d-vectors, B*L RLC stash). Reject a flush too large for that to
    // fit int rather than silently wrapping -- callers split work into chunks long
    // before this bound for memory reasons anyway.
    expecting((int64_t)std::max(B, 3) * length <= (int64_t)INT_MAX,
              "triple_pool: flush too large (bucketed size overflows int) -- split into chunks");
    return B;
  }

private:
  // Generate one authenticated random triple per output position from B fresh,
  // independent leaky triples. This phase deliberately accepts no circuit-mask
  // data. Every layer is freshly overwritten, including all three layer-0 regions;
  // the folded triples remain internal and are consumed by this call's Beaver use.
  void generate_independent_triples(int L, int B) {
    FsHash feq;  // running F_eq transcript over all layers' gb-windows (nP==2 only)
    alpha_masked_cat_.clear();   // nP>=3 batched-RLC stash, fresh per batch
    alpha_uzero_.clear();
    const int any_peer = (party == 1) ? 2 : 1;
    BucketPolicy pol(this, bkt_accMAC_, bkt_accKEY_, L, B, feq, any_peer);
    ag::run_bucketing_core(pol, B, L);
  }

  // Symmetric open check: fold each d-bit's residual from this party's MACs and keys
  // on the two b-regions it combines, its own share and the combined d (bkt_bd_[0]).
  // Runs after seal(); the b-regions are untouched since the d exchange.
  void fold_d_residuals_(const typename OpenCheck::Run &run, int L, int B) {
    BlockVec(&accMAC)[nP + 1] = bkt_accMAC_;
    BlockVec(&accKEY)[nP + 1] = bkt_accKEY_;
    for (int k = 1; k < B; ++k) {
      const int sh = bkt_shift_[k];
      const size_t off = (size_t)(k - 1) * L;
      const BlockVec *lm = bkt_sac_macs_[k].data(), *lk = bkt_sac_keys_[k].data();
      ag::parallel_for(pool, L, [&, sh, off, lm, lk](int i0, int i1) {
        auto lane = open_check_.lane(run);
        for (int i = i0; i < i1; ++i) {
          const size_t j = off + (size_t)i;
          const int src = ag::bucket_fold_src(i, L, sh);
          block s = zero_block;
          for (int peer = 1; peer <= nP; ++peer) if (peer != party)
            s = s ^ accMAC[peer][L + i] ^ lm[peer][L + src] ^ accKEY[peer][L + i] ^
                lk[peer][L + src];
          lane.put((int64_t)j, open_check_.residual(bkt_bd_[party][j] ^ bkt_bd_[0][j], s));
        }
        open_check_.merge(lane);
      });
    }
  }

public:
  // Standard Beaver use of independently generated, bucketed random triples. ops
  // holds the real per-AND circuit-mask shares (MAC and key per peer) captured by
  // the draw walk. They are read only after triple generation and its checks finish,
  // to open x = λ_α ⊕ a and y = λ_β ⊕ b and to check those opens against their MACs.
  // The output wire masks are drawn separately by draw_and_seed (one aShare/AND).
  void compute_and_shares(const BeaverOperands<nP> &ops, int length,
                          AShareBundleVec<nP> &out_sigma) {
    const int B = validate_batch_length(length);
    out_sigma.clear();
    if (length == 0) return;
    const int L = length;
    const int any_peer = (party == 1) ? 2 : 1;

#ifdef AG_PROFILE
    g_ag_tp_cot_ns = g_ag_tp_hg_ns = g_ag_tp_sopen_ns = 0;
    g_ag_tp_acheck_ns = g_ag_tp_bkt_ns = g_ag_tp_open_ns = 0;
#endif

    generate_independent_triples(L, B);
    BlockVec(&accMAC)[nP + 1] = bkt_accMAC_;
    BlockVec(&accKEY)[nP + 1] = bkt_accKEY_;

#ifdef AG_PROFILE
    uint64_t _tp_o0 = agmpc_now_ns();
#endif
    std::vector<unsigned char>(&x)[nP + 1] = bkt_x_;
    std::vector<unsigned char>(&y)[nP + 1] = bkt_y_;
    for (int p = 1; p <= nP; ++p) {
      if (x[p].size() < (size_t)L) x[p].resize((size_t)L);
      if (y[p].size() < (size_t)L) y[p].resize((size_t)L);
    }
    ag::parallel_for(pool, L, [&](int lo, int hi) {
      for (int i = lo; i < hi; ++i) {
        x[party][i] = (unsigned char)(ops.a_bit[i] ^ getLSB(accMAC[any_peer][i]));
        y[party][i] = (unsigned char)(ops.b_bit[i] ^ getLSB(accMAC[any_peer][L + i]));
      }
    });
#ifdef EMP_AG_TEST_FLIP_XY
    // TEST-ONLY (never in production): a malicious party 2 flips its share of the first
    // x and sends it to everyone, keeping it itself, so every party forms the same
    // wrong x and a validly authenticated σ ⊕ λ_β. The open check must abort.
    if (party == 2) x[party][0] ^= 1;
#endif
    // Lane-split the Beaver x/y open (after run_bucketing_core, so no coin or check
    // reads it; the combine below runs on the assembled x[]/y[]). Both x and y ride
    // the same slice on each mesh, so P1's window cannot desync.
    lane_fan_out(L,
      [this, &x, &y](NetIOMP<nP> *ch, int peer, int lo, int hi) {
        ch->send_bool(peer, (const bool *)(x[party].data() + lo), hi - lo);
        ch->send_bool(peer, (const bool *)(y[party].data() + lo), hi - lo);
        ch->flush(peer);
      },
      [this, &x, &y](NetIOMP<nP> *ch, int peer, int lo, int hi) {
        ch->recv_bool(peer, (bool *)(x[peer].data() + lo), hi - lo);
        ch->recv_bool(peer, (bool *)(y[peer].data() + lo), hi - lo);
      });
    // x and y are shares of λ_α ⊕ a and λ_β ⊕ b, authenticated by the XOR of those
    // MACs (keys). Every open of this call is in now: the open check's runs start and
    // its coin is drawn (the symmetric check's; the pairwise one has none). The
    // symmetric check then folds the d-bits; the σ fold below folds x and y. Its zero
    // test also covers the aShare consistency residuals of every share minted since
    // the last one (this call's layers, the draw walk, the inputs); with the pairwise
    // check they are settled on their own below.
    typename OpenCheck::Run run_d{};
    if constexpr (!OpenCheck::kPerPeerOperands)
      run_d = open_check_.begin((int64_t)(B - 1) * L);
    const typename OpenCheck::Run run_x = open_check_.begin(L);
    const typename OpenCheck::Run run_y = open_check_.begin(L);
    open_check_.seal();
    if constexpr (OpenCheck::kAbsorbsZeroShares) {
      const auto pending = abit.take_pending_check2();
      open_check_.absorb(pending.residuals, pending.view);
    }
    if constexpr (!OpenCheck::kPerPeerOperands) fold_d_residuals_(run_d, L, B);

    out_sigma.resize(L);
    block dxor = Delta ^ bit0_mask;
    // Branchless Beaver fold, width-split (out_sigma[i] is disjoint per i), fused with
    // the combine of x and y and with their open check: every MAC and key of the
    // triple's a and b is loaded once for both. x[p]/y[p] stay as each party sent them.
    ag::parallel_for(pool, L, [&](int lo, int hi) {
      auto lane_x = open_check_.lane(run_x), lane_y = open_check_.lane(run_y);
      for (int i = lo; i < hi; ++i) {
        unsigned char xv = 0, yv = 0;
        for (int p = 1; p <= nP; ++p) { xv ^= x[p][i]; yv ^= y[p][i]; }
        // mask each addend by select_mask rather than branching on the two random
        // public selectors.
        const block mx = select_mask[xv], my = select_mask[yv];
        AShareBundle<nP> &sb = out_sigma[i];
        [[maybe_unused]] block sum_a = zero_block, sum_b = zero_block;
        for (int peer = 1; peer <= nP; ++peer) if (peer != party) {
          const int slot = peer_slot(party, peer);
          const block am = accMAC[peer][i], bm = accMAC[peer][L + i];
          const block ak = accKEY[peer][i], bk = accKEY[peer][L + i];
          sb.mac(slot) = accMAC[peer][2 * L + i] ^ (bm & mx) ^ (am & my);
          sb.key(slot) = accKEY[peer][2 * L + i] ^ (bk & mx) ^ (ak & my);
          if constexpr (OpenCheck::kPerPeerOperands) {
            lane_x.sent(peer, i, ops.a_mac[peer][i] ^ am);
            lane_x.expected(peer, i, ops.a_key[peer][i] ^ ak, x[peer][i]);
            lane_y.sent(peer, i, ops.b_mac[peer][i] ^ bm);
            lane_y.expected(peer, i, ops.b_key[peer][i] ^ bk, y[peer][i]);
          } else {
            sum_a = sum_a ^ am ^ ak;
            sum_b = sum_b ^ bm ^ bk;
          }
        }
        if constexpr (!OpenCheck::kPerPeerOperands) {
          // mu_i(x) = mu_i(λ_α) ^ own_a * Δ_i ^ sum_a, so the residual adds the
          // captured mu_i(λ_α) to the triple's part; y likewise.
          lane_x.put(i, ops.a_mu[i] ^ open_check_.residual(
                                          (unsigned char)getLSB(accMAC[any_peer][i]) ^ xv, sum_a));
          lane_y.put(i, ops.b_mu[i] ^ open_check_.residual(
                                          (unsigned char)getLSB(accMAC[any_peer][L + i]) ^ yv, sum_b));
        }
        if (xv && yv) {
          if (party != 1) {
            sb.key(peer_slot(party, 1)) = sb.key(peer_slot(party, 1)) ^ dxor;
          } else {
            for (int slot = 0; slot < AShareBundle<nP>::K; ++slot)
              sb.mac(slot) = sb.mac(slot) ^ bit0_mask;
          }
        }
      }
      open_check_.merge(lane_x);
      open_check_.merge(lane_y);
    });
    // Settle every open of this call -- the d-vector and x, y -- before σ is returned.
    open_check_.check_result();
    if constexpr (!OpenCheck::kAbsorbsZeroShares) abit.settle_check2();
#ifdef AG_PROFILE
    g_ag_tp_open_ns += agmpc_now_ns() - _tp_o0;
    if (party == 1) {
      auto ms = [](uint64_t ns) { return (double)ns / 1.0e6; };
      uint64_t sum = g_ag_tp_cot_ns + g_ag_tp_hg_ns + g_ag_tp_sopen_ns +
                     g_ag_tp_acheck_ns + g_ag_tp_bkt_ns + g_ag_tp_open_ns;
      std::printf("[ag-tp]   -- independent_triples breakdown (B=%d layers, L=%d) --\n", B, L);
      std::printf("[ag-tp]     COT/aShare draw  %9.1f ms\n", ms(g_ag_tp_cot_ns));
      std::printf("[ag-tp]     half-gate phi    %9.1f ms\n", ms(g_ag_tp_hg_ns));
      std::printf("[ag-tp]     s-open           %9.1f ms\n", ms(g_ag_tp_sopen_ns));
      std::printf("[ag-tp]     alpha check      %9.1f ms\n", ms(g_ag_tp_acheck_ns));
      std::printf("[ag-tp]     bucket layers    %9.1f ms\n", ms(g_ag_tp_bkt_ns));
      std::printf("[ag-tp]     final open       %9.1f ms\n", ms(g_ag_tp_open_ns));
      std::printf("[ag-tp]     sub-sum          %9.1f ms\n", ms(sum));
    }
#endif
  }
};

}  // namespace emp::ag
#endif // EMP_AG_BACKEND_PREPROC_TRIPLE_POOL_H__
