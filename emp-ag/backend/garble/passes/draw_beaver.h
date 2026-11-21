#ifndef EMP_AG_BACKEND_GARBLE_PASSES_DRAW_BEAVER_H__
#define EMP_AG_BACKEND_GARBLE_PASSES_DRAW_BEAVER_H__
//
// The draw+seed+Beaver phase (fused into ONE circuit walk):
// DrawBeaverPass<nP> and the AGMPCProtocol<nP> method body that drives it
// (draw_and_seed). Tail-included by protocol.h.
//
#include "emp-ag/backend/garble/protocol.h"
#include "emp-ag/backend/garble/spdz.h"   // spdz_mac_share (the P1 record sweeps)

namespace emp::ag {

// Where the walk writes the AND operand mask shares (see BeaverOperands): the share
// bits always, and either the MACs/keys per peer or the SPDZ collapse mu_i, whichever
// the open check needs (the others stay null). operands() is the read-only view
// compute_and_shares takes (triple/triple_pool.h).
template <int nP>
struct BeaverCapture {
  unsigned char *a_bit = nullptr, *b_bit = nullptr;
  block *a_mac[nP + 1] = {}, *a_key[nP + 1] = {};
  block *b_mac[nP + 1] = {}, *b_key[nP + 1] = {};
  block *a_mu = nullptr, *b_mu = nullptr;
  BeaverOperands<nP> operands() const {
    BeaverOperands<nP> o;
    o.a_bit = a_bit; o.b_bit = b_bit;
    for (int p = 0; p <= nP; ++p) {
      o.a_mac[p] = a_mac[p]; o.a_key[p] = a_key[p];
      o.b_mac[p] = b_mac[p]; o.b_key[p] = b_key[p];
    }
    o.a_mu = a_mu; o.b_mu = b_mu;
    return o;
  }
};

// Draw+seed+Beaver fused into ONE circuit walk: seed each AND-output mask from the
// authenticated-share pool + free-XOR/NOT/const propagation, and retain the real
// input-mask shares for the final Beaver differences and their open check. Capture
// happens while the inputs are live because wire slots are reused later in the walk.
// The captured shares never enter triple generation or bucketing: compute_and_shares
// generates B independent random triples per AND before using them.
template <int nP>
struct DrawBeaverPass : SlotGateMixin<DrawBeaverPass<nP>> {
  using Wire = uint32_t;
  ComputeCtx<nP> &ctx;
  const block *pre_mac_[nP + 1], *pre_key_[nP + 1];   // drawn aShares, SoA per peer
  // Captured AND operand mask shares (BeaverCapture), first input a and second b.
  unsigned char *a_bit_, *b_bit_;
  block *a_mac_[nP + 1], *a_key_[nP + 1], *b_mac_[nP + 1], *b_key_[nP + 1];
  block *a_mu_, *b_mu_;
  bool per_peer_ = false;   // the per-peer arrays are in use
  // P1-only eval-record capture (state.h ev_tg/ev_mu), FUSED into the
  // and_gate peer loop while the bundles are register-hot — the exact pattern of
  // the garbler's cgamma_s* capture in GarblePass. null at garblers (and at P1 with
  // no ANDs) => the capture compiles to a predicted-never branch. sigma's
  // contribution to C/s0 is folded by draw_and_seed's post-compute_and_shares sweep
  // (sigma does not exist during this walk).
  block *tg_ = nullptr;
  block *mu_ = nullptr;
  // P1 under Auth::WRK (state.h ev_auth / ev_auth_bits): its key sums and own bits on
  // the shares of lambda_in1, lambda_in0 and lambda_out, for its per-gate check. sigma's
  // are folded in by the sweep. null otherwise.
  block *auth_ = nullptr;
  unsigned char *auth_bits_ = nullptr;
  block Delta_ = zero_block;
  int party_;
  uint32_t wid;
  int ai = 0;
  int c0_ = -1, c1_ = -1;   // const dedup (active iff ctx.dedup_consts)
  DrawBeaverPass(ComputeCtx<nP> &c, const block *pre_mac[nP + 1],
                 const block *pre_key[nP + 1], int party,
                 const BeaverCapture<nP> &capture)
      : ctx(c), a_bit_(capture.a_bit), b_bit_(capture.b_bit), a_mu_(capture.a_mu),
        b_mu_(capture.b_mu), party_(party), wid((uint32_t)c.num_in) {
    for (int p = 0; p <= nP; ++p) {
      pre_mac_[p] = pre_mac ? pre_mac[p] : nullptr;
      pre_key_[p] = pre_key ? pre_key[p] : nullptr;
      a_mac_[p] = capture.a_mac[p];
      a_key_[p] = capture.a_key[p];
      b_mac_[p] = capture.b_mac[p];
      b_key_[p] = capture.b_key[p];
      if (p != party && capture.a_mac[p] != nullptr) per_peer_ = true;
    }
  }
  Wire public_bit(bool v) {
    int h = this->dedup_hit(v); if (h >= 0) return (Wire)h;
    uint32_t id = wid++;
    zero_share(ctx.WIRE(id));
    this->dedup_note(v, id);
    return id;
  }
  Wire and_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    const AShareBundle<nP> &A = ctx.WIRE(i0);   // real circuit input masks
    const AShareBundle<nP> &B = ctx.WIRE(i1);
    AShareBundle<nP> &W = ctx.WIRE(id);          // and seed the output from the SoA
    // P1 eval-record capture (see the member comment): the tgamma basis per dest
    // (A_i = M_i[lam_in1] from B, B_i = M_i[lam_in0] from A, C_i = M_i[lam_out]
    // from pre) plus the running mac/key sums for the spdz records — all from
    // values this loop already loads.
    block *r = tg_ ? tg_ + (size_t)3 * (nP - 1) * ai : nullptr;
    const bool sums = (r != nullptr) || (a_mu_ != nullptr);   // operand mac/key sums needed
    block m1 = zero_block, k1 = zero_block;   // in1 (B) mac/key sums
    block m0 = zero_block, k0 = zero_block;   // in0 (A) mac/key sums
    block mo = zero_block, ko = zero_block;   // out (pre) mac/key sums
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
      const int s = peer_slot(party_, peer);
      if (per_peer_) {   // operand shares for the Beaver open's pairwise check
        a_mac_[peer][ai] = A.mac(s); a_key_[peer][ai] = A.key(s);
        b_mac_[peer][ai] = B.mac(s); b_key_[peer][ai] = B.key(s);
      }
      // Seed this AND-output's share straight from the drawn SoA — out and input
      // slots never alias (the inputs are live at this gate), so W is safe to
      // write here.
      W.mac(s) = pre_mac_[peer][ai];
      W.key(s) = pre_key_[peer][ai];
      if (sums) {
        m1 = m1 ^ B.mac(s); k1 = k1 ^ B.key(s);
        m0 = m0 ^ A.mac(s); k0 = k0 ^ A.key(s);
      }
      if (r) {
        r[3 * s + 0] = B.mac(s);              // A_i (Lambda_alpha-gated at eval)
        r[3 * s + 1] = A.mac(s);              // B_i (Lambda_beta-gated)
        r[3 * s + 2] = pre_mac_[peer][ai];    // C_i minus sigma (sigma sweep)
        mo = mo ^ pre_mac_[peer][ai]; ko = ko ^ pre_key_[peer][ai];
      }
    }
    // own share bits = bit0 of mac slot 0 (slot-invariant across peers).
    const unsigned char a_bit = (unsigned char)getLSB(A.mac(0));
    const unsigned char b_bit = (unsigned char)getLSB(B.mac(0));
    a_bit_[ai] = a_bit;
    b_bit_[ai] = b_bit;
    if (a_mu_) {   // operand mu_i for the Beaver open's symmetric check
      a_mu_[ai] = (select_mask[a_bit] & Delta_) ^ m0 ^ k0;
      b_mu_[ai] = (select_mask[b_bit] & Delta_) ^ m1 ^ k1;
    }
    if (mu_) {
      // spdz records from the same loaded values: own_bit*Delta ^ mac-sum ^ key-sum.
      mu_[3 * ai + 0] = (select_mask[getLSB(W.mac(0))] & Delta_) ^ mo ^ ko;
      mu_[3 * ai + 1] = (select_mask[b_bit] & Delta_) ^ m1 ^ k1;
      mu_[3 * ai + 2] = (select_mask[a_bit] & Delta_) ^ m0 ^ k0;
    }
    if (auth_) {
      auth_[3 * ai + 0] = k1;
      auth_[3 * ai + 1] = k0;
      auth_[3 * ai + 2] = ko;
      auth_bits_[ai] = (unsigned char)(b_bit | (a_bit << 1) | (getLSB(W.mac(0)) << 2));
    }
    ++ai;
    return id;
  }
  Wire xor_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    xor_share(ctx.WIRE(id), ctx.WIRE(i0), ctx.WIRE(i1));
    return id;
  }
  Wire not_gate(Wire i0) {
    uint32_t id = wid++;
    ctx.WIRE(id) = ctx.WIRE(i0);
    return id;
  }
};

// Draw one independent output-mask share per AND, then seed the circuit masks
// and retain the real operand mask shares in one walk. Triple generation happens
// separately in compute_and_shares: B independent triples per AND are bucketed
// before opening x = λ_α ⊕ a and y = λ_β ⊕ b. The resulting corrected share is
// σ = c ⊕ xb ⊕ ya ⊕ xy = λ_α λ_β; neither operand mask is a leaky-AND input.
template <int nP, class Cfg>
template <class Source>
void AGMPCProtocol<nP, Cfg>::draw_and_seed(ComputeCtx &ctx, Source &source) {
  const int num_ands = ctx.num_ands;
#ifdef AG_PROFILE
  int64_t _all0 = io->count();
  uint64_t _cot0 = g_ag_cot_bytes, _phi0 = g_ag_phi_bytes;
#endif
  fpre->validate_batch_length(num_ands);
  // The walk keeps every AND's operand mask shares in these grow-only arrays for the
  // Beaver open and its check: the share bits, plus what the open check reads -- the
  // MACs/keys per peer (pairwise) or one mu_i block per operand (symmetric).
  BeaverCapture<nP> capture;
  if (bp_abit_.size() < (size_t)num_ands) {
    bp_abit_.resize((size_t)num_ands);
    bp_bbit_.resize((size_t)num_ands);
  }
  capture.a_bit = bp_abit_.data();
  capture.b_bit = bp_bbit_.data();
  if constexpr (TriplePool<nP>::open_check_t::kPerPeerOperands) {
    for (int p = 1; p <= nP; ++p) if (p != party) {
      for (BlockVec *v : {&bp_amac_[p], &bp_akey_[p], &bp_bmac_[p], &bp_bkey_[p]})
        if (v->size() < (size_t)num_ands) v->resize((size_t)num_ands);
      capture.a_mac[p] = bp_amac_[p].data(); capture.a_key[p] = bp_akey_[p].data();
      capture.b_mac[p] = bp_bmac_[p].data(); capture.b_key[p] = bp_bkey_[p].data();
    }
  } else {
    if (bp_amu_.size() < (size_t)num_ands) {
      bp_amu_.resize((size_t)num_ands);
      bp_bmu_.resize((size_t)num_ands);
    }
    capture.a_mu = bp_amu_.data();
    capture.b_mu = bp_bmu_.data();
  }
  // The drawn aShares stay in the pool's SoA scratch; the walk seeds each
  // AND-output slot straight from it.
  {
    const block *pre_mac[nP + 1] = {nullptr}, *pre_key[nP + 1] = {nullptr};
    if (num_ands > 0) fpre->abit.draw_soa(num_ands, pre_mac, pre_key);
    DrawBeaverPass<nP> pass(ctx, pre_mac, pre_key, party, capture);
    pass.Delta_ = Delta;   // for the mu_i captures and P1's records
    // P1: capture the eval records inside the walk itself (the bundles are
    // register-hot in and_gate's peer loop, as in GarblePass's cgamma_s* capture),
    // rather than re-streaming the circuit-mask rows in a second pass. sigma's
    // contribution is folded by the sigma sweep below, after compute_and_shares mints it.
    if (party == 1 && num_ands > 0) {
      ctx.ev_tg.resize((size_t)3 * (nP - 1) * num_ands);
      pass.tg_ = ctx.ev_tg.data();
      if constexpr (Cfg::auth == Auth::KRRW) {
        ctx.ev_mu.resize((size_t)3 * num_ands);
        pass.mu_ = ctx.ev_mu.data();
      } else {
        ctx.ev_auth.resize((size_t)3 * num_ands);
        ctx.ev_auth_bits.resize((size_t)num_ands);
        pass.auth_ = ctx.ev_auth.data();
        pass.auth_bits_ = ctx.ev_auth_bits.data();
      }
    }
    ag::run_pass(pass, source);
  }
  if (num_ands > 0) fpre->compute_and_shares(capture.operands(), num_ands, ctx.sigma);
  else ctx.sigma.clear();
  // P1 record sweep: fold sigma (born in compute_and_shares, so not fusable into
  // the walk above) into the C and s0 records — sigma's mac(i-2) completes each
  // tgamma row, its spdz collapse completes s0. After this nothing at P1 reads ctx.sigma or the WIRE fabric
  // until the output decode (which reads the DrawBeaverPass-seeded
  // output slots, pinned live by liveness).
  if (party == 1 && num_ands > 0) {
    block *tg = ctx.ev_tg.data();
    block *mu = ctx.ev_mu.data();
    block *au = ctx.ev_auth.data();
    unsigned char *aub = ctx.ev_auth_bits.data();
    const block D = Delta;
    const AShareBundle<nP> *sig = ctx.sigma.data();
    ag::parallel_for(pool, num_ands, [&, tg, mu, au, aub, D, sig](int lo, int hi) {
      for (int ai = lo; ai < hi; ++ai) {
        block *r = tg + (size_t)3 * (nP - 1) * ai;
        for (int i = 2; i <= nP; ++i)
          r[3 * (i - 2) + 2] = r[3 * (i - 2) + 2] ^ sig[ai].mac(i - 2);
        if constexpr (Cfg::auth == Auth::KRRW) {
          mu[3 * ai + 0] = mu[3 * ai + 0] ^ ag::spdz_mac_share(sig[ai], D);
        } else {
          au[3 * ai + 2] = au[3 * ai + 2] ^ peer_key_sum(sig[ai]);
          aub[ai] = (unsigned char)(aub[ai] ^ (own_bit(sig[ai]) << 2));
        }
      }
    });
  }
  // The half-gate hash seed comes from the triple-generation coin (piggybacked inside
  // compute_and_shares -> TriplePool::draw_coins). Garbler and evaluator derive it from
  // the same globally-agreed coin, so their per-gate keys agree. Meaningful only when
  // there are ANDs: with none, compute_and_shares is skipped and nothing is hashed.
  if (num_ands > 0) ctx.halfgate_seed = fpre->halfgate_seed_;
#ifdef AG_PROFILE
  if (party == 1) {
    uint64_t all = (uint64_t)(io->count() - _all0), cot = g_ag_cot_bytes - _cot0,
             phi = g_ag_phi_bytes - _phi0;
    printf("[ag]   draw_and_seed split: COT %llu B, phi-exchange %llu B, "
           "other-non-COT %lld B\n",
           (unsigned long long)cot, (unsigned long long)phi,
           (long long)(all - cot - phi));
  }
#endif
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_GARBLE_PASSES_DRAW_BEAVER_H__
