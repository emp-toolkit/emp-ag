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

// Draw+seed fused into ONE circuit walk: seed each AND-output mask from the
// authenticated-share pool + free-XOR/NOT/const propagation, and write every AND gate's
// input-mask shares where the session's AND-gate protocol asks (AndInputs,
// triple/and_prep.h), while the inputs are live: wire slots are reused later in the walk.
template <int nP>
struct DrawBeaverPass : SlotGateMixin<DrawBeaverPass<nP>> {
  using Wire = uint32_t;
  ComputeCtx<nP> &ctx;
  const block *pre_mac_[nP + 1], *pre_key_[nP + 1];   // drawn aShares, SoA per peer
  // Where each AND gate's input masks go (AndInputs): alpha for its first input, beta for
  // its second.
  unsigned char *alpha_bit_, *beta_bit_;
  block *alpha_mac_[nP + 1], *alpha_key_[nP + 1], *beta_mac_[nP + 1], *beta_key_[nP + 1];
  block *alpha_mu_, *beta_mu_;
  bool alpha_per_peer_ = false, beta_per_peer_ = false;   // the per-peer arrays are in use
  // P1-only eval-record capture (state.h ev_tg/ev_mu), FUSED into the
  // and_gate peer loop while the bundles are register-hot — the exact pattern of
  // the garbler's cgamma_s* capture in GarblePass. null at garblers (and at P1 with
  // no ANDs) => the capture compiles to a predicted-never branch. sigma's
  // contribution to C/s0 is folded by draw_and_seed's sweep after and_prep->run
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
                 const AndInputs<nP> &in)
      : ctx(c), alpha_bit_(in.alpha_bit), beta_bit_(in.beta_bit), alpha_mu_(in.alpha_mu),
        beta_mu_(in.beta_mu), party_(party), wid((uint32_t)c.num_in) {
    for (int p = 0; p <= nP; ++p) {
      pre_mac_[p] = pre_mac ? pre_mac[p] : nullptr;
      pre_key_[p] = pre_key ? pre_key[p] : nullptr;
      alpha_mac_[p] = in.alpha_mac[p];
      alpha_key_[p] = in.alpha_key[p];
      beta_mac_[p] = in.beta_mac[p];
      beta_key_[p] = in.beta_key[p];
      if (p != party && in.alpha_mac[p] != nullptr) alpha_per_peer_ = true;
      if (p != party && in.beta_mac[p] != nullptr) beta_per_peer_ = true;
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
    // operand mac/key sums needed
    const bool sums = (r != nullptr) || (alpha_mu_ != nullptr) || (beta_mu_ != nullptr);
    block m1 = zero_block, k1 = zero_block;   // in1 (B) mac/key sums
    block m0 = zero_block, k0 = zero_block;   // in0 (A) mac/key sums
    block mo = zero_block, ko = zero_block;   // out (pre) mac/key sums
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
      const int s = peer_slot(party_, peer);
      if (alpha_per_peer_) { alpha_mac_[peer][ai] = A.mac(s); alpha_key_[peer][ai] = A.key(s); }
      if (beta_per_peer_) { beta_mac_[peer][ai] = B.mac(s); beta_key_[peer][ai] = B.key(s); }
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
    if (alpha_bit_) alpha_bit_[ai] = a_bit;
    if (beta_bit_) beta_bit_[ai] = b_bit;
    // operand mu_i, for a symmetric open check
    if (alpha_mu_) alpha_mu_[ai] = (select_mask[a_bit] & Delta_) ^ m0 ^ k0;
    if (beta_mu_) beta_mu_[ai] = (select_mask[b_bit] & Delta_) ^ m1 ^ k1;
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

// Draw one independent output-mask share per AND, then seed the circuit masks and
// write every AND gate's input masks for the session's AND-gate protocol in one walk.
// The protocol (and_prep, triple/and_prep.h) then makes sigma = λ_α λ_β per gate.
template <int nP, class Cfg>
template <class Source>
void AGMPCProtocol<nP, Cfg>::draw_and_seed(ComputeCtx &ctx, Source &source) {
  const int num_ands = ctx.num_ands;
#ifdef AG_PROFILE
  int64_t _all0 = io->count();
  uint64_t _cot0 = g_ag_cot_bytes, _phi0 = g_ag_phi_bytes;
#endif
  and_prep->validate(num_ands);
  AndInputs<nP> inputs{};
  if (num_ands > 0) inputs = and_prep->inputs(num_ands);
  // The drawn aShares stay in the pool's SoA scratch; the walk seeds each
  // AND-output slot straight from it.
  {
    const block *pre_mac[nP + 1] = {nullptr}, *pre_key[nP + 1] = {nullptr};
    // Their check2 waits for the coin of the AND gates' protocol (and_prep->run, below).
    if (num_ands > 0) abit->draw_soa(num_ands, pre_mac, pre_key, /*defer_check2=*/true);
    DrawBeaverPass<nP> pass(ctx, pre_mac, pre_key, party, inputs);
    pass.Delta_ = Delta;   // for the mu_i captures and P1's records
    // P1: capture the eval records inside the walk itself (the bundles are
    // register-hot in and_gate's peer loop, as in GarblePass's cgamma_s* capture),
    // rather than re-streaming the circuit-mask rows in a second pass. sigma's
    // contribution is folded by the sigma sweep below, after and_prep->run makes it.
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
  block coin = zero_block;
  if (num_ands > 0) {
    coin = and_prep->run(num_ands, ctx.sigma);
    expecting(ctx.sigma.size() == (size_t)num_ands,
              "AGMPC: the AND-gate protocol returned the wrong number of products");
    // A no-op when the protocol agreed on the views of its consistency checks; one round
    // when it only folded them; an abort when it left a draw unfolded.
    abit->settle_check2();
  } else {
    ctx.sigma.clear();
  }
  // P1 record sweep: fold sigma (born in and_prep->run, so not fusable into
  // the walk above) into the C and s0 records — sigma's mac(i-2) completes each
  // tgamma row, its spdz collapse completes s0. After this nothing at P1 reads
  // ctx.sigma or the WIRE fabric until the output decode (which reads the
  // DrawBeaverPass-seeded output slots, pinned live by liveness).
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
  // The half-gate hash seed: one domain-separated squeeze of the coin of the AND gates'
  // protocol, so no round of its own. Garbler and evaluator derive it from the same
  // coin, so their per-gate keys agree. The coin may be predictable (and_prep.h); the
  // seed needs only to be fresh per chunk, since MITCCRH's keys are public. Meaningful only when there are ANDs: with none,
  // the protocol is not run and nothing is hashed.
  if (num_ands > 0)
    ctx.halfgate_seed = fs_coin("AGMPC halfgate seed", coin, zero_block);
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
