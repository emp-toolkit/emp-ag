#ifndef EMP_AG_BACKEND_PASSES_DRAW_BEAVER_H__
#define EMP_AG_BACKEND_PASSES_DRAW_BEAVER_H__
//
// The draw+seed+Beaver phase (fused into ONE circuit walk):
// DrawBeaverPass<nP> and the AGMPCProtocol<nP> method body that drives it
// (draw_and_seed). Tail-included by protocol.h.
//
#include "emp-ag/backend/protocol.h"
#include "emp-ag/backend/crypto/spdz.h"   // spdz_mac_share (the P1 record sweeps)

namespace emp::ag {

// Draw+seed+Beaver fused into ONE circuit walk: seed each AND-output mask from the
// authenticated-share pool + free-XOR/NOT/const propagation, and retain the real
// input-mask share bits for the final Beaver differences. Capture happens while
// the inputs are live because wire slots are reused later in the walk. The bits
// never enter triple generation or bucketing: compute_and_shares generates B
// independent random triples per AND before using these saved bits.
template <int nP>
struct DrawBeaverPass : SlotGateMixin<DrawBeaverPass<nP>> {
  using Wire = uint32_t;
  ComputeCtx<nP> &ctx;
  const block *pre_mac_[nP + 1], *pre_key_[nP + 1];   // drawn aShares, SoA per peer
  unsigned char *a_bit_, *b_bit_;      // original a/b share bits
  // P1-only eval-record capture (state.h ev_tg/ev_mu), FUSED into the
  // and_gate peer loop while the bundles are register-hot — the exact pattern of
  // the garbler's cgamma_s* capture in GarblePass. null at garblers (and at P1 with
  // no ANDs) => the capture compiles to a predicted-never branch. sigma's
  // contribution to C/s0 is folded by draw_and_seed's post-compute_and_shares sweep
  // (sigma does not exist during this walk).
  block *tg_ = nullptr;
  block *mu_ = nullptr;
  block Delta_ = zero_block;
  int party_;
  uint32_t wid;
  int ai = 0;
  int c0_ = -1, c1_ = -1;   // const dedup (active iff ctx.dedup_consts)
  DrawBeaverPass(ComputeCtx<nP> &c, const block *pre_mac[nP + 1],
                 const block *pre_key[nP + 1], int party,
                 unsigned char *a_bit, unsigned char *b_bit)
      : ctx(c), a_bit_(a_bit), b_bit_(b_bit),
        party_(party), wid((uint32_t)c.num_in) {
    for (int p = 0; p <= nP; ++p) {
      pre_mac_[p] = pre_mac ? pre_mac[p] : nullptr;
      pre_key_[p] = pre_key ? pre_key[p] : nullptr;
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
    block m1 = zero_block, k1 = zero_block;   // in1 (B) mac/key sums
    block m0 = zero_block, k0 = zero_block;   // in0 (A) mac/key sums
    block mo = zero_block, ko = zero_block;   // out (pre) mac/key sums
    for (int peer = 1; peer <= nP; ++peer) if (peer != party_) {
      const int s = peer_slot(party_, peer);
      // Seed this AND-output's share straight from the drawn SoA — out and input
      // slots never alias (the inputs are live at this gate), so W is safe to
      // write here.
      W.mac(s) = pre_mac_[peer][ai];
      W.key(s) = pre_key_[peer][ai];
      if (r) {
        r[3 * s + 0] = B.mac(s);              // A_i (Lambda_alpha-gated at eval)
        r[3 * s + 1] = A.mac(s);              // B_i (Lambda_beta-gated)
        r[3 * s + 2] = pre_mac_[peer][ai];    // C_i minus sigma (sigma sweep)
        m1 = m1 ^ B.mac(s); k1 = k1 ^ B.key(s);
        m0 = m0 ^ A.mac(s); k0 = k0 ^ A.key(s);
        mo = mo ^ pre_mac_[peer][ai]; ko = ko ^ pre_key_[peer][ai];
      }
    }
    a_bit_[ai] = (unsigned char)getLSB(A.mac(0));
    b_bit_[ai] = (unsigned char)getLSB(B.mac(0));
    if (mu_) {
      // spdz records from the same loaded values: own_bit*Delta ^ mac-sum ^ key-sum.
      // own_bit(out) = bit0 of mac slot 0 (slot-invariant across peers).
      mu_[3 * ai + 0] = (select_mask[getLSB(W.mac(0))] & Delta_) ^ mo ^ ko;
      mu_[3 * ai + 1] = (select_mask[b_bit_[ai]] & Delta_) ^ m1 ^ k1;
      mu_[3 * ai + 2] = (select_mask[a_bit_[ai]] & Delta_) ^ m0 ^ k0;
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
// and retain the real operand share bits in one walk. Triple generation happens
// separately in compute_and_shares: B independent triples per AND are bucketed
// before opening x = λ_α ⊕ a and y = λ_β ⊕ b. The resulting corrected share is
// σ = c ⊕ xb ⊕ ya ⊕ xy = λ_α λ_β; neither operand mask is a leaky-AND input.
template <int nP>
template <class Source>
void AGMPCProtocol<nP>::draw_and_seed(ComputeCtx &ctx, Source &source) {
  const int num_ands = ctx.num_ands;
#ifdef AG_PROFILE
  int64_t _all0 = io->count();
  uint64_t _cot0 = g_ag_cot_bytes, _phi0 = g_ag_phi_bytes;
#endif
  fpre->validate_batch_length(num_ands);
  std::vector<unsigned char> &a_bit = bp_abit_, &b_bit = bp_bbit_;
  if ((int)a_bit.size() < num_ands) { a_bit.resize(num_ands); b_bit.resize(num_ands); }
  // The drawn aShares stay in the pool's SoA scratch; the walk seeds each
  // AND-output slot straight from it.
  {
    const block *pre_mac[nP + 1] = {nullptr}, *pre_key[nP + 1] = {nullptr};
    if (num_ands > 0) fpre->abit.draw_soa(num_ands, pre_mac, pre_key);
    DrawBeaverPass<nP> pass(ctx, pre_mac, pre_key, party, a_bit.data(), b_bit.data());
    // P1: capture the eval records inside the walk itself (the bundles are
    // register-hot in and_gate's peer loop, as in GarblePass's cgamma_s* capture),
    // rather than re-streaming the circuit-mask rows in a second pass. sigma's
    // contribution is folded by the sigma sweep below, after compute_and_shares mints it.
    if (party == 1 && num_ands > 0) {
      ctx.ev_tg.resize((size_t)3 * (nP - 1) * num_ands);
      ctx.ev_mu.resize((size_t)3 * num_ands);
      pass.tg_ = ctx.ev_tg.data();
      pass.mu_ = ctx.ev_mu.data();
      pass.Delta_ = Delta;
    }
    ag::run_pass(pass, source);
  }
  if (num_ands > 0) fpre->compute_and_shares(a_bit.data(), b_bit.data(), num_ands, ctx.sigma);
  else ctx.sigma.clear();
  // P1 record sweep: fold sigma (born in compute_and_shares, so not fusable into
  // the walk above) into the C and s0 records — sigma's mac(i-2) completes each
  // tgamma row, its spdz collapse completes s0. After this nothing at P1 reads ctx.sigma or the WIRE fabric
  // until the output decode (which reads the DrawBeaverPass-seeded
  // output slots, pinned live by liveness).
  if (party == 1 && num_ands > 0) {
    block *tg = ctx.ev_tg.data();
    block *mu = ctx.ev_mu.data();
    const block D = Delta;
    const AShareBundle<nP> *sig = ctx.sigma.data();
    ag::parallel_for(pool, num_ands, [&, tg, mu, D, sig](int lo, int hi) {
      for (int ai = lo; ai < hi; ++ai) {
        block *r = tg + (size_t)3 * (nP - 1) * ai;
        for (int i = 2; i <= nP; ++i)
          r[3 * (i - 2) + 2] = r[3 * (i - 2) + 2] ^ sig[ai].mac(i - 2);
        mu[3 * ai + 0] = mu[3 * ai + 0] ^ ag::spdz_mac_share(sig[ai], D);
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
#endif  // EMP_AG_BACKEND_PASSES_DRAW_BEAVER_H__
