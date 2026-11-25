#ifndef EMP_AG_BACKEND_GARBLE_PASSES_MASK_WITNESS_H__
#define EMP_AG_BACKEND_GARBLE_PASSES_MASK_WITNESS_H__
//
// The output-check phase: a single SYMMETRIC SPDZ c_gamma MACCheck.
//
// One check certifies every party at once (KRRW's symmetric c_gamma open, instantiated on
// the authenticated-garbling t_gamma constraint under the shared global key
// Delta := XOR_i Delta_i):
//
//   open_and_masks is its own cheap walk so P1 broadcasts Lambda_AND EARLY -- before the
//   witness fold -- keeping the two parties pipelined on the latency-bound path.
//
//   Output check: each party folds its SPDZ MAC shares mu_c[a] of c_gamma = t_gamma under
//   Delta from witness material the garble/eval walks already produced (garble/passes/garble.h, garble/passes/evaluate.h): P1's
//   mu were finalized inside the eval walk (pure buffer fold here, no walk); a garbler
//   walks ONLY the MASK bit fabric (MaskWitnessPass, which also applies the broadcast
//   Lambda_AND) and assembles mu from its 48 B/AND garble-time records -- the WIRE bundle
//   fabric is never re-propagated. A random linear combination
//   m_i = sum_a chi_a * mu_c[a] (chi from F_coin: fs_coin_pair at nP==2, the post-commitment
//   multiparty coin sampleRandom at nP>2) is then batch-checked to XOR to zero across parties
//   (commit-then-open, rush-safe). Since XOR_i m_i = c_gamma . Delta on honest execution and
//   Delta != 0, XOR_i m_i = 0 proves every c_gamma = 0; a wrong Lambda makes some c_gamma=1 so
//   XOR_i m_i = Delta != 0. Delta is NEVER opened (it is reused across chunks), so only the
//   claimed-zero c.Delta is revealed. Soundness 2^-csp. Tail-included by
//   protocol.h.
//
#include "emp-ag/backend/garble/protocol.h"
#include "emp-ag/backend/common/fs_hash.h"  // FsHash (FS/check digests)
#include "emp-ag/backend/common/feq.h"        // fs_coin_pair, symmetric F_eq
#include "emp-ag/backend/common/protocols.h"  // sampleRandom, check_shared_zero
#include "emp-ag/backend/garble/spdz.h"       // gf_pow, kRlcLanes, rlc_fold_mu, collapse_cgamma_from_records
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

// ---- c_gamma SPDZ-collapse witness kernels: spdz_mac_share / collapse_cgamma_witness
// live in garble/spdz.h (the garble/eval walks PRODUCE the witness material while the
// share bundles are already loaded; this file only folds it). Only the MAC share is
// needed: the check verifies XOR_i mu = 0 and never OPENS c_gamma, so no value
// (c_bit) share is computed. Shares are reached ONLY through the ADL accessors
// (shares.h).

// Lambda_AND broadcast (P1): the buffer is filled INSIDE the eval walk
// (StreamEvaluatePass stashes each AND's opened mask as it derives it), so P1 has
// no collect walk — open_and_masks just sends the buffer.

// The garbler's output-check witness pass: re-propagate the MASK BIT fabric (a garbler
// sets its fabric MASK only here — garbling touches LABEL/WIRE, not MASK — and
// gather_outputs reads it, so this walk runs even with no ANDs), apply P1's broadcast
// Lambda_AND at each AND output, and fold the witness from the garble-time records:
// with s0 = S(sig)^S(out), s1 = S(in1), s2 = S(in0) captured by GarblePass
// (garble/passes/garble.h),
//   mu_a = ((La&Lb)^Lg)*Delta ^ La*s1[a] ^ Lb*s2[a] ^ s0[a]
// — value-identical to collapse_cgamma_witness on re-propagated bundles, without
// re-propagating the WIRE bundle fabric. The RLC is STREAMED: given the challenge chi
// up front, each AND folds m_i ^= chi^{a+1} * mu_a in place, so there is no
// num_ands-sized muc / coeff scratch. m_i is identical to
// vector_inn_prdt_sum_red(muc, uni_hash_coeff_gen(chi)) by the linearity of GF(2^128)
// reduction. P1 has no such pass at all: its mu were finalized inside the eval walk
// (StreamEvaluatePass); its MASK fabric persists from eval and its WIRE fabric from
// DrawBeaverPass's walk (eval does not touch WIRE) — see output_check.
template <int nP, class Cfg>
struct MaskWitnessPass : SlotGateMixin<MaskWitnessPass<nP, Cfg>> {
  using Wire = uint32_t;
  AGMPCProtocol<nP, Cfg> *P;
  ComputeCtx<nP> &ctx;
  const std::vector<unsigned char> &Lambda_AND;
  // The RLC fold streams forward in kRlcLanes Horner chains (lane j = a mod K), one
  // multiplication per AND: with beta = chi^{-1}, lane j keeps
  //   acc_j = XOR over its ANDs a of beta^{a_last(j) - a} * mu_a,
  // a_last(j) being its last AND, and m() lifts it by chi^{a_last(j) + 1}. The result is
  // the same field element as XOR_a chi^{a+1} * mu_a (see rlc_fold_mu), and 0 for chi = 0,
  // since then the lift is 0.
  block chi;
  block betaK;   // chi^{-K}
  block acc[kRlcLanes];
  uint32_t wid;
  int ai = 0;
  int c0_ = -1, c1_ = -1;
  MaskWitnessPass(AGMPCProtocol<nP, Cfg> *p, ComputeCtx<nP> &c,
                  const std::vector<unsigned char> &la, block chi_)
      : P(p), ctx(c), Lambda_AND(la), chi(chi_),
        betaK(gf_pow(gf_inv(chi_), kRlcLanes)), wid((uint32_t)c.num_in) {
    for (int j = 0; j < kRlcLanes; ++j) acc[j] = zero_block;
  }
  block m() const {
    block r = zero_block;
    for (int j = 0; j < kRlcLanes && j < ai; ++j) {
      const int last = j + kRlcLanes * ((ai - 1 - j) / kRlcLanes);   // lane j's last AND
      block lift;
      gfmul(acc[j], gf_pow(chi, (uint64_t)last + 1), &lift);
      r = r ^ lift;
    }
    return r;
  }
  Wire public_bit(bool v) {
    int h = this->dedup_hit(v); if (h >= 0) { ctx.MASK(h) = (unsigned char)v; return (Wire)h; }
    uint32_t id = wid++;
    ctx.MASK(id) = (unsigned char)v;
    this->dedup_note(v, id);
    return id;
  }
  Wire xor_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    ctx.MASK(id) = ctx.MASK(i0) ^ ctx.MASK(i1);
    return id;
  }
  Wire not_gate(Wire i0) {
    uint32_t id = wid++;
    ctx.MASK(id) = ctx.MASK(i0) ^ 1;
    return id;
  }
  Wire and_gate(Wire i0, Wire i1) {
    uint32_t id = wid++;
    int a = ai++;
    bool La = ctx.MASK(i0), Lb = ctx.MASK(i1);
    bool Lg = Lambda_AND[a] != 0;
    ctx.MASK(id) = (unsigned char)Lg;
    block mu = ag::collapse_cgamma_from_records(La, Lb, Lg, ctx.cgamma_s0[a],
                                                ctx.cgamma_s1[a], ctx.cgamma_s2[a],
                                                P->Delta);
    const int j = a & (kRlcLanes - 1);   // lane a mod K
    gfmul(acc[j], betaK, &acc[j]);       // the lane's earlier ANDs move one step down
    acc[j] = acc[j] ^ mu;
    return id;
  }
};

// Auth::WRK on a circuit with no AND gate: every mask follows from the inputs, so a
// garbler sets its own with the mask walk above (no AND gate fires, so it folds nothing)
// and nothing is sent. P1's masks come from evaluation.
template <int nP, class Cfg>
template <class Source>
void AGMPCProtocol<nP, Cfg>::linear_masks_(ComputeCtx &ctx, Source &source) {
  if (party == 1) return;
  MaskWitnessPass<nP, Cfg> pass(this, ctx, ctx.Lambda_AND, zero_block);
  ag::run_pass(pass, source);
}

// open_and_masks: P1 broadcasts the AND-output masks Lambda_AND EARLY. The buffer was
// filled during the eval walk (StreamEvaluatePass), so this phase is pure I/O at
// every role: P1 sends, garblers receive (application + the witness fold live in
// the output check's MaskWitnessPass).
template <int nP, class Cfg>
template <class Source>
void AGMPCProtocol<nP, Cfg>::open_and_masks(ComputeCtx &ctx, [[maybe_unused]] Source &source) {
  const int num_ands = ctx.num_ands;
  if (num_ands == 0) return;
  std::vector<unsigned char> &Lambda_AND = ctx.Lambda_AND;
  if ((int)Lambda_AND.size() < num_ands) Lambda_AND.resize(num_ands);
  if (party == 1) {
    if constexpr (kTestHooks) {
      // TEST-ONLY (hook flip_lambda): a malicious P1 corrupts one broadcast AND-output
      // Lambda. The symmetric MACCheck must then abort at EVERY honest party.
      if (hooks().flip_lambda) Lambda_AND[0] ^= 1;
    }
    std::vector<future<void>> rs;
    for (int p2 = 2; p2 <= nP; ++p2) {
      int party2 = p2;
      rs.push_back(pool->enqueue([this, &Lambda_AND, num_ands, party2]() {
        io->send_bool(party2, (const bool *)Lambda_AND.data(), num_ands);
        io->flush(party2);
      }));
    }
    joinNclean(rs);
  } else {
    // Receive only: the broadcast masks are applied by the output check's
    // MaskWitnessPass (which owns the garbler's whole MASK fabric walk); nothing
    // reads a garbler's AND-output MASK between this phase and the output check.
    io->recv_bool(1, (bool *)Lambda_AND.data(), num_ands);
  }
}

// The symmetric SPDZ c_gamma MACCheck. One walk (collapse the per-AND SPDZ MAC share mu_c),
// one F_coin challenge chi, one RLC m_i = sum chi_a mu_c[a], one rush-safe shared-zero check
// XOR_i m_i = 0 (== c_gamma . Delta, which is 0 iff every gate is correct; Delta is never
// opened). Runs at EVERY party: every honest party certifies the whole computation.
template <int nP, class Cfg>
template <class Source>
void AGMPCProtocol<nP, Cfg>::output_check(ComputeCtx &ctx, Source &source) {
  const int num_ands = ctx.num_ands;

  // F_coin: the RLC challenge chi, drawn BEFORE the witness walk. The walk sends nothing, so its
  // transcript position is unchanged -- drawing chi here is byte-identical to drawing it after,
  // but lets the walk STREAM the RLC (no num_ands-sized scratch). At nP==2 the shared channel
  // transcript gives chi for free (FS from session start covers the Lambda_AND broadcast); at
  // nP>2 there is no single transcript, so use the post-commitment commit-reveal coin (garbling
  // + Lambda_AND already on the wire). num_ands==0: no coin (nothing to certify).
  block chi = zero_block;
  if (num_ands > 0) {
    if constexpr (nP == 2) chi = fs_coin_pair<nP>(io, party == 1 ? 2 : 1, "AGMPC cgamma");
    else                   chi = sampleRandom<nP>(io, &prg, pool, party,
                                                  session_id);
  }

  // Fold this party's SPDZ MAC shares mu_c into the streamed RLC
  // m_i = XOR_a chi^{a+1} * mu_c[a], from the witness material the garble/eval walks
  // produced (garble/passes/garble.h, garble/passes/evaluate.h) — the WIRE bundle fabric is never re-propagated here.
  //
  //   P1: mu was finalized per AND inside the eval walk from the draw-time records
  //   (its MASK fabric persists from eval, its WIRE fabric from DrawBeaverPass, so
  //   gather_outputs is already served) -> a pure buffer fold, no walk at all.
  //
  //   Garbler: one MASK-BIT fabric walk (a garbler sets its fabric MASK ONLY here --
  //   garbling touches LABEL/WIRE, not MASK -- and gather_outputs reads it, so this
  //   walk runs even with no ANDs: else a garbler that decodes a pure-linear output,
  //   e.g. reveal(a ^ b) to a garbler, would carry MASK 0, not Λ_a ⊕ Λ_b). It applies
  //   the broadcast Lambda_AND in place and folds mu from the 48 B/AND records.
  block m_i = zero_block;
  if (party == 1) {
    m_i = ag::rlc_fold_mu(ctx.cgamma_mu.data(), num_ands, chi, pool);
  } else {
    MaskWitnessPass<nP, Cfg> pass(this, ctx, ctx.Lambda_AND, chi);
    ag::run_pass(pass, source);
    m_i = pass.m();
  }
  if (num_ands == 0) return;                       // no AND gates -> nothing to certify
  // m_i is the reduced RLC share (== vector_inn_prdt_sum_red)

  // Shared-zero check XOR_i m_i = 0, rush-safe (commit-before-open) + equivocation-safe.
  if constexpr (nP == 2) {
    // XOR_i m_i = 0  <=>  m_1 == m_2 : a rush-safe equality on H(m_i).
    char Dme[FsHash::DIGEST_SIZE];
    FsHash::hash_once(Dme, &m_i, sizeof(block));
    int peer = (party == 1) ? 2 : 1;
    NetIO *sch = (party < peer) ? io->ios[peer] : io->ios2[peer];
    NetIO *rch = (peer < party) ? io->ios[peer] : io->ios2[peer];
    FeqSymmetric2PC eq = feq_prepare_symmetric_2pc(
        &prg, session_id, "emp-ag:cgamma", party, Dme);
    sch->send_data(eq.commitment, FsHash::DIGEST_SIZE);
    sch->flush();
    rch->recv_data(eq.peer_commitment, FsHash::DIGEST_SIZE);
    feq_finish_symmetric_2pc(
        sch, rch, session_id, "emp-ag:cgamma", party, eq,
        "cheat in c_gamma MACCheck");
  } else {
    ag::check_shared_zero<nP>(io, pool, &prg, party, m_i,
                              session_id, "emp-ag:cgamma",
                              "cheat in c_gamma MACCheck",
                              "c_gamma MACCheck: commit-open mismatch");
  }
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_GARBLE_PASSES_MASK_WITNESS_H__
