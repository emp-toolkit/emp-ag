#ifndef EMP_AG_BACKEND_GARBLE_INPUT_AUTH_H__
#define EMP_AG_BACKEND_GARBLE_INPUT_AUTH_H__
//
// Out-of-line AGMPCProtocol<nP> method bodies: input authentication
// (process_inputs / process_input / load_inputs), output decode (decode), and output
// gather (gather_outputs). Kept out of protocol.h so the coordinator stays thin; these
// are member definitions, so ComputeCtx and the class state resolve in class scope.
// Tail-included by protocol.h (and self-standing via the include below).
//
#include "emp-ag/backend/garble/protocol.h"
#include "emp-ag/backend/ashare/open.h"   // open_to_targets
#include "emp-ag/backend/common/fs_hash.h"  // FsHash (FS/check digests)
#include "emp-ag/backend/common/protocols.h"   // EchoBC

namespace emp::ag {

template <int nP, class Cfg>
std::vector<SecureWires<nP>> AGMPCProtocol<nP, Cfg>::process_inputs(
    const std::vector<int> &owners,
    const std::vector<std::vector<bool>> &bits_per_owner) {
  AG_PHASE_BEGIN();
  const int K = (int)owners.size();
  expecting((int)bits_per_owner.size() == K,
            "process_inputs: owner and bit-vector counts differ");
  for (int k = 0; k < K; ++k)
    expecting(owners[k] >= 1 && owners[k] <= nP,
              "process_inputs: owner id out of range [1, nP]");
  int n_total = 0;
  std::vector<int> off_per_owner(K);
  for (int k = 0; k < K; ++k) {
    off_per_owner[k] = n_total;
    n_total += (int)bits_per_owner[k].size();
  }
  if (n_total == 0) {
    AG_PHASE("process_inputs[empty]");
    return std::vector<SecureWires<nP>>(K);
  }

  SecureWires<nP> sw;
  sw.Lambda.resize(n_total);
  if (party != 1)
    sw.label0.resize(n_total);
  else
    for (int j = 2; j <= nP; ++j) sw.eval_label[j].resize(n_total);

  // Authenticated λ-shares (Π_aShare), drawn in one batch; draw() transposes
  // the generator's per-peer MAC/key arrays into the wire bundles.
  // Each share-bit λ_w^i is implicit in bit0(sw.wire_bundle[w].mac(0)).
  // The draw's share-consistency view stays pending: the open below
  // publishes only Λ_w = λ_w ⊕ x_w, which the owner's own share masks whatever
  // bits the other parties hold, and the next open check or decode settles it.
  abit->draw(n_total, sw.wire_bundle);
  abit->maybe_flush_cot_check();

  // Pi (i ≥ 2) samples m_{w, 0}^i for each input wire.
  if (party != 1)
    prg.random_block(sw.label0.data(), n_total);

  // Open λ_w to the OWNER only; the owner forms Λ_w = λ_w ⊕ x_w
  // and broadcasts the public Λ_w. No party but the owner sees λ_w or x_w — the owner's own
  // mask λ_w^{owner}, folded into Λ, is never opened, so a curious/corrupt evaluator (or any
  // peer) learns nothing about the inputs. Λ's correctness is bound downstream by c_gamma.
  //
  // Batch by OWNING PARTY (not by owner-entry): one ordered open + one broadcast message per
  // party, so a party owning several input batches never races multiple sends on one channel
  // (which would scramble the transcript that the F_eq / coin checks hash).
  std::vector<std::vector<int>> wires_of(nP + 1);   // t -> the input wires owned by party t
  for (int k = 0; k < K; ++k) {
    int off = off_per_owner[k];
    for (int i = 0; i < (int)bits_per_owner[k].size(); ++i)
      wires_of[owners[k]].push_back(off + i);
  }
  std::vector<unsigned char> x_of(n_total, 0);       // my cleartext bit per wire I own
  for (int k = 0; k < K; ++k) if (party == owners[k]) {
    int off = off_per_owner[k];
    for (int i = 0; i < (int)bits_per_owner[k].size(); ++i)
      x_of[off + i] = (unsigned char)bits_per_owner[k][i];
  }

  // Open <λ_w> to its owner, for EVERY owning party in ONE all-to-all round; each owner
  // then sets Λ_w = λ_w ⊕ x_w for its own wires. open_to_targets sends target t only t's wires, so a
  // party learns λ only for wires it owns (input privacy).
  {
    std::vector<unsigned char> lam = open_to_targets(sw.wire_bundle.data(), wires_of);
    for (size_t j = 0; j < wires_of[party].size(); ++j) {
      int w = wires_of[party][j];
      sw.Lambda[w] = (unsigned char)((lam[j] ^ x_of[w]) & 1);
    }
  }

  broadcast_input_masks_(sw, wires_of);

  // Garblers ship m_{w,Λ_w} = label0 ⊕ Λ·Δ to the evaluator P1.
  exchange_input_labels_(sw, n_total);
  AG_PHASE("process_inputs");

  std::vector<SecureWires<nP>> result(K);
  for (int k = 0; k < K; ++k) {
    int off = off_per_owner[k];
    int n = (int)bits_per_owner[k].size();
    result[k] = sw.slice((size_t)off, (size_t)(off + n));
  }
  return result;
}

template <int nP, class Cfg>
SecureWires<nP> AGMPCProtocol<nP, Cfg>::process_input(const bool *inputs, int n,
                                                int owner) {
  std::vector<int> owners{owner};
  std::vector<std::vector<bool>> bits(1);
  bits[0].resize(n);
  if (inputs)
    for (int i = 0; i < n; ++i) bits[0][i] = inputs[i];
  return process_inputs(owners, bits)[0];
}

// Broadcast the owner-computed input masks and realize F_BC for them.  `wires_of`
// contains only the wires whose masks need an owner broadcast; prepared soldered
// inputs are already fixed by an authenticated public open and are deliberately
// omitted.  The echo still covers the complete Lambda vector whenever at least one
// owner broadcast occurs, so mixed staged/persistent binding has one agreed view.
template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::broadcast_input_masks_(
    SecureWires<nP> &sw, const std::vector<std::vector<int>> &wires_of) {
  bool any = false;
  for (int t = 1; t <= nP; ++t) any = any || !wires_of[t].empty();
  if (!any) return;

  const int mm = (int)wires_of[party].size();
  std::vector<unsigned char> mybuf(mm);
  for (int j = 0; j < mm; ++j) mybuf[j] = sw.Lambda[wires_of[party][j]];
  std::vector<std::vector<unsigned char>> rxbuf(nP + 1);
  for (int t = 1; t <= nP; ++t)
    if (t != party && !wires_of[t].empty()) rxbuf[t].resize(wires_of[t].size());
  std::vector<future<void>> res;
  if (mm > 0)
    for (int p = 1; p <= nP; ++p) if (p != party) {
      int pp = p;
      res.push_back(pool->enqueue([this, &mybuf, mm, pp]() {
#ifdef EMP_AG_TEST_FLIP_INPUT_LAMBDA
        // TEST-ONLY: an equivocating owner must still be caught on prepared input.
        std::vector<unsigned char> b = mybuf;
        int victim = (party == 1) ? 2 : 1;
        if (mm > 0 && pp == victim) b[0] ^= 1;
        io->send_bool(pp, (const bool *)b.data(), mm);
#else
        io->send_bool(pp, (const bool *)mybuf.data(), mm);
#endif
        io->flush(pp);
      }));
    }
  for (int t = 1; t <= nP; ++t) if (t != party && !wires_of[t].empty()) {
    int tt = t, tm = (int)wires_of[t].size();
    res.push_back(pool->enqueue([this, &rxbuf, tt, tm]() {
      io->recv_bool(tt, (bool *)rxbuf[tt].data(), tm);
    }));
  }
  joinNclean(res);
  for (int t = 1; t <= nP; ++t) if (t != party && !wires_of[t].empty())
    for (size_t j = 0; j < wires_of[t].size(); ++j)
      sw.Lambda[wires_of[t][j]] = rxbuf[t][j];

  if constexpr (nP > 2) {
    char h_me[FsHash::DIGEST_SIZE];
    FsHash::hash_once(h_me, sw.Lambda.data(),
                      sw.Lambda.size() * sizeof(unsigned char));
    EchoBC<nP> echo(io, pool, party);
    char view_buf[nP + 1][FsHash::DIGEST_SIZE];
    char *view[nP + 1];
    for (int p = 1; p <= nP; ++p) view[p] = view_buf[p];
    echo.all_bcast(h_me, FsHash::DIGEST_SIZE, view);
    for (int p = 1; p <= nP; ++p)
      expecting(memcmp(view[p], h_me, FsHash::DIGEST_SIZE) == 0,
                "input Lambda equivocation");
    echo.finalize();
  }
}

// Offline half of prepared input handling: mint a fresh authenticated mask and
// garbling-label pair for every circuit input, but do not name an owner, open a
// mask, or select an evaluator label.  Lambda/eval_label are zero placeholders
// solely so the ordinary slot loader can seed the offline circuit walks.
template <int nP, class Cfg>
SecureWires<nP> AGMPCProtocol<nP, Cfg>::make_prepared_inputs_(int n) {
  expecting(n >= 0, "make_prepared_inputs: negative input width");
  SecureWires<nP> sw;
  sw.Lambda.assign((size_t)n, 0);
  if (n == 0) return sw;
  abit->draw(n, sw.wire_bundle);
  if (party != 1) {
    sw.label0.resize((size_t)n);
    prg.random_block(sw.label0.data(), n);
  } else {
    for (int j = 2; j <= nP; ++j)
      sw.eval_label[j].assign((size_t)n, zero_block);
  }
  return sw;
}

// Online half of prepared input handling.  Every target position is either:
//
//   staged:      open lambda_target only to owner, then Lambda=x^lambda_target;
//   persistent:  open d=lambda_source^lambda_target to all, then
//                Lambda_target=Lambda_source^d.
//
// Both cases end in the same prepared target representation.  Owner broadcasts
// are batched and echoed once, then all selected target labels are exchanged in
// one input-label message per garbler.
template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::bind_prepared_inputs_(
    SecureWires<nP> &target, const PreparedInputBinding<nP> &binding) {
  const int n = (int)binding.size();
  expecting(target.size() == (size_t)n && target.wire_bundle.size() == (size_t)n,
            "bind_prepared_inputs: target width mismatch");
  expecting(binding.clear.size() == (size_t)n &&
                binding.source_lambda.size() == (size_t)n &&
                binding.source_bundle.size() == (size_t)n,
            "bind_prepared_inputs: binding arrays differ in width");
  if (n == 0) return;

  AShareBundleVec<nP> opened_base((size_t)n);
  std::vector<std::vector<int>> open_targets(nP + 1);
  std::vector<std::vector<int>> owner_wires(nP + 1);
  std::vector<int> mine_pos((size_t)n, -1);
  for (int w = 0; w < n; ++w) {
    const int owner = binding.owner[w];
    if (owner == 0) {
      xor_share(opened_base[w], target.wire_bundle[w],
                binding.source_bundle[w]);
      for (int t = 1; t <= nP; ++t) {
        if (t == party) mine_pos[w] = (int)open_targets[t].size();
        open_targets[t].push_back(w);
      }
    } else {
      expecting(owner >= 1 && owner <= nP,
                "bind_prepared_inputs: staged owner out of range [1, nP]");
      opened_base[w] = target.wire_bundle[w];
      if (owner == party) mine_pos[w] = (int)open_targets[owner].size();
      open_targets[owner].push_back(w);
      owner_wires[owner].push_back(w);
    }
  }

  // This is the first reveal of any correlation minted for the job.  prepare()
  // normally leaves the checks clean already; the guards keep this boundary safe
  // however the material was produced and are wire-free on the clean path.
  abit->maybe_flush_cot_check();
  abit->settle_check2();
  std::vector<unsigned char> opened =
      open_to_targets(opened_base.data(), open_targets);
  for (int w = 0; w < n; ++w) {
    if (binding.owner[w] == 0) {
      target.Lambda[w] =
          (unsigned char)((opened[(size_t)mine_pos[w]] ^
                           binding.source_lambda[w]) & 1);
    } else if (binding.owner[w] == party) {
      target.Lambda[w] =
          (unsigned char)((opened[(size_t)mine_pos[w]] ^ binding.clear[w]) & 1);
    }
  }

  broadcast_input_masks_(target, owner_wires);
  exchange_input_labels_(target, n);
}

// Offline half of a Computation's input handling, after the prepared material is
// garbled: open each Party input's target mask to its owner and each Public
// input's to every party, in one MAC-checked round.  A Public input's mask then
// is public, and its masked value b ^ lambda follows from the public bit at every
// party; no owner broadcast is needed for it online.
template <int nP, class Cfg>
std::vector<unsigned char> AGMPCProtocol<nP, Cfg>::open_computation_input_masks_(
    const SecureWires<nP> &target, const std::vector<int> &owner) {
  const int n = (int)owner.size();
  expecting(target.wire_bundle.size() == (size_t)n,
            "open_computation_input_masks: target width mismatch");
  std::vector<unsigned char> mine((size_t)n, 0);
  if (n == 0) return mine;
  std::vector<std::vector<int>> targets(nP + 1);
  for (int w = 0; w < n; ++w) {
    expecting(owner[w] == PUBLIC || (owner[w] >= 1 && owner[w] <= nP),
              "open_computation_input_masks: owner must be a party id in [1, nP] or PUBLIC");
    if (owner[w] == PUBLIC)
      for (int t = 1; t <= nP; ++t) targets[t].push_back(w);
    else
      targets[owner[w]].push_back(w);
  }
  // Every check of the job's preprocessing completes before its first opening;
  // the guards also settle anything an earlier call left pending, and are
  // wire-free on the clean path.
  abit->maybe_flush_cot_check();
  abit->settle_check2();
  std::vector<unsigned char> lam = open_to_targets(target.wire_bundle.data(), targets);
  const std::vector<int> &me = targets[party];
  for (size_t j = 0; j < me.size(); ++j) mine[(size_t)me[j]] = (unsigned char)(lam[j] & 1);
  return mine;
}

// Online half: `lambda` holds Lambda = x ^ mask for this party's own Party inputs
// and b ^ mask for every Public input.  The owners broadcast their masked values
// (echoed at nP > 2, over the whole Lambda vector), then the garblers send P1 the
// selected labels of every input.
template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::bind_computation_inputs_(
    SecureWires<nP> &target, const std::vector<int> &owner,
    const std::vector<unsigned char> &lambda) {
  const int n = (int)owner.size();
  expecting(target.size() == (size_t)n && lambda.size() == (size_t)n,
            "bind_computation_inputs: width mismatch");
  if (n == 0) return;
  std::vector<std::vector<int>> owner_wires(nP + 1);
  for (int w = 0; w < n; ++w) {
    if (owner[w] == PUBLIC || owner[w] == party)
      target.Lambda[w] = (unsigned char)(lambda[w] & 1);
    if (owner[w] != PUBLIC) owner_wires[owner[w]].push_back(w);
  }
  broadcast_input_masks_(target, owner_wires);
  exchange_input_labels_(target, n);
}

// Input-label exchange, shared with adopt_authenticated_input: garblers (Pi, i>=2)
// ship m_{w,Λ_w} = label0[w] ⊕ Λ_w·Δ to the evaluator P1, who stores eval_label.
template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::exchange_input_labels_(SecureWires<nP> &sw, int n_total) {
  if (party != 1) {
    BlockVec tmp(n_total);
    for (int i = 0; i < n_total; ++i)
      tmp[i] = sw.Lambda[i] ? (sw.label0[i] ^ Delta) : sw.label0[i];
    io->send_data(1, tmp.data(), n_total * sizeof(block));
    io->flush(1);
  } else {
    std::vector<future<void>> res;
    for (int p2 = 2; p2 <= nP; ++p2) {
      int party2 = p2;
      res.push_back(pool->enqueue([this, &sw, n_total, party2]() {
        io->recv_data(party2, sw.eval_label[party2].data(),
                      n_total * sizeof(block));
      }));
    }
    joinNclean(res);
  }
}

// Adopt externally-authenticated aShare bundles as input wires WITHOUT drawing
// fresh COTs -- the generic reactive-input primitive. The bundles ARE the wire
// mask λ: one-sided (known to whoever owns the value; other parties hold only the
// key), so the aShare "degrades" to a plain IT-MAC of the value (e.g. a value
// authenticated by another protocol under this session's keys). Λ is fixed 0, hence
// the wire value equals λ and Λ=0 leaks nothing (a non-owner never learns λ). The
// caller must supply bundles authenticated under this protocol instance's existing
// global keys/Delta; cross-session material is not translated. Only the
// garbling-label exchange runs.
template <int nP, class Cfg>
SecureWires<nP> AGMPCProtocol<nP, Cfg>::adopt_authenticated_input(
    const AShareBundle<nP> *bundles, int n) {
  SecureWires<nP> sw;
  sw.Lambda.assign((size_t)n, 0);                       // Λ = 0
  sw.wire_bundle.assign(bundles, bundles + n);          // provided IT-MAC = mask λ
  if (party != 1) { sw.label0.resize(n); prg.random_block(sw.label0.data(), n); }
  else for (int j = 2; j <= nP; ++j) sw.eval_label[j].resize(n);
  exchange_input_labels_(sw, n);
  return sw;
}

// Copy each input SecureWires bundle into wire indices [0, num_in) in order;
// inputs occupy slots [0, num_in). SecureWires is AoS, so this is a pure memcpy.
template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::load_inputs(ComputeCtx &ctx, const SecureWires<nP> *const *inputs,
                           int n_inputs) {
  size_t off = 0;
  for (int b = 0; b < n_inputs; ++b) {
    const SecureWires<nP> &in = *inputs[b];
    size_t n = in.size();
    memcpy(ctx.mask_input.data() + off, in.Lambda.data(), n);
    memcpy(&ctx.wire_slot[off], in.wire_bundle.data(),
           n * sizeof(AShareBundle<nP>));
    if (party != 1) {
      memcpy(ctx.label_slot.data() + off, in.label0.data(), n * sizeof(block));
    } else {
      for (int j = 2; j <= nP; ++j)
        memcpy(ctx.eval_slot[j].data() + off, in.eval_label[j].data(),
               n * sizeof(block));
    }
    off += n;
  }
}

// open_to_targets (ashare/open.h) over this session's mesh and keys.
template <int nP, class Cfg>
std::vector<unsigned char> AGMPCProtocol<nP, Cfg>::open_to_targets(
    const AShareBundle<nP> *base, const std::vector<std::vector<int>> &targets) {
  return ag::open_to_targets<nP>(io, pool, party, Delta, base, targets);
}

template <int nP, class Cfg>
std::vector<bool> AGMPCProtocol<nP, Cfg>::decode(const SecureWires<nP> &wires,
                                         int recipient) {
  int n = (int)wires.size();
  // Validate `recipient` here too, not only at the frontend (agmpc_session.h): decode() is a
  // documented expert/backend entry point, and an out-of-range recipient would index
  // `targets[recipient]` below out of bounds (OOB vector write / UB).
  expecting(recipient == PUBLIC || (recipient >= 1 && recipient <= nP),
            "AGMPCProtocol::decode: recipient must be a party id in [1, nP] or PUBLIC");
  // Any party may decode: every party holds checked Lambda for the outputs (the symmetric
  // SPDZ c_gamma MACCheck under Auth::KRRW; P1's per-gate checks and the garblers' check
  // of the delivered output Lambda under Auth::WRK), so `recipient` is a pure delivery
  // choice (which party reconstructs this open, or PUBLIC = all).
  AG_PHASE_BEGIN();
  abit->maybe_flush_cot_check();
  abit->settle_check2();
  // Reveal via a MAC-checked open of the wire masks. Every reconstructing party
  // verifies each peer's lambda-share against its OWN (c_gamma-authenticated) keys and forms
  // y_w = Λ_w ⊕ ⊕_p λ_w^p locally -- not trusting P1 to reconstruct and broadcast raw bits. Also
  // serves reactive host branching (every party learns the same value). PUBLIC opens every
  // wire to EVERY party in ONE all-to-all round (open_to_targets), not nP sequential
  // openings to one party each; a directed reveal opens only to `recipient`.
  std::vector<int> all(n);
  for (int i = 0; i < n; ++i) all[i] = i;
  std::vector<std::vector<int>> targets(nP + 1);
  if (recipient == PUBLIC) for (int t = 1; t <= nP; ++t) targets[t] = all;
  else                     targets[recipient] = all;
  std::vector<unsigned char> lam = open_to_targets(wires.wire_bundle.data(), targets);
  std::vector<bool> result;
  if (recipient == PUBLIC || party == recipient) {
    result.resize(n);
    for (int i = 0; i < n; ++i)
      result[i] = ((lam[i] ^ wires.Lambda[i]) & 1);
  }
  AG_PHASE("decode");
  return result;
}

// Gather output SecureWires by explicit wire id; outputs are pinned to permanent
// slots and need not be contiguous or at the tail. Member definition, so ComputeCtx
// resolves in class scope.
template <int nP, class Cfg>
SecureWires<nP> AGMPCProtocol<nP, Cfg>::gather_outputs(ComputeCtx &ctx,
                                         const std::vector<int> &output_ids) {
  SecureWires<nP> out;
  int n3 = (int)output_ids.size();
  out.Lambda.resize(n3);
  out.wire_bundle.resize(n3);
  for (int i = 0; i < n3; ++i) {
    out.Lambda[i] = ctx.MASK(output_ids[i]);       // outputs: persistent slots
    out.wire_bundle[i] = ctx.WIRE(output_ids[i]);
  }
  if (party != 1) {
    out.label0.resize(n3);
    for (int i = 0; i < n3; ++i) out.label0[i] = ctx.LABEL(output_ids[i]);
  } else {
    for (int j = 2; j <= nP; ++j) {
      out.eval_label[j].resize(n3);
      for (int i = 0; i < n3; ++i) out.eval_label[j][i] = ctx.EVAL(j, output_ids[i]);
    }
  }
  return out;
}

// Auth::WRK: after evaluation only P1 knows the masked values Lambda of AND-derived
// wires. The direct paths hand every garbler every output: the hand-off below with
// all positions for every garbler.
template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::deliver_output_masks_(SecureWires<nP> &out) {
  std::vector<int> all(out.size());
  for (size_t k = 0; k < all.size(); ++k) all[k] = (int)k;
  deliver_output_masks_to_(out, std::vector<std::vector<int>>(nP + 1, all));
}

// Auth::WRK hand-off. P1 sends garbler i the Lambda of the output positions in
// positions_of[i] and a hash of that garbler's active labels on them; the garbler
// rebuilds those labels from its 0-labels and checks the hash. Changing a bit would
// take the garbler's label for the other value, hence its Delta. A Computation
// lists only the positions a garbler receives, never another's, and takes this path
// with or without AND gates: its garblers never derive a masked value themselves.
template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::deliver_output_masks_to_(
    SecureWires<nP> &out, const std::vector<std::vector<int>> &positions_of) {
  char h[FsHash::DIGEST_SIZE];
  if (party == 1) {
    for (int i = 2; i <= nP; ++i) {
      const std::vector<int> &pos = positions_of[i];
      const int m = (int)pos.size();
      if (m == 0) continue;
      std::vector<unsigned char> lam((size_t)m);
      BlockVec active((size_t)m);
      for (int k = 0; k < m; ++k) {
        lam[k] = out.Lambda[pos[k]];
        active[k] = out.eval_label[i][pos[k]];
      }
      FsHash::hash_once(h, active.data(), (size_t)m * sizeof(block));
#ifdef EMP_AG_TEST_FLIP_DELIVERED_LAMBDA
      // TEST-ONLY (never in production): garbler 2 gets its first Lambda flipped,
      // with the honest hash. Garbler 2's check must fail.
      if (i == 2) lam[0] ^= 1;
#endif
      io->send_bool(i, (const bool *)lam.data(), m);
      io->send_data(i, h, FsHash::DIGEST_SIZE);
      io->flush(i);
    }
    return;
  }
  const std::vector<int> &pos = positions_of[party];
  const int m = (int)pos.size();
  if (m == 0) return;
  std::vector<unsigned char> lam((size_t)m);
  io->recv_bool(1, (bool *)lam.data(), m);
  io->recv_data(1, h, FsHash::DIGEST_SIZE);
  BlockVec active((size_t)m);
  for (int k = 0; k < m; ++k)
    active[k] = out.label0[pos[k]] ^ (select_mask[lam[k] & 1] & Delta);
  char expect[FsHash::DIGEST_SIZE];
  FsHash::hash_once(expect, active.data(), (size_t)m * sizeof(block));
  expecting(memcmp(expect, h, FsHash::DIGEST_SIZE) == 0,
            "WRK: P1's output masks do not match its labels");
  for (int k = 0; k < m; ++k) out.Lambda[pos[k]] = (unsigned char)(lam[k] & 1);
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_GARBLE_INPUT_AUTH_H__
