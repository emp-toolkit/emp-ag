#ifndef EMP_AG_BACKEND_INPUT_AUTH_H__
#define EMP_AG_BACKEND_INPUT_AUTH_H__
//
// Out-of-line AGMPCProtocol<nP> method bodies: input authentication
// (process_inputs / process_input / load_inputs), output decode (decode), and output
// gather (gather_outputs). Kept out of protocol.h so the coordinator stays thin; these
// are member definitions, so ComputeCtx and the class state resolve in class scope.
// Tail-included by protocol.h (and self-standing via the include below).
//
#include "emp-ag/backend/protocol.h"
#include "emp-ag/backend/crypto/fs_hash.h"  // FsHash (FS/check digests)
#include "emp-ag/backend/crypto/protocols.h"   // EchoBC

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

  // Authenticated λ-shares (Π_aShare), drawn in one batch. The pool
  // stores AoS-by-wire, so draw is a single memcpy into sw.wire_bundle.
  // Each share-bit λ_w^i is implicit in bit0(sw.wire_bundle[w].mac(0)).
  // The draw's share-consistency residual stays pending: the open below
  // publishes only Λ_w = λ_w ⊕ x_w, which the owner's own share masks whatever
  // bits the other parties hold, and the next open check or decode settles it.
  fpre->abit.draw(n_total, sw.wire_bundle);
  fpre->abit.maybe_flush_cot_check();

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

  // OpenTo(<λ_w>, owner) for EVERY owning party in ONE all-to-all round; each owner then
  // sets Λ_w = λ_w ⊕ x_w for its own wires. open_to_targets sends target t only t's wires, so a
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
  fpre->abit.draw(n, sw.wire_bundle);
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
  fpre->abit.maybe_flush_cot_check();
  fpre->abit.settle_check2();
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

// One-round all-to-all authenticated open. targets[t] = wires to open to party t. Every party
// sends each non-empty target t != self ONE message [share bits][MAC digest under t's key]; each
// target verifies every peer (key ^ bit·Δ) and reconstructs λ_w = ⊕_p λ_w^p. Returns the bits
// for targets[self] (empty if self is not a target). One message per directed pair -> the
// per-channel transcript is deterministic and a party sees only shares of wires opened TO IT.
template <int nP, class Cfg>
std::vector<unsigned char> AGMPCProtocol<nP, Cfg>::open_to_targets(
    const AShareBundle<nP> *base, const std::vector<std::vector<int>> &targets) {
  std::vector<std::vector<unsigned char>> tx(nP + 1);   // share bits I send to target t
  std::vector<std::vector<char>> txd(nP + 1);           // MAC digest I send to target t
  for (int t = 1; t <= nP; ++t) {
    if (t == party || targets[t].empty()) continue;
    int m = (int)targets[t].size();
    tx[t].resize(m);
    txd[t].resize(FsHash::DIGEST_SIZE);
    BlockVec macs(m);
    int slot = peer_slot(party, t);
    for (int j = 0; j < m; ++j) {
#ifdef EMP_AG_TEST_TWO_WORLD
      // TEST-ONLY (never in production): party 2 sends each target the bit it holds
      // toward that target (with EMP_AG_TEST_SPLIT_CHOICE those differ), so every
      // target's MAC check passes.
      tx[t][j] = (unsigned char)getLSB(base[targets[t][j]].mac(party == 2 ? slot : 0));
#else
      tx[t][j] = (unsigned char)getLSB(base[targets[t][j]].mac(0));
#endif
      macs[j] = base[targets[t][j]].mac(slot);
    }
    FsHash::hash_once(txd[t].data(), macs.data(), (size_t)m * sizeof(block));
  }

  const std::vector<int> &mine = targets[party];
  int mm = (int)mine.size();
  std::vector<std::vector<unsigned char>> rx(nP + 1);   // peer p's shares of MY wires
  std::vector<std::vector<char>> rxd(nP + 1);           // peer p's MAC digest
  if (mm > 0)
    for (int p = 1; p <= nP; ++p) if (p != party) {
      rx[p].resize(mm);
      rxd[p].resize(FsHash::DIGEST_SIZE);
    }

  // One round: send to every target + (if I'm a target) recv from every peer, concurrently.
  std::vector<future<void>> res;
  for (int t = 1; t <= nP; ++t) if (t != party && !targets[t].empty()) {
    int tt = t;
    res.push_back(pool->enqueue([this, &tx, &txd, tt]() {
      io->send_bool(tt, (const bool *)tx[tt].data(), (int)tx[tt].size());
      io->send_data(tt, txd[tt].data(), FsHash::DIGEST_SIZE);
      io->flush(tt);
    }));
  }
  if (mm > 0)
    for (int p = 1; p <= nP; ++p) if (p != party) {
      int pp = p;
      res.push_back(pool->enqueue([this, &rx, &rxd, pp, mm]() {
        io->recv_bool(pp, (bool *)rx[pp].data(), mm);
        io->recv_data(pp, rxd[pp].data(), FsHash::DIGEST_SIZE);
      }));
    }
  joinNclean(res);
  if (mm == 0) return {};

  // Verify each peer's shares of MY wires against my keys, then reconstruct λ = ⊕_p λ^p.
  std::vector<unsigned char> my_share(mm);
  for (int j = 0; j < mm; ++j) my_share[j] = (unsigned char)getLSB(base[mine[j]].mac(0));
  BlockVec exp_macs(mm);
  for (int p = 1; p <= nP; ++p) if (p != party) {
    int slot = peer_slot(party, p);
    for (int j = 0; j < mm; ++j)
      exp_macs[j] = base[mine[j]].key(slot) ^ (select_mask[rx[p][j]] & Delta);
    char D_exp[FsHash::DIGEST_SIZE];
    FsHash::hash_once(D_exp, exp_macs.data(), (size_t)mm * sizeof(block));
    expecting(memcmp(D_exp, rxd[p].data(), FsHash::DIGEST_SIZE) == 0,
              "open_to_targets: share-MAC hash mismatch");
  }
  std::vector<unsigned char> lam(mm);
  for (int j = 0; j < mm; ++j) {
    unsigned char v = my_share[j];
    for (int p = 1; p <= nP; ++p) if (p != party) v = v ^ rx[p][j];
    lam[j] = (unsigned char)(v & 1);
  }
  return lam;
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
  fpre->abit.maybe_flush_cot_check();
  fpre->abit.settle_check2();
  // Reveal via a MAC-checked open of the wire masks. Every reconstructing party
  // verifies each peer's lambda-share against its OWN (c_gamma-authenticated) keys and forms
  // y_w = Λ_w ⊕ ⊕_p λ_w^p locally -- not trusting P1 to reconstruct and broadcast raw bits. Also
  // serves reactive host branching (every party learns the same value). PUBLIC (OpenToAll) opens
  // every wire to EVERY party in ONE all-to-all round (open_to_targets), not nP sequential
  // OpenTo(i); a directed reveal opens only to `recipient`.
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
// wires. P1 sends each garbler the outputs' Lambda and a hash of that garbler's active
// labels on them; the garbler rebuilds those labels from its 0-labels and checks the
// hash. Changing a bit would take the garbler's label for the other value, hence its
// Delta.
template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::deliver_output_masks_(SecureWires<nP> &out) {
  const int n = (int)out.size();
  if (n == 0) return;
  char h[FsHash::DIGEST_SIZE];
  if (party == 1) {
    for (int i = 2; i <= nP; ++i) {
      FsHash::hash_once(h, out.eval_label[i].data(), (size_t)n * sizeof(block));
#ifdef EMP_AG_TEST_FLIP_DELIVERED_LAMBDA
      // TEST-ONLY (never in production): P1 sends garbler 2 the first output's Lambda
      // flipped, with the honest hash. Garbler 2's check must fail.
      if (i == 2) {
        std::vector<unsigned char> bad(out.Lambda);
        bad[0] ^= 1;
        io->send_bool(i, (const bool *)bad.data(), n);
        io->send_data(i, h, FsHash::DIGEST_SIZE);
        io->flush(i);
        continue;
      }
#endif
      io->send_bool(i, (const bool *)out.Lambda.data(), n);
      io->send_data(i, h, FsHash::DIGEST_SIZE);
      io->flush(i);
    }
    return;
  }
  std::vector<unsigned char> lam((size_t)n);
  io->recv_bool(1, (bool *)lam.data(), n);
  io->recv_data(1, h, FsHash::DIGEST_SIZE);
  BlockVec active((size_t)n);
  for (int k = 0; k < n; ++k) active[k] = out.label0[k] ^ (select_mask[lam[k] & 1] & Delta);
  char expect[FsHash::DIGEST_SIZE];
  FsHash::hash_once(expect, active.data(), (size_t)n * sizeof(block));
  expecting(memcmp(expect, h, FsHash::DIGEST_SIZE) == 0,
            "WRK: P1's output masks do not match its labels");
  out.Lambda = std::move(lam);
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_INPUT_AUTH_H__
