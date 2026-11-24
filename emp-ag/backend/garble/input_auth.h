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
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

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

// Share mode: process_inputs without the garbling labels. One draw of n masks, each
// opened to the owner only; the owner broadcasts x ^ mask (echoed at nP > 2), and every
// party folds that public bit into its share of the mask, giving an aShare of x. The
// draw's consistency view stays pending, as in process_inputs: the broadcast reveals only
// x ^ mask, and the next open check or opening settles it.
template <int nP, class Cfg>
AShareBundleVec<nP> AGMPCProtocol<nP, Cfg>::share_inputs(int owner, const unsigned char *bits,
                                                         int n) {
  expecting(owner >= 1 && owner <= nP, "share_inputs: owner id out of range [1, nP]");
  expecting(n >= 0, "share_inputs: a negative count");
  expecting(party != owner || n == 0 || bits != nullptr, "share_inputs: the owner's bits are missing");
  if (n == 0) return {};
  SecureWires<nP> sw;   // the masks and their public Λ only
  sw.Lambda.assign((size_t)n, 0);
  abit->draw(n, sw.wire_bundle);
  abit->maybe_flush_cot_check();
  std::vector<std::vector<int>> wires_of(nP + 1);
  wires_of[owner].resize((size_t)n);
  for (int i = 0; i < n; ++i) wires_of[owner][(size_t)i] = i;
  const std::vector<unsigned char> lam = open_to_targets(sw.wire_bundle.data(), wires_of);
  if (party == owner)
    for (int i = 0; i < n; ++i) sw.Lambda[(size_t)i] = (unsigned char)((lam[(size_t)i] ^ bits[i]) & 1);
  broadcast_input_masks_(sw, wires_of);
  AShareBundleVec<nP> out = std::move(sw.wire_bundle);
  for (int i = 0; i < n; ++i)
    if (sw.Lambda[(size_t)i])
      add_public_one<nP>(party, Delta,
                         [&](int p) -> block & { return out[(size_t)i].mac(peer_slot(party, p)); },
                         [&](int p) -> block & { return out[(size_t)i].key(peer_slot(party, p)); });
  return out;
}

// Share mode: open n aShares, each recipient checking every peer's share against its own
// keys. The COT check is flushed and the consistency view settled first, as in decode().
template <int nP, class Cfg>
std::vector<unsigned char> AGMPCProtocol<nP, Cfg>::share_open(const AShareBundle<nP> *b, int n,
                                                              int recipient) {
  expecting(recipient == PUBLIC || (recipient >= 1 && recipient <= nP),
            "share_open: recipient must be a party id in [1, nP] or PUBLIC");
  expecting(n >= 0, "share_open: a negative count");
  abit->maybe_flush_cot_check();
  abit->settle_check2();
  std::vector<int> all((size_t)n);
  for (int i = 0; i < n; ++i) all[(size_t)i] = i;
  std::vector<std::vector<int>> targets(nP + 1);
  if (recipient == PUBLIC) for (int t = 1; t <= nP; ++t) targets[t] = all;
  else                     targets[recipient] = all;
  return open_to_targets(b, targets);
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
        if constexpr (kTestHooks) {
          // TEST-ONLY (hook flip_input_lambda): an owner equivocates, sending one peer a
          // flipped bit. It must still be caught on prepared input.
          if (hooks().flip_input_lambda && pp == ((party == 1) ? 2 : 1)) {
            std::vector<unsigned char> b = mybuf;
            b[0] ^= 1;
            io->send_bool(pp, (const bool *)b.data(), mm);
            io->flush(pp);
            return;
          }
        }
        io->send_bool(pp, (const bool *)mybuf.data(), mm);
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
// solely so the ordinary slot loader can seed the offline circuit walks.  A wire
// bound at prepare takes its value as the mask, with Lambda 0 for good, and draws
// none: one draw covers the other wires, in order.
template <int nP, class Cfg>
SecureWires<nP> AGMPCProtocol<nP, Cfg>::make_prepared_inputs_(int n,
                                                              const PreparedBound<nP> *bound) {
  expecting(n >= 0, "make_prepared_inputs: negative input width");
  expecting(bound == nullptr || (bound->bound.size() == (size_t)n && bound->bundle.size() == (size_t)n),
            "make_prepared_inputs: bound inputs differ in width");
  SecureWires<nP> sw;
  sw.Lambda.assign((size_t)n, 0);
  if (n == 0) return sw;
  if (bound == nullptr) {
    abit->draw(n, sw.wire_bundle);
  } else {
    int fresh_n = 0;
    for (int w = 0; w < n; ++w) fresh_n += bound->bound[(size_t)w] ? 0 : 1;
    AShareBundleVec<nP> fresh;
    if (fresh_n > 0) abit->draw(fresh_n, fresh);
    sw.wire_bundle.resize((size_t)n);
    for (int w = 0, j = 0; w < n; ++w)
      sw.wire_bundle[(size_t)w] = bound->bound[(size_t)w] ? bound->bundle[(size_t)w] : fresh[(size_t)j++];
  }
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
    SecureWires<nP> &target, const std::vector<int> &owner,
    const std::vector<unsigned char> *bound) {
  const int n = (int)owner.size();
  expecting(target.wire_bundle.size() == (size_t)n,
            "open_computation_input_masks: target width mismatch");
  expecting(bound == nullptr || bound->empty() || bound->size() == (size_t)n,
            "open_computation_input_masks: bound flags differ in width");
  std::vector<unsigned char> mine((size_t)n, 0);
  if (n == 0) return mine;
  auto is_bound = [&](int w) { return bound != nullptr && !bound->empty() && (*bound)[(size_t)w] != 0; };
  std::vector<std::vector<int>> targets(nP + 1);
  std::vector<int> bound_wires;
  for (int w = 0; w < n; ++w) {
    expecting(owner[w] == PUBLIC || (owner[w] >= 1 && owner[w] <= nP),
              "open_computation_input_masks: owner must be a party id in [1, nP] or PUBLIC");
    if (is_bound(w)) {
      bound_wires.push_back(w);
      continue;
    }
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
  // A bound wire's masked value is 0, known now: its labels go to P1 offline.
  if (!bound_wires.empty()) exchange_input_labels_(target, bound_wires);
  return mine;
}

// Online half: `lambda` holds Lambda = x ^ mask for this party's own Party inputs
// and b ^ mask for every Public input.  The owners broadcast their masked values
// (echoed at nP > 2, over the whole Lambda vector), then the garblers send P1 the
// selected labels of every input.
//
// A wire with an authenticated source takes no broadcast. Its value is the source's,
// an aShare under this session's global keys (Lambda 0, so the source bundle is the
// value's sharing). Every party opens d = source ^ mask under the MAC check of
// open_to_targets, and Lambda = d: the computation's input is then exactly the
// source's value. Opening the mask to the slot's owner at prepare time does not change
// this: the other parties learn only d, as from a broadcast. As before every other
// opening, the deferred COT check and check2 run first: the caller may have drawn COTs
// (draw_cots) for the sources since prepare_computation; with none drawn, nothing is sent.
template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::bind_computation_inputs_(
    SecureWires<nP> &target, const std::vector<int> &owner,
    const std::vector<unsigned char> &lambda, const AShareBundle<nP> *source,
    const std::vector<unsigned char> *from_source, const std::vector<unsigned char> *bound) {
  const int n = (int)owner.size();
  expecting(target.size() == (size_t)n && lambda.size() == (size_t)n,
            "bind_computation_inputs: width mismatch");
  expecting(source == nullptr || (from_source != nullptr && from_source->size() == (size_t)n),
            "bind_computation_inputs: source flags differ in width");
  expecting(bound == nullptr || bound->empty() || bound->size() == (size_t)n,
            "bind_computation_inputs: bound flags differ in width");
  if (n == 0) return;
  auto sourced = [&](int w) { return source != nullptr && (*from_source)[(size_t)w] != 0; };
  auto is_bound = [&](int w) { return bound != nullptr && !bound->empty() && (*bound)[(size_t)w] != 0; };
  std::vector<int> source_wires, unbound_wires;
  for (int w = 0; w < n; ++w) {
    expecting(!(sourced(w) && is_bound(w)), "bind_computation_inputs: a wire is both bound and sourced");
    if (sourced(w)) source_wires.push_back(w);
    if (!is_bound(w)) unbound_wires.push_back(w);
  }
  if (!source_wires.empty()) {
    abit->maybe_flush_cot_check();
    abit->settle_check2();
    AShareBundleVec<nP> d((size_t)n);
    std::vector<std::vector<int>> to_all(nP + 1);
    for (int w : source_wires) {
      xor_share(d[(size_t)w], target.wire_bundle[(size_t)w], source[w]);
      for (int t = 1; t <= nP; ++t) to_all[(size_t)t].push_back(w);
    }
    const std::vector<unsigned char> opened = open_to_targets(d.data(), to_all);
    for (size_t j = 0; j < source_wires.size(); ++j)
      target.Lambda[(size_t)source_wires[j]] = (unsigned char)(opened[j] & 1);
  }
  std::vector<std::vector<int>> owner_wires(nP + 1);
  for (int w = 0; w < n; ++w) {
    if (sourced(w) || is_bound(w)) continue;
    if (owner[w] == PUBLIC || owner[w] == party)
      target.Lambda[w] = (unsigned char)(lambda[w] & 1);
    if (owner[w] != PUBLIC) owner_wires[owner[w]].push_back(w);
  }
  broadcast_input_masks_(target, owner_wires);
  // A bound wire's labels went to P1 at prepare.
  if (unbound_wires.size() == (size_t)n) exchange_input_labels_(target, n);
  else if (!unbound_wires.empty()) exchange_input_labels_(target, unbound_wires);
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

template <int nP, class Cfg>
void AGMPCProtocol<nP, Cfg>::exchange_input_labels_(SecureWires<nP> &sw,
                                                    const std::vector<int> &wires) {
  const int m = (int)wires.size();
  if (m == 0) return;
  if (party != 1) {
    BlockVec tmp(m);
    for (int j = 0; j < m; ++j) {
      const int i = wires[(size_t)j];
      tmp[j] = sw.Lambda[(size_t)i] ? (sw.label0[(size_t)i] ^ Delta) : sw.label0[(size_t)i];
    }
    io->send_data(1, tmp.data(), m * sizeof(block));
    io->flush(1);
  } else {
    std::vector<future<void>> res;
    for (int p2 = 2; p2 <= nP; ++p2) {
      const int party2 = p2;
      res.push_back(pool->enqueue([this, &sw, &wires, m, party2]() {
        BlockVec tmp(m);
        io->recv_data(party2, tmp.data(), m * sizeof(block));
        for (int j = 0; j < m; ++j) sw.eval_label[party2][(size_t)wires[(size_t)j]] = tmp[j];
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
      if constexpr (kTestHooks) {
        // TEST-ONLY (hook flip_delivered_lambda): garbler 2 gets its first Lambda
        // flipped, with the honest hash. Garbler 2's check must fail.
        if (hooks().flip_delivered_lambda && i == 2) lam[0] ^= 1;
      }
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

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_GARBLE_INPUT_AUTH_H__
