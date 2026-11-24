#ifndef EMP_AG_BACKEND_TRIPLE_SHARE_EVAL_H__
#define EMP_AG_BACKEND_TRIPLE_SHARE_EVAL_H__
//
// Boolean circuits evaluated on aShares (authenticated GMW). Every wire is an aShare under
// the session's global keys: XOR, NOT and constants are local, and each layer of AND gates
// is one Beaver multiplication (triple/beaver.h) against random triples from a bank
// (TripleBank, triple/and_prep.h). A layer's x and y go to every peer in one flight with
// the pairwise check's tag riding it (ashare/open_check.h), and the check settles before
// the layer's products are formed, so a layer costs one flight. AND gates are scheduled by
// their AND depth.
//
// The opened x and y are padded by the triples' a and b and reveal nothing. A value
// derived from the evaluation leaves only through an opening of its own, which flushes the
// COT check and settles the aShare consistency check first (AGMPCProtocol::share_open).
//
#include "emp-ag/backend/ashare/open_check.h"   // PairwiseOpenCheck
#include "emp-ag/backend/ashare/share.h"
#include "emp-ag/backend/ashare/source.h"       // AShareSource
#include "emp-ag/backend/common/lane_mesh.h"
#include "emp-ag/backend/common/runtime.h"      // parallel_for
#include "emp-ag/backend/triple/and_prep.h"     // TripleBank, AndInputs
#include "emp-ag/backend/triple/beaver.h"
#include "emp-ag/backend/triple/triple_row.h"
#include "emp-tool/ir/program.h"
#include "emp-tool/ir/validate.h"
#include <algorithm>
#include <cstdint>
#include <vector>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

template <int nP, class OpenCheck = PairwiseOpenCheck<nP>>
class ShareEval {
  static_assert(OpenCheck::kPerPeerOperands && OpenCheck::kTagRidesBits,
                "share evaluation: a layer in one flight needs a check whose tags ride the bits");

public:
  // The triples come from `bank`, which the caller keeps alive; `abit` is the session's
  // share pool, whose pending consistency view each layer settles. tag_bytes is the width
  // of the tag per directed pair per layer (PairwiseOpenCheck). All parties construct it
  // with the same parameters and make the same calls.
  ShareEval(NetIOMP<nP> *io, NetIOMPGroup<nP> *grp, ThreadPool *pool, int party, block Delta,
            block session_id, AShareSource<nP> &abit, TripleBank<nP> &bank,
            int tag_bytes = (int)sizeof(block))
      : mesh_(io, grp, pool, party), party_(party), Delta_(Delta), abit_(abit), bank_(bank),
        check_(io, pool, party, Delta, session_id, &prg_, grp, "emp-ag:share-eval",
               "share evaluation: MAC tag mismatch", tag_bytes),
        beaver_(mesh_, Delta) {}

  ShareEval(const ShareEval &) = delete;
  ShareEval &operator=(const ShareEval &) = delete;

  // *out[i] = *x[i] AND *y[i] for i < n: one layer.
  void and_layer(int n, const AShareBundle<nP> *const *x, const AShareBundle<nP> *const *y,
                 AShareBundle<nP> *const *out) {
    expecting(n >= 0, "share evaluation: a negative layer width");
    if (n == 0) return;
    const AndInputs<nP> in = beaver_.inputs(n);
    parallel_for(mesh_.pool, n, [&](int lo, int hi) {
      for (int i = lo; i < hi; ++i) {
        in.alpha_bit[i] = (unsigned char)getLSB(x[i]->mac(0));
        in.beta_bit[i] = (unsigned char)getLSB(y[i]->mac(0));
        for (int p = 1; p <= nP; ++p) if (p != party_) {
          const int s = peer_slot(party_, p);
          in.alpha_mac[p][i] = x[i]->mac(s);
          in.alpha_key[p][i] = x[i]->key(s);
          in.beta_mac[p][i] = y[i]->mac(s);
          in.beta_key[p][i] = y[i]->key(s);
        }
      }
    });
    bank_.take(n, mac_, key_);
    const TripleRow<nP> t = strided_row<nP>(mac_, key_, 0, n, party_);
    const auto runs = beaver_.begin(check_, 0, n);
    beaver_.open(check_, runs, t, n);
    beaver_.finish(check_, abit_, runs, t, n, [](const typename OpenCheck::Run &) {}, prod_);
    parallel_for(mesh_.pool, n, [&](int lo, int hi) {
      for (int i = lo; i < hi; ++i) *out[i] = prod_[i];
    });
    ++layers_;
    ands_ += n;
  }

  // Every gate of `prog`, a dense circuit (WireReuse::None), on `in`, one aShare per input
  // wire; the aShares of its outputs, in order.
  AShareBundleVec<nP> evaluate(const circuit::BooleanProgram &prog, const AShareBundleVec<nP> &in) {
    expecting(prog.wire_reuse == circuit::WireReuse::None,
              "share evaluation: the circuit must be dense (WireReuse::None)");
#if !defined(NDEBUG) || defined(EMP_AG_DEBUG_CHECKS)
    circuit::validate_program(prog);
#endif
    expecting(in.size() == (size_t)prog.num_inputs, "share evaluation: one aShare per input wire");
    AShareBundleVec<nP> w(prog.num_wires);
    std::copy(in.begin(), in.end(), w.begin());

    // The AND depth of every wire, and the gates grouped by the depth of their output.
    std::vector<uint32_t> depth(prog.num_wires, 0);
    uint32_t D = 0;
    for (const circuit::Gate &g : prog.gates) {
      uint32_t d = 0;
      if (g.op == circuit::Op::And) d = std::max(depth[g.in0], depth[g.in1]) + 1;
      else if (g.op == circuit::Op::Xor) d = std::max(depth[g.in0], depth[g.in1]);
      else if (g.op == circuit::Op::Not) d = depth[g.in0];
      depth[g.out] = d;
      D = std::max(D, d);
    }
    std::vector<std::vector<uint32_t>> ands(D + 1), linear(D + 1);
    for (uint32_t gi = 0; gi < (uint32_t)prog.gates.size(); ++gi) {
      const circuit::Gate &g = prog.gates[gi];
      (g.op == circuit::Op::And ? ands : linear)[depth[g.out]].push_back(gi);
    }

    // Depth d: its AND layer (inputs of depth below d), then its linear gates in program
    // order (inputs of depth at most d, those of depth d already computed).
    std::vector<const AShareBundle<nP> *> xs, ys;
    std::vector<AShareBundle<nP> *> outs;
    for (uint32_t d = 0; d <= D; ++d) {
      if (!ands[d].empty()) {
        const int n = (int)ands[d].size();
        xs.resize(n);
        ys.resize(n);
        outs.resize(n);
        for (int i = 0; i < n; ++i) {
          const circuit::Gate &g = prog.gates[ands[d][i]];
          xs[i] = &w[g.in0];
          ys[i] = &w[g.in1];
          outs[i] = &w[g.out];
        }
        and_layer(n, xs.data(), ys.data(), outs.data());
      }
      for (uint32_t gi : linear[d]) {
        const circuit::Gate &g = prog.gates[gi];
        switch (g.op) {
          case circuit::Op::Xor: xor_share(w[g.out], w[g.in0], w[g.in1]); break;
          case circuit::Op::Not: w[g.out] = w[g.in0]; add_one_(w[g.out]); break;
          case circuit::Op::Const0: zero_share(w[g.out]); break;
          case circuit::Op::Const1: zero_share(w[g.out]); add_one_(w[g.out]); break;
          case circuit::Op::And: break;
        }
      }
    }
    AShareBundleVec<nP> out(prog.outputs.size());
    for (size_t i = 0; i < prog.outputs.size(); ++i) out[i] = w[prog.outputs[i]];
    return out;
  }

  // AND layers and gates evaluated so far.
  int64_t layers() const { return layers_; }
  int64_t ands() const { return ands_; }

private:
  void add_one_(AShareBundle<nP> &b) const {
    add_public_one<nP>(party_, Delta_,
                       [&](int p) -> block & { return b.mac(peer_slot(party_, p)); },
                       [&](int p) -> block & { return b.key(peer_slot(party_, p)); });
  }

  LaneMesh<nP> mesh_;
  int party_;
  block Delta_;
  AShareSource<nP> &abit_;
  TripleBank<nP> &bank_;
  PRG prg_;
  OpenCheck check_;
  Beaver<nP, OpenCheck> beaver_;
  BlockVec mac_[nP + 1], key_[nP + 1];   // a layer's triples, a | b | c
  AShareBundleVec<nP> prod_;
  int64_t layers_ = 0, ands_ = 0;
};

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_TRIPLE_SHARE_EVAL_H__
