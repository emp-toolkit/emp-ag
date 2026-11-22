#ifndef EMP_AG_BACKEND_TRIPLE_AND_PREP_H__
#define EMP_AG_BACKEND_TRIPLE_AND_PREP_H__
//
// The function-dependent preprocessing of AND gates. For every AND gate (alpha, beta,
// gamma) of a chunk the garbling needs an aShare of lambda_alpha * lambda_beta under the
// session's global keys, from the aShares of the gate's input-wire masks: lambda_alpha of
// its first input and lambda_beta of its second. An AndPrep computes them. Per chunk of n
// AND gates the garbling (garble/passes/draw_beaver.h) calls validate(n) before it draws
// the chunk's output masks, writes each gate's input masks into inputs(n), and calls
// run(n, out).
//
// emp-ag has two: LeakyAndPrep (triple/leaky_and_prep.h: leaky AND triples merged by
// bucketing, then Beaver) and CutAndChoosePrep (triple/cut_and_choose_triples.h:
// cut-and-choose triples, then Beaver). A session can be given another through its
// constructor (AndPrepFactory, below). Whichever it is, the protocol alone is responsible
// for its products: the garbling's checks certify the garbled circuit against them, not
// the products themselves. So a protocol guarantees:
//   1. out[i] is lambda_alpha * lambda_beta of gate i, authenticated under the Deltas.
//   2. lambda_alpha never enters a position whose leakage the protocol does not remove
//      (above all, a leaky AND's hashed operand a), and lambda_beta at most one whose
//      leakage excludes it.
//   3. It uses fresh aShares, each once, and consumes no triple twice.
//   4. Before run() returns, the consistency check (check2) of every share drawn since
//      the last call is folded at a coin drawn after those shares, and every value it
//      opened is checked against its MACs. These shares include the walk's output masks,
//      which are drawn with their check2 deferred. After run() the garbling settles any
//      check2 view still unagreed (AShareSource::settle_check2), and aborts if a draw was
//      never folded.
//      A protocol may instead agree on that view itself, inside an agreement it runs
//      anyway, to save the round: it takes the view (AShareSource::take_pending_check2)
//      and must then put it into an agreement that aborts unless every party holds the
//      same view, before run() returns. Taking the view clears it, so the garbling no
//      longer sees it: a view taken and never agreed on goes unchecked, and nothing
//      aborts.
//   5. The returned coin is held by every party, drawn in this call after everything its
//      checks depend on is fixed, and fresh per call. It may be predictable: a party
//      may know or steer it (the cut-and-choose protocol's is Fiat-Shamir at nP == 2).
//      The session uses it only to key the chunk's half-gate hash, whose keys are public
//      anyway and must only be fresh per chunk.
//   6. It sizes its own buckets or batches, under its own bound. Every coin such a bound
//      rests on (rotations, a cut, a sacrifice's pairing) is commit-then-open, drawn after
//      what it checks is fixed. A hash of the transcript will not do: the last party to
//      speak before it can try its own free choices offline and send the one whose coin
//      it likes.
// Every party runs the same protocol with the same parameters, and calls it at the same
// points with the same n.
//
#include "emp-ag/backend/ashare/ashare_gen.h"   // AShareSource
#include "emp-ag/backend/ashare/share.h"        // AShareBundleVec
#include "emp-ag/backend/common/netmp.h"
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/crypto/ro.h"
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace emp::ag {

// What a protocol gets from its session, once, after setup.
template <int nP>
struct AndPrepContext {
  NetIOMP<nP> *io = nullptr;
  NetIOMPGroup<nP> *grp = nullptr;   // the session's lanes (mesh(0) == io), or null
  ThreadPool *pool = nullptr;
  int party = 0;
  int ssp = 40;
  block session_id = zero_block;
  AShareSource<nP> *abit = nullptr;  // the session's aShares (fresh per draw)
};

// Where the walk writes AND gate i's input masks, alpha (the gate's first input) and beta
// (its second): this party's share bits, and either its MACs and keys per peer (share.h)
// or their SPDZ collapse mu = x * Delta ^ XOR_p (MAC_p ^ KEY_p), as the protocol asks. The
// walk skips a null pointer.
template <int nP>
struct AndInputs {
  unsigned char *alpha_bit = nullptr, *beta_bit = nullptr;
  block *alpha_mac[nP + 1] = {}, *alpha_key[nP + 1] = {};
  block *beta_mac[nP + 1] = {}, *beta_key[nP + 1] = {};
  block *alpha_mu = nullptr, *beta_mu = nullptr;
};

template <int nP>
class AndPrep {
public:
  virtual ~AndPrep() = default;
  // Aborts unless a chunk of n AND gates can be served.
  virtual void validate(int64_t n) = 0;
  // The buffers for n gates' input masks, owned by the protocol and valid until run().
  virtual AndInputs<nP> inputs(int64_t n) = 0;
  // out[i] = lambda_alpha_i * lambda_beta_i for the n gates written into inputs(n).
  // Returns the call's coin; a caller derives from it under a domain of its own.
  virtual block run(int64_t n, AShareBundleVec<nP> &out) = 0;
};

// How a session builds its protocol for the AND gates, after setup. `id` names the
// protocol and its parameters: a session binds a nonempty id into its session id before
// setup (garble/protocol.h), so parties that chose differently fail setup. The leaky ANDs
// (LeakyAndPrep), the default, have the empty id; any other protocol needs its own.
template <int nP>
struct AndPrepFactory {
  std::string id;
  std::function<std::unique_ptr<AndPrep<nP>>(const AndPrepContext<nP> &)> make;
};

// The session id under the protocol `id` names: unchanged for the empty id.
inline block bind_and_prep(block session_id, const std::string &id) {
  if (id.empty()) return session_id;
  return RO("emp-ag:and-prep", session_id).absorb(std::string_view(id)).squeeze_block();
}

}  // namespace emp::ag
#endif  // EMP_AG_BACKEND_TRIPLE_AND_PREP_H__
