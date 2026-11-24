#ifndef EMP_AG_BACKEND_GARBLE_MATERIAL_H__
#define EMP_AG_BACKEND_GARBLE_MATERIAL_H__

// Owner-independent material for one prepared circuit execution.
//
// PreparedMaterial is a single-job object: prepare(circuit) creates one, and
// run(std::move(prepared), args...) consumes it. Its variable-sized members are
// contiguous and job-local, so no prepared state lives on AGMPCProtocol.

#include "emp-ag/backend/garble/passes/replay.h"
#include "emp-ag/backend/garble/passes/wire_format.h"
#include "emp-ag/backend/garble/wires.h"
#include "emp-ag/backend/garble/state.h"
#include "emp-tool/ir/program.h"
#include <cstdint>
#include <memory>
#include <vector>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

// One flattened binding entry per circuit input wire.  owner[w] == 0 means that
// wire is soldered from an already-authenticated source; owner[w] in [1,nP]
// means clear[w] is the staged clear bit (real only at its owner, dummy elsewhere).
// The source arrays are still full-width so the binder can stream one contiguous
// target order; staged positions contain canonical zeros and are never consumed.
template <int nP>
struct PreparedInputBinding {
  std::vector<int> owner;
  std::vector<unsigned char> clear;
  std::vector<unsigned char> source_lambda;
  AShareBundleVec<nP> source_bundle;

  size_t size() const { return owner.size(); }
};

// Input wires a Computation binds at prepare to values the session holds as aShares
// under its global keys. Where bound[w] is set, bundle[w] is wire w's value, and it
// becomes the wire's mask with masked value 0: nothing about it is opened, its labels go
// to P1 at prepare, and the run takes no bits for it. Both vectors have one entry per
// circuit input wire.
template <int nP>
struct PreparedBound {
  std::vector<unsigned char> bound;
  AShareBundleVec<nP> bundle;

  size_t size() const { return bound.size(); }
};

template <int nP>
struct PreparedMaterial {
  PreparedMaterial() = default;
  PreparedMaterial(const PreparedMaterial &) = delete;
  PreparedMaterial &operator=(const PreparedMaterial &) = delete;
  PreparedMaterial(PreparedMaterial &&) = default;
  PreparedMaterial &operator=(PreparedMaterial &&) = default;

  // The program prepared: flat (program) or composed (its replay layout).
  std::shared_ptr<const circuit::BooleanProgram> program;
  std::shared_ptr<const ComposedLayout> composed;
  LoweredUnit lowered;                  // populated for a flat WireReuse::Linear program
  ComputeCtx<nP> ctx;
  EvalChunk<nP> rows;                   // populated only at P1
  SecureWires<nP> target_inputs;        // fresh offline masks + garbling labels
  std::vector<unsigned char> bound;     // per input wire, set where bound at prepare (empty: none)
  // Under WRK, output masks opened ahead of the run (AGMPCEngine::open_output_masks_early):
  // this party's, in its recipient order. The run then opens none.
  bool masks_open = false;
  std::vector<unsigned char> early_mask;
  SecureWires<nP> output_static;        // authenticated bundles (+ garbler label0)
  std::vector<uint32_t> output_ids;
  bool linear = false;

  // Prepared and not yet run; a run consumes it.
  bool live() const { return program != nullptr || composed != nullptr; }
  void consume() {
    program.reset();
    composed.reset();
  }
};

EMP_AG_NAMESPACE_END

#endif  // EMP_AG_BACKEND_GARBLE_MATERIAL_H__
