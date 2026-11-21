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

namespace emp::ag {

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

template <int nP>
struct PreparedMaterial {
  PreparedMaterial() = default;
  PreparedMaterial(const PreparedMaterial &) = delete;
  PreparedMaterial &operator=(const PreparedMaterial &) = delete;
  PreparedMaterial(PreparedMaterial &&) = default;
  PreparedMaterial &operator=(PreparedMaterial &&) = default;

  std::shared_ptr<const circuit::BooleanProgram> program;
  LoweredUnit lowered;                  // populated for WireReuse::Linear
  ComputeCtx<nP> ctx;
  EvalChunk<nP> rows;                   // populated only at P1
  SecureWires<nP> target_inputs;        // fresh offline masks + garbling labels
  SecureWires<nP> output_static;        // authenticated bundles (+ garbler label0)
  std::vector<uint32_t> output_ids;
  bool linear = false;
};

}  // namespace emp::ag

#endif  // EMP_AG_BACKEND_GARBLE_MATERIAL_H__
