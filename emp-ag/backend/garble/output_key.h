#ifndef EMP_AG_BACKEND_GARBLE_OUTPUT_KEY_H__
#define EMP_AG_BACKEND_GARBLE_OUTPUT_KEY_H__
//
// Keys from output labels (AGMPCSession::expert_output_key, and run_computation with keys).
// Garbler j holds both of its labels on an output wire, L_0 and L_0 ^ Delta_j; P1 ends the
// run holding the one for the wire's masked value. A key is a hash of one such label under
// the caller's domain, the session id, the output position and j, so that a garbler's key
// for a value equals P1's key from that garbler exactly when the output takes that value,
// and keys of different sessions, positions, garblers or domains are unrelated. Neither
// side ever needs the other's Delta.
//
#include "emp-tool/runtime/core/block.h"
#include "emp-tool/runtime/crypto/ro.h"
#include <cstdint>
#include <string_view>
#include "emp-ag/backend/common/test_hooks.h"

EMP_AG_NAMESPACE_BEGIN

inline block output_label_key(const block &session_id, std::string_view domain, uint64_t pos,
                              uint64_t garbler, const block &label) {
  return RO("emp-ag:output-label-key", session_id)
      .absorb(domain)
      .absorb(pos)
      .absorb(garbler)
      .absorb(label)
      .squeeze_block();
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_GARBLE_OUTPUT_KEY_H__
