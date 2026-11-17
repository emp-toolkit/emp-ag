#ifndef AG_TEST_CLEAR_ORACLE_H__
#define AG_TEST_CLEAR_ORACLE_H__

// Cleartext oracle: evaluate a BooleanProgram on emp-tool's plaintext ClearCtx,
// the reference for AG-MPC builtin tests (the SAME program runs both ways).
#include "emp-tool/ir/context/context.h"   // ClearCtx, execute_program
#include <cstdint>
#include <span>
#include <vector>

namespace agmpc_test {
inline std::vector<uint8_t> clear_eval(const emp::circuit::BooleanProgram &p,
                                       const std::vector<uint8_t> &in) {
  emp::ClearCtx cx;
  std::vector<uint8_t> cin(in.size());
  for (size_t i = 0; i < in.size(); ++i) cin[i] = in[i] ? 1 : 0;
  std::vector<uint8_t> cow =
      emp::execute_program(cx, p, std::span<const uint8_t>(cin.data(), cin.size()));
  std::vector<uint8_t> out(cow.size());
  for (size_t i = 0; i < cow.size(); ++i) out[i] = (cow[i] & 1);
  return out;
}
}  // namespace agmpc_test
#endif  // AG_TEST_CLEAR_ORACLE_H__
