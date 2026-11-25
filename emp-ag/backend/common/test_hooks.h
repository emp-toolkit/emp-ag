#ifndef EMP_AG_BACKEND_COMMON_TEST_HOOKS_H__
#define EMP_AG_BACKEND_COMMON_TEST_HOOKS_H__
//
// Fault-injection hooks for emp-ag's own tests. Each hook makes one party deviate from
// the protocol at one point, so that a test can check the deviation is caught.
//
// A build compiles the hooks in only with -DEMP_AG_TEST_HOOKS, which emp-ag's test
// directory sets and nothing else does. Everywhere else kTestHooks is false and every
// hook site is `if constexpr (kTestHooks)` (or #ifdef EMP_AG_TEST_HOOKS around a
// declaration), so none of them generates code.
//
// In a hooks build, a process runs with the hooks named in the environment variable
// EMP_AG_TEST_HOOKS, read once: a comma-separated list of hook names, and flip_party=<p>
// for the party some row hooks make cheat (default: the last). An unknown name aborts.
//
// A hooks build also moves emp-ag's declarations into an inline namespace (the
// EMP_AG_*NAMESPACE_BEGIN macros below), so that code built with hooks and code built
// without them never share a definition: mixing the two in one program cannot silently
// pick one build's body for the other.
//
#include "emp-tool/runtime/core/error.h"
#include <cstdlib>
#include <string>

#ifdef EMP_AG_TEST_HOOKS
#define EMP_AG_NAMESPACE_BEGIN namespace emp::ag { inline namespace test_hooks {
#define EMP_AG_NAMESPACE_END } }
#define EMP_AG_PUBLIC_NAMESPACE_BEGIN namespace emp { inline namespace ag_test_hooks {
#define EMP_AG_PUBLIC_NAMESPACE_END } }
#else
#define EMP_AG_NAMESPACE_BEGIN namespace emp::ag {
#define EMP_AG_NAMESPACE_END }
#define EMP_AG_PUBLIC_NAMESPACE_BEGIN namespace emp {
#define EMP_AG_PUBLIC_NAMESPACE_END }
#endif

// The hooks that are on or off. Each is described where it acts.
#define EMP_AG_TEST_HOOK_FLAGS(X)                                                      \
  X(adapt_check1) X(cnc_flip_all_zr) X(cnc_flip_open) X(cnc_flip_product)              \
  X(cnc_flip_receiver) X(cnc_flip_residual) X(cnc_flip_zr) X(cnc_king_split)           \
  X(cnc_split_zr) X(corrupt_adopted_share) X(flip_agg) X(flip_agg_mid) X(flip_b)       \
  X(flip_bucket_seed) X(flip_bw) X(flip_d) X(flip_delivered_lambda) X(flip_direct)     \
  X(flip_g) X(flip_input_lambda) X(flip_laand) X(flip_laand_high) X(flip_lambda)       \
  X(flip_output_share) X(flip_p1_row) X(flip_tag) X(flip_xy) X(skip_cgamma_check)      \
  X(split_choice) X(split_delta) X(split_first_draw) X(tamper_prefix) X(two_world)

EMP_AG_NAMESPACE_BEGIN

#ifdef EMP_AG_TEST_HOOKS
inline constexpr bool kTestHooks = true;
#else
inline constexpr bool kTestHooks = false;
#endif

struct TestHooks {
#define EMP_AG_TEST_HOOK_FIELD_(name) bool name = false;
  EMP_AG_TEST_HOOK_FLAGS(EMP_AG_TEST_HOOK_FIELD_)
#undef EMP_AG_TEST_HOOK_FIELD_
  int flip_party = 0;   // the garbler the row hooks make cheat; 0 means the last party
};

// A comma-separated hook list, as EMP_AG_TEST_HOOKS holds it.
inline TestHooks parse_test_hooks(const char *spec) {
  TestHooks h;
  const std::string s = spec != nullptr ? spec : "";
  size_t i = 0;
  while (i < s.size()) {
    size_t j = s.find(',', i);
    if (j == std::string::npos) j = s.size();
    const std::string item = s.substr(i, j - i);
    i = j + 1;
    if (item.empty()) continue;
    const size_t eq = item.find('=');
    const std::string name = item.substr(0, eq);
    const std::string value = eq == std::string::npos ? "" : item.substr(eq + 1);
    bool known = false;
#define EMP_AG_TEST_HOOK_PARSE_(n)                                                     \
    if (name == #n) {                                                                  \
      expecting(eq == std::string::npos, "EMP_AG_TEST_HOOKS: " #n " takes no value");  \
      h.n = true;                                                                      \
      known = true;                                                                    \
    }
    EMP_AG_TEST_HOOK_FLAGS(EMP_AG_TEST_HOOK_PARSE_)
#undef EMP_AG_TEST_HOOK_PARSE_
    if (name == "flip_party") {
      expecting(!value.empty() && value.find_first_not_of("0123456789") == std::string::npos,
                "EMP_AG_TEST_HOOKS: flip_party takes a party id");
      h.flip_party = std::stoi(value);
      known = true;
    }
    expecting(known, [&] { return "EMP_AG_TEST_HOOKS: unknown hook " + name; });
  }
  return h;
}

// The hooks this process runs with. Only hook sites call it, and in a build without hooks
// they are compiled out.
#ifdef EMP_AG_TEST_HOOKS
inline const TestHooks &hooks() {
  static const TestHooks h = parse_test_hooks(std::getenv("EMP_AG_TEST_HOOKS"));
  return h;
}
#else
inline const TestHooks &hooks() {
  static constexpr TestHooks h{};
  return h;
}
#endif

// The party the row hooks make cheat at nP parties.
inline int test_flip_party(int nP) {
  return hooks().flip_party != 0 ? hooks().flip_party : nP;
}

EMP_AG_NAMESPACE_END
#endif  // EMP_AG_BACKEND_COMMON_TEST_HOOKS_H__
