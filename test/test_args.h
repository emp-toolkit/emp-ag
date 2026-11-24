#ifndef EMP_AG_TEST_TEST_ARGS_H__
#define EMP_AG_TEST_TEST_ARGS_H__
//
// A test's variant, given as arguments after its party id: `name` or `name=value`, as
// add_np_variant's ARGS writes them (runN forwards them to every party). A test lists the
// names it takes, and any other argument aborts, so a misspelt variant cannot silently run
// as the default one.
//
#include "emp-tool/runtime/core/error.h"
#include <initializer_list>
#include <string>
#include <vector>

class TestArgs {
 public:
  TestArgs(int argc, char **argv, std::initializer_list<const char *> known) {
    for (int i = 1; i < argc; ++i) {
      const std::string a = argv[i];
      if (!a.empty() && a.find_first_not_of("0123456789") == std::string::npos) continue;  // party id
      const std::string name = a.substr(0, a.find('='));
      bool ok = false;
      for (const char *k : known) ok = ok || name == k;
      emp::expecting(ok, [&] { return "test: unknown argument " + a; });
      args_.push_back(a);
    }
  }

  bool has(const char *name) const { return find_(name) != nullptr; }

  // The value of name=value, or def when the argument is absent.
  long long num(const char *name, long long def) const {
    const std::string *a = find_(name);
    if (a == nullptr) return def;
    const size_t eq = a->find('=');
    emp::expecting(eq != std::string::npos && eq + 1 < a->size() &&
                       a->find_first_not_of("-0123456789", eq + 1) == std::string::npos,
                   [&] { return "test: " + *a + " needs a numeric value"; });
    return std::stoll(a->substr(eq + 1));
  }

 private:
  const std::string *find_(const char *name) const {
    for (const std::string &a : args_)
      if (a.substr(0, a.find('=')) == name) return &a;
    return nullptr;
  }
  std::vector<std::string> args_;
};

#endif  // EMP_AG_TEST_TEST_ARGS_H__
