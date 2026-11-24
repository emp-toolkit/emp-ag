// Scalar two-phase execution: owner-independent prepare(circuit), ordinary
// sess.input syntax during the online phase, mixed persistent/staged arguments,
// input_batch staging, and a normal checkpoint fallback.
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "test_options.h"
#include <cstdint>
#include <cstdio>
#include <type_traits>
#include <utility>

using namespace emp;
namespace cf = emp::frontend;

#ifndef PREP_NP
#define PREP_NP 2
#endif
constexpr int nP = PREP_NP;

template <class S, class P, class... Args>
concept RunsPreparedLvalue = requires(S &s, P &p, const Args &...args) {
  s.run(p, args...);
};

template <class S, class P, class... Args>
concept RunsPreparedRvalue = requires(S &s, P &p, const Args &...args) {
  s.run(std::move(p), args...);
};

int main(int argc, char **argv) {
  const int party = parse_party(argv, nP);
  if (party > nP) return 0;
  ThreadPool pool(ag::default_pool_size(nP));
  const TestArgs args(argc, argv, {"adopt_above_two", TEST_OPTION_ARGS});
  AGMPCSession<nP> sess(party, peer_port(), nullptr, &pool, test_options(args));
  using U8 = UInt_T<typename AGMPCSession<nP>::ctx_t, 8>;
  using Bit = Bit_T<typename AGMPCSession<nP>::ctx_t>;
  if (args.has("adopt_above_two")) {
    // Above two parties an adopted bundle could differ toward each peer: refused.
    const bool source_clear = party == nP;
    auto source = sess.protocol().process_input(&source_clear, 1, nP);
    (void)sess.adopt_authenticated_input<Bit>(source.wire_bundle.data());
    return 1;
  }
  using Batch = decltype(sess.input_batch());
  using BackendMaterial = typename AGMPCSession<nP>::Engine::Material;
  static_assert(!std::is_copy_constructible_v<Batch> &&
                !std::is_copy_assignable_v<Batch> &&
                std::is_move_constructible_v<Batch>);
  static_assert(!std::is_copy_constructible_v<BackendMaterial> &&
                !std::is_copy_assignable_v<BackendMaterial> &&
                std::is_move_constructible_v<BackendMaterial> &&
                std::is_move_assignable_v<BackendMaterial>);
  bool ok = true;

  // Dense circuit + direct staged inputs. input() itself is communication-free,
  // and the AND count is charged at successful offline garbling, not online use.
  {
    auto circuit = cf::compile<rec::UInt<8>, rec::UInt<8>>(
        [](auto x, auto y) { return (x + y) ^ (x & y); });
    const uint64_t and0 = sess.num_and();
    auto prepared = sess.prepare(circuit);
    using P = decltype(prepared);
    static_assert(!std::is_copy_constructible_v<P> &&
                  std::is_move_constructible_v<P>);
    static_assert(!RunsPreparedLvalue<AGMPCSession<nP>, P, U8, U8>);
    static_assert(RunsPreparedRvalue<AGMPCSession<nP>, P, U8, U8>);
    static_assert(!RunsPreparedRvalue<AGMPCSession<nP>, P, U8>);
    const uint64_t and1 = sess.num_and();
#ifdef AG_PROFILE
    const uint64_t cot_after_prepare = ag::g_ag_cot_bytes;
#endif
    const int64_t before_inputs = sess.io().count();
    auto x = sess.input<U8>(1, party == 1 ? 0x35 : 0);
    auto y = sess.input<U8>(2, party == 2 ? 0x17 : 0);
    const int64_t after_inputs = sess.io().count();
    auto z = sess.run(std::move(prepared), x, y);
#ifdef AG_PROFILE
    ok &= ag::g_ag_cot_bytes == cot_after_prepare;
#endif
    const uint64_t and2 = sess.num_and();
    const uint8_t got = (uint8_t)sess.reveal(z, PUBLIC).value_or(0);
    const uint8_t x_again = (uint8_t)sess.reveal(x, PUBLIC).value_or(0);
    const uint8_t ref = (uint8_t)((0x35 + 0x17) ^ (0x35 & 0x17));
    ok &= got == ref && x_again == 0x35;
    ok &= before_inputs == after_inputs;
    ok &= and1 == and0 + (uint64_t)ag::agmpc_count_ands(circuit.program());
    ok &= and2 == and1;
  }

  // A typed view may bind only part of a staged value. The unused bits remain
  // deferred and become an ordinary authenticated value at the next boundary.
  {
    auto circuit = cf::compile_linear<rec::Bit>([](auto x) { return !x; });
    auto prepared = sess.prepare(circuit);
    auto whole = sess.input<U8>(nP, party == nP ? 0x5a : 0);
    auto out = sess.run(std::move(prepared), whole[0]);
    ok &= sess.reveal(out, PUBLIC).value_or(false) == true;
    ok &= (uint8_t)sess.reveal(whole, PUBLIC).value_or(0) == 0x5a;
  }

  // Move ownership of a handle and destroy the Circuit before online use. The
  // material owns the immutable program, and duplicate staged arguments bind
  // independently while retaining one reusable representation of the source.
  {
    using P = decltype(sess.prepare(
        cf::compile_linear<rec::UInt<8>, rec::UInt<8>>(
            [](auto x, auto y) { return x ^ y; })));
    P prepared = [&]() {
      auto circuit = cf::compile_linear<rec::UInt<8>, rec::UInt<8>>(
          [](auto x, auto y) { return x ^ y; });
      return sess.prepare(circuit);
    }();
    P moved = std::move(prepared);
    prepared = std::move(moved);
    auto x = sess.input<U8>(1, party == 1 ? 0x6d : 0);
    auto out = sess.run(std::move(prepared), x, x);
    ok &= (uint8_t)sess.reveal(out, PUBLIC).value_or(1) == 0;
    ok &= (uint8_t)sess.reveal(x, PUBLIC).value_or(0) == 0x6d;
  }

  // A value authenticated before prepare is soldered to an anonymous pad; the
  // second argument uses the staged clear-input path. The zero-AND circuit also
  // covers the online garbler MASK walk with an empty stored-row artifact.
  {
    auto persistent = sess.input<U8>(1, party == 1 ? 0xa5 : 0);
    auto circuit = cf::compile_linear<rec::UInt<8>, rec::UInt<8>>(
        [](auto x, auto y) { return x ^ y; });
    auto prepared = sess.prepare(circuit);
    auto staged = sess.input<U8>(2, party == 2 ? 0x3c : 0);
    const uint8_t got = (uint8_t)sess.reveal(
        sess.run(std::move(prepared), persistent, staged), PUBLIC).value_or(0);
    ok &= got == (uint8_t)(0xa5 ^ 0x3c);
  }

  // Externally authenticated values adopted under an active prepare do not
  // exchange source labels: soldering needs only Lambda and the IT-MAC bundle.
  // A direct reveal also stays label-free; the first later ordinary circuit
  // activates labels once, in one input-boundary batch. Two parties only, as
  // adopt_authenticated_input is.
  if constexpr (nP == 2) {
    const bool source_clear = party == nP;
    auto source = sess.protocol().process_input(&source_clear, 1, nP);
    const bool adopted_clear = true ^ (source.Lambda[0] != 0);
    auto identity = cf::compile_linear<rec::Bit>([](auto x) { return x; });
    auto prepared = sess.prepare(identity);
    const int64_t before_adopt = sess.io().count();
    auto adopted =
        sess.adopt_authenticated_input<Bit>(source.wire_bundle.data());
    const int64_t after_adopt = sess.io().count();
    ok &= before_adopt == after_adopt;
    ok &= sess.reveal(adopted, PUBLIC).value_or(!adopted_clear) == adopted_clear;

    auto prepared_out = sess.run(std::move(prepared), adopted);
    ok &= sess.reveal(prepared_out, PUBLIC).value_or(!adopted_clear) ==
          adopted_clear;

    const int64_t before_first_ordinary = sess.io().count();
    auto ordinary1 = sess.run(identity, adopted);
    const int64_t after_first_ordinary = sess.io().count();
    auto ordinary2 = sess.run(identity, adopted);
    const int64_t after_second_ordinary = sess.io().count();
    ok &= after_first_ordinary > before_first_ordinary;
    ok &= after_second_ordinary == after_first_ordinary;
    ok &= sess.reveal(ordinary1, PUBLIC).value_or(!adopted_clear) ==
          adopted_clear;
    ok &= sess.reveal(ordinary2, PUBLIC).value_or(!adopted_clear) ==
          adopted_clear;
  }

  // input_batch uses its ordinary syntax and finish contract; finish performs
  // no authentication traffic while a prepared execution is active.
  {
    auto circuit = cf::compile_linear<rec::UInt<8>, rec::UInt<8>>(
        [](auto x, auto y) { return x + y; });
    auto prepared = sess.prepare(circuit);
    const int64_t before = sess.io().count();
    auto batch = sess.input_batch();
    auto x = batch.template add<U8>(1, party == 1 ? 9 : 0);
    auto y = batch.template add<U8>(2, party == 2 ? 14 : 0);
    batch.finish();
    const int64_t after = sess.io().count();
    const uint8_t got = (uint8_t)sess.reveal(
        sess.run(std::move(prepared), x, y), PUBLIC).value_or(0);
    ok &= before == after && got == 23;
  }

  // An ordinary boundary settles staged descriptors through the eager batched
  // input path. The prepared execution remains usable and takes the solder path.
  {
    auto circuit = cf::compile_linear<rec::UInt<8>, rec::UInt<8>>(
        [](auto x, auto y) { return x + y; });
    auto prepared = sess.prepare(circuit);
    auto x = sess.input<U8>(1, party == 1 ? 20 : 0);
    auto y = sess.input<U8>(2, party == 2 ? 22 : 0);
    sess.checkpoint(x, y);
    const uint8_t got = (uint8_t)sess.reveal(
        sess.run(std::move(prepared), x, y), PUBLIC).value_or(0);
    ok &= got == 42;
  }

  // Dropping a handle performs no destructor-time network I/O and does not
  // strand values already returned by input(); the next ordinary boundary
  // authenticates the orphaned staged descriptor.
  {
    auto circuit = cf::compile_linear<rec::UInt<8>>(
        [](auto x) { return x ^ x; });
    auto orphan = [&]() {
      auto prepared = sess.prepare(circuit);
      const int64_t before_input = sess.io().count();
      auto x = sess.input<U8>(1, party == 1 ? 77 : 0);
      const int64_t after_input = sess.io().count();
      ok &= after_input == before_input;
      return x;                         // prepared is abandoned here
    }();
    const uint8_t got = (uint8_t)sess.reveal(orphan, PUBLIC).value_or(0);
    ok &= got == 77;
  }

  if (party == 1)
    std::printf("agmpc_prepared_np%d: %s\n", nP, ok ? "GOOD!" : "BAD!");
  return (party == 1 && !ok) ? 1 : 0;
}
