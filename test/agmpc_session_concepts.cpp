// Compile-time gate: AGMPCSession<2> models the emp-tool session concepts, its gate
// context is a pure BooleanContext recorder, and run() is well-formed over both a
// compiled Circuit and a live body. No network — the test IS that this translation
// unit compiles; main() only confirms the binary links and runs. It targets the
// 2-party instantiation AGMPCSession<2> (the value/concept layer is shared via the
// ChunkedSession base, so the gates are identical).
#include "emp-tool/emp-tool.h"
#include "emp-ag/emp-ag.h"
#include "emp-tool/ir/session/session_io.h"
#include <cstdio>
#include <optional>
#include <type_traits>
using namespace emp;

using Sess = AGMPCSession<2>;

// The session models the three emp-tool session concepts (also asserted inside the
// header; restated here so this TU is the standalone concept gate).
static_assert(Session<Sess>);
static_assert(DirectSession<Sess>);
static_assert(SessionIO<Sess, UInt_T<Sess::ctx_t, 32>>);
static_assert(SessionIO<Sess, Int_T<Sess::ctx_t, 32>>);
static_assert(SessionIO<Sess, BitVec_T<Sess::ctx_t, 128>>);
static_assert(CheckpointingSession<Sess>);

// Ctx is emp-tool's shared gate recorder (ChunkRecorderCtx); the value layer is built over it.
static_assert(std::is_same_v<Sess::ctx_t, ChunkRecorderCtx>);
static_assert(BooleanContext<Sess::ctx_t>);
static_assert(ag::valid_statistical_security(1));
static_assert(ag::valid_statistical_security(40));
static_assert(ag::valid_statistical_security(126));
static_assert(!ag::valid_statistical_security(0));
static_assert(!ag::valid_statistical_security(127));
static_assert(valid_netmp_party<2>(1));
static_assert(valid_netmp_party<2>(2));
static_assert(!valid_netmp_party<2>(0));
static_assert(!valid_netmp_party<2>(3));
static_assert(valid_netmp_base_port<2>(1));
static_assert(valid_netmp_base_port<2>(65533));
static_assert(!valid_netmp_base_port<2>(0));
static_assert(!valid_netmp_base_port<2>(65534));
static_assert(valid_netmp_mesh_count<2>(1));
static_assert(valid_netmp_mesh_count<2>(1 << 16));
static_assert(!valid_netmp_mesh_count<2>(0));
static_assert(!valid_netmp_mesh_count<2>((1 << 16) + 1));

// AGMPC reveal is recipient-only: reveal_t<V> is std::optional<V::clear_t>.
static_assert(std::is_same_v<
    Sess::reveal_t<UInt_T<Sess::ctx_t, 32>>,
    std::optional<UInt_T<Sess::ctx_t, 32>::clear_t>>);

// run() is well-formed over a compiled Circuit and over a live body, and a
// checkpointed (materialized) value is an acceptable run() argument. These are
// decltype-only probes — nothing is evaluated, so no session/network is built.
using UInt32 = UInt_T<Sess::ctx_t, 32>;
using Adder  = frontend::Circuit<rec::UInt<32>, rec::UInt<32>, rec::UInt<32>>;

template <class S>
using run_compiled_t =
    decltype(std::declval<S&>().run(std::declval<const Adder&>(),
                                    std::declval<const UInt32&>(),
                                    std::declval<const UInt32&>()));
template <class S>
using run_body_t =
    decltype(std::declval<S&>().run([](auto x, auto y) { return x + y; },
                                    std::declval<const UInt32&>(),
                                    std::declval<const UInt32&>()));

static_assert(std::is_same_v<run_compiled_t<Sess>, UInt32>);
static_assert(std::is_same_v<run_body_t<Sess>, UInt32>);

int main() {
  if (ag::default_pool_size(2) < 2) return 1;
  std::printf("agmpc_session_concepts: GOOD!\n");
  return 0;
}
