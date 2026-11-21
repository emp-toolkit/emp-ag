// 100M-AND benchmark for AGMPCSession<nP>, GENERIC in the number of
// parties. The party count nP is chosen at run time from $EMP_N (2..8) and
// dispatched to a compiled AGMPCSession<nP> instantiation.
//
// Workload: start from a 32-byte all-zero string (256 zero bits owned by party 1),
// then repeatedly apply the stored sha256_256 BooleanProgram, composed on the fly
// (the sha unit is compacted ONCE to WireReuse::Linear and replayed N times per
// chunk via run_compose -> run_composed; no flattened chain is materialized).
// Party 1 checks the final digest against OpenSSL SHA-256 iterated the same count.
//
// Environment:
//   EMP_N=<n>           number of parties (default 3; 2..8 supported)
//   EMP_PORT=<p>        base port (peer_port())
//   EMP_IP1..EMP_IPn    1-based peer IP table (unset -> 127.0.0.1 loopback)
//   SHA_ITERS=<n>       exact SHA-256 iterations (overrides TARGET_ANDS)
//   TARGET_ANDS=<n>     default 100000000; used when SHA_ITERS unset
//   SHA_CHUNK_ITERS=<n> SHA iterations per protocol chunk, default 202
//                       (trades barrier amortization against peak RSS and cache
//                       footprint)
//   BENCH_THREADS=<n>   ThreadPool workers, default ag::default_pool_size(nP)
//   EMP_AG_PLANNED_COTS=<n> COTs planned per COT stream (unset: no plan). A run
//                       prints the count that plans the same run ("cots/stream");
//                       with SilentFerret the plan prepays the whole run at setup.
//
// "wall setup" times the session's construction (connections, base OTs, the COT
// setup); "wall total" starts after it. Start party 1 last so that its setup does
// not include waiting for the other parties to start.

#include "emp-ag/emp-ag.h"
#include "emp-tool/ir/builtins.h"
#include "emp-tool/ir/transform.h"   // make_compact (Linear) for the composed sha unit

#include <openssl/sha.h>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/resource.h>

using namespace emp;

namespace {

uint64_t env_u64(const char *name, uint64_t fallback) {
  const char *s = std::getenv(name);
  if (s == nullptr || *s == '\0') return fallback;
  char *end = nullptr;
  uint64_t v = std::strtoull(s, &end, 10);
  if (end == s || *end != '\0') {
    std::fprintf(stderr, "bench_100m: invalid %s=%s\n", name, s);
    std::exit(1);
  }
  return v;
}

uint64_t count_ands(const circuit::BooleanProgram &p) {
  uint64_t n = 0;
  for (const circuit::Gate &g : p.gates)
    if (g.op == circuit::Op::And) ++n;
  return n;
}

// This party's total bytes across ALL meshes: mesh 0
// carries the parent COT + all non-COT traffic, meshes 1..L-1 the lane COT.
template <int nP>
int64_t comm_bytes(NetIOMP<nP> *io, NetIOMPGroup<nP> *grp, int lanes) {
  int64_t c = io->count();
  for (int m = 1; grp && m < lanes; ++m) c += grp->mesh(m).count();
  return c;
}

long peak_rss_kib() {
  struct rusage ru;
  getrusage(RUSAGE_SELF, &ru);
#if defined(__APPLE__)
  return ru.ru_maxrss / 1024;
#else
  return ru.ru_maxrss;
#endif
}

std::array<uint8_t, 32> openssl_sha_chain(uint64_t iters) {
  std::array<uint8_t, 32> cur{}, next{};
  for (uint64_t i = 0; i < iters; ++i) { SHA256(cur.data(), cur.size(), next.data()); cur = next; }
  return cur;
}

void print_hex(const char *label, const std::array<uint8_t, 32> &d) {
  std::printf("%s", label);
  for (uint8_t b : d) std::printf("%02x", b);
  std::printf("\n");
}

template <int nP>
int run_bench(char **argv) {
  using RB256 = BitVec_T<RecordCtx, 256>;
  int party = parse_party(argv, nP);
  if (party < 1 || party > nP) return 0;

  // 1-based peer IP table from env (EMP_IP1..EMP_IPnP); loopback if none set.
  std::string ipbuf[nP + 1];
  const char *iptab[nP + 1] = {nullptr};
  bool any_ip = false;
  for (int p = 1; p <= nP; ++p) {
    char key[16];
    std::snprintf(key, sizeof(key), "EMP_IP%d", p);
    const char *v = std::getenv(key);
    if (v != nullptr && *v != '\0') { ipbuf[p] = v; any_ip = true; }
    else ipbuf[p] = "127.0.0.1";
    iptab[p] = ipbuf[p].c_str();
  }

  const circuit::BooleanProgram &sha = circuit::builtin_circuit("sha256_256");
  const uint64_t sha_ands = count_ands(sha);
  const uint64_t target_ands = env_u64("TARGET_ANDS", 100000000ULL);
  uint64_t iters = env_u64("SHA_ITERS", 0);
  if (iters == 0) iters = (target_ands + sha_ands - 1) / sha_ands;
  if (iters == 0) { std::fprintf(stderr, "bench_100m: zero iterations\n"); return 1; }
  const uint64_t chunk_iters = env_u64("SHA_CHUNK_ITERS", 202);
  const int threads = (int)env_u64("BENCH_THREADS", (uint64_t)ag::default_pool_size(nP));

  // EMP_AG_LANES=<L>: split COT/aShare generation across L lanes on a
  // NetIOMPGroup (L meshes over ONE listening port per party). Unset => the
  // production L(nP) (ag::lanes_for); 1 => the single-mesh path.
  const int lanes = (int)env_u64("EMP_AG_LANES", (uint64_t)ag::lanes_for(nP));
  ThreadPool pool(threads);
  // The session owns its network: `lanes` meshes over one port per party (the
  // owning ctor builds + flushes them). EMP_AG_LANES overrides the production
  // L(nP). AuthSharePool uses L = grp->size().
  const char *planned_env = std::getenv("EMP_AG_PLANNED_COTS");
  const int64_t planned_cots = (planned_env != nullptr && *planned_env != '\0')
                                   ? (int64_t)std::strtoll(planned_env, nullptr, 10)
                                   : -1;
  // A fixed session id: the benchmark leaves out the setup coin flip. Every
  // stream draws the same count, so one plan serves both directions.
  auto t_setup0 = std::chrono::steady_clock::now();
  AGMPCSession<nP> sess(party, peer_port(), any_ip ? iptab : nullptr, &pool, 40, lanes,
                        zero_block, BaseOtKind::CSW, planned_cots, planned_cots);
  auto t_setup = std::chrono::steady_clock::now();
  using Ctx = typename AGMPCSession<nP>::ctx_t;
  using B256 = BitVec_T<Ctx, 256>;

  const uint64_t planned_ands = sha_ands * iters;
  if (party == 1) {
    std::printf("bench_100m sha256_256 zero-string chain (nP=%d)\n", nP);
    std::printf("  parties         %d\n", nP);
    std::printf("  iterations      %llu\n", (unsigned long long)iters);
    std::printf("  sha ANDs/iter   %llu\n", (unsigned long long)sha_ands);
    std::printf("  planned ANDs    %llu\n", (unsigned long long)planned_ands);
    std::printf("  chunk iters     %llu\n", (unsigned long long)chunk_iters);
    std::printf("  threads         %d\n", threads);
    std::printf("  input           256 zero bits owned by party 1\n");
  }

  // Compact the sha UNIT once (cheap). Each chunk composes it `n` times, chained.
  auto t_compile0 = std::chrono::steady_clock::now();
  circuit::CircuitArtifact art{
      circuit::make_compact(sha, circuit::WireReuse::Linear).prog,
      circuit::CircuitSignature{std::vector<uint32_t>{256u}, 256u}};
  frontend::Circuit<RB256, RB256> sha_unit(std::move(art));
  auto t_compile = std::chrono::steady_clock::now();
  if (party == 1) {
    std::printf("  unit wires      %u (Linear; gates %zu) compacted once\n",
                sha_unit.program().num_wires, sha_unit.program().gates.size());
    std::printf("  wall compile    %.3f s\n",
                std::chrono::duration<double>(t_compile - t_compile0).count());
  }

  auto t0 = std::chrono::steady_clock::now();
  std::array<bool, 256> zero{};
  B256 state = sess.template input<B256>(1, zero);   // party 1 owns the zero state
  auto t_input = std::chrono::steady_clock::now();

  uint64_t chunks = 0;
  for (uint64_t done = 0; done < iters;) {
    const uint64_t n = std::min<uint64_t>(chunk_iters, iters - done);
    state = sess.run_compose([&sha_unit, n](auto &ctx, auto s) {
      for (uint64_t i = 0; i < n; ++i) s = frontend::run(ctx, sha_unit, s);
      return s;
    }, state);
    sess.checkpoint(state);
    done += n;
    ++chunks;
  }
  B256 digest = state;
  auto t_run = std::chrono::steady_clock::now();
  auto opened = sess.reveal(digest, 1);
  auto t_reveal = std::chrono::steady_clock::now();

  bool ok = true;
  if (party == 1) {
    if (!opened.has_value()) { std::printf("  result          missing reveal at party 1\n"); ok = false; }
    else {
      std::array<uint8_t, 32> got{};
      bools_to_bits(got.data(), opened.value().data(), 256);
      std::array<uint8_t, 32> ref = openssl_sha_chain(iters);
      ok = std::memcmp(got.data(), ref.data(), got.size()) == 0;
      print_hex("  got             ", got);
      print_hex("  openssl         ", ref);
    }
    const double input_s  = std::chrono::duration<double>(t_input - t0).count();
    const double run_s    = std::chrono::duration<double>(t_run - t_input).count();
    const double reveal_s = std::chrono::duration<double>(t_reveal - t_run).count();
    const double total_s  = std::chrono::duration<double>(t_reveal - t0).count();
    const double setup_s  = std::chrono::duration<double>(t_setup - t_setup0).count();
    std::printf("  protocol chunks %llu\n", (unsigned long long)chunks);
    std::printf("  actual ANDs     %llu\n", (unsigned long long)planned_ands);
    std::printf("  planned cots    %lld\n", (long long)planned_cots);
    std::printf("  cots/stream     %lld\n", (long long)sess.protocol().abit->cots_per_stream());
    std::printf("  wall setup      %.3f s\n", setup_s);
    std::printf("  wall input      %.3f s\n", input_s);
    std::printf("  wall run        %.3f s\n", run_s);
    std::printf("  wall reveal     %.3f s\n", reveal_s);
    std::printf("  wall total      %.3f s\n", total_s);
    std::printf("  throughput      %.3f MAND/s\n",
                total_s > 0 ? (double)planned_ands / total_s / 1.0e6 : 0.0);
    std::printf("  with setup      %.3f MAND/s\n",
                (total_s + setup_s) > 0
                    ? (double)planned_ands / (total_s + setup_s) / 1.0e6 : 0.0);
    std::printf("  comm total      %.3f GiB  (this party, all peers)\n",
                (double)comm_bytes(&sess.io(), sess.group(), lanes) / (1024.0 * 1024.0 * 1024.0));
    std::printf("  peak RSS        %.3f GiB\n",
                (double)peak_rss_kib() / (1024.0 * 1024.0));
    std::printf("bench_100m: %s\n", ok ? "GOOD!" : "BAD!");
  }
  return (party == 1 && !ok) ? 1 : 0;
}

}  // namespace

int main(int argc, char **argv) {
  (void)argc;
  const uint64_t n = env_u64("EMP_N", 3);
  switch (n) {
    case 2: return run_bench<2>(argv);
    case 3: return run_bench<3>(argv);
    case 4: return run_bench<4>(argv);
    case 5: return run_bench<5>(argv);
    case 6: return run_bench<6>(argv);
    case 7: return run_bench<7>(argv);
    case 8: return run_bench<8>(argv);
    default:
      std::fprintf(stderr, "bench_100m: unsupported EMP_N=%llu (2..8)\n",
                   (unsigned long long)n);
      return 1;
  }
}
