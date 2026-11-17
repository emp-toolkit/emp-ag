// Data-parallel AES-128 batch benchmark for AGMPCSession<nP>, GENERIC in the
// number of parties (default 2; $EMP_N picks 2..8). The counterpoint to
// bench_100m: that workload is an inherently SERIAL sha chain (each iteration
// feeds the next), while the AES blocks here are fully independent — the wide
// per-chunk circuit is what the engine's chunk pipeline and thread pool chew
// through in parallel.
//
// Workload: party 2 owns the AES key, party 1 owns every plaintext block
// (example/aes.cpp is the single-block version of this split). The key schedule
// runs ONCE in-circuit and is shared by all blocks. Each chunk authenticates
// its plaintexts in a single input_batch phase, encrypts them, and XOR-folds
// the ciphertexts (free gates) into one 128-bit accumulator, revealed once at
// the end. Party 1 checks the fold against OpenSSL AES over the same blocks.
//
// Environment:
//   EMP_N=<n>            number of parties (default 2; 2..8 supported)
//   EMP_PORT=<p>         base port (peer_port())
//   EMP_IP1..EMP_IPn     1-based peer IP table (unset -> 127.0.0.1 loopback)
//   AES_BLOCKS=<n>       total AES-128 blocks (default 16384)
//   AES_CHUNK_BLOCKS=<n> blocks per protocol chunk (default 1024)
//   BENCH_THREADS=<n>    ThreadPool workers, default ag::default_pool_size(nP)
//   EMP_AG_LANES=<L>     COT lanes (unset -> the production L(nP))

#include "emp-ag/emp-ag.h"
#include "emp-tool/circuits/crypto/aes128.h"

#include <openssl/aes.h>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <sys/resource.h>
#include <vector>

using namespace emp;

namespace {

uint64_t env_u64(const char *name, uint64_t fallback) {
  const char *s = std::getenv(name);
  if (s == nullptr || *s == '\0') return fallback;
  char *end = nullptr;
  uint64_t v = std::strtoull(s, &end, 10);
  if (end == s || *end != '\0') {
    std::fprintf(stderr, "bench_aes: invalid %s=%s\n", name, s);
    std::exit(1);
  }
  return v;
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

// Deterministic plaintext block i, known to every party so party 1's OpenSSL
// reference needs no key/data exchange (the block still enters as a private,
// authenticated input — cost is data-independent).
std::array<uint8_t, 16> pt_block(uint64_t i) {
  std::array<uint8_t, 16> b;
  for (int j = 0; j < 16; ++j) b[j] = (uint8_t)(0xA5u ^ (i * 17 + (uint64_t)j * 31));
  return b;
}

// bytes -> 128 bits, LSB-first within each byte (the BitVec clear layout).
std::array<bool, 128> bits_of(const std::array<uint8_t, 16> &bytes) {
  std::array<bool, 128> a{};
  for (int i = 0; i < 128; ++i) a[i] = ((bytes[i / 8] >> (i % 8)) & 1) != 0;
  return a;
}

template <int nP>
int run_bench(char **argv) {
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

  const uint64_t blocks = env_u64("AES_BLOCKS", 16384);
  const uint64_t chunk_blocks = env_u64("AES_CHUNK_BLOCKS", 1024);
  if (blocks == 0 || chunk_blocks == 0) {
    std::fprintf(stderr, "bench_aes: AES_BLOCKS and AES_CHUNK_BLOCKS must be > 0\n");
    return 1;
  }
  const int threads = (int)env_u64("BENCH_THREADS", (uint64_t)ag::default_pool_size(nP));
  const int lanes = (int)env_u64("EMP_AG_LANES", (uint64_t)ag::lanes_for(nP));

  ThreadPool pool(threads);
  // A fixed session id: the benchmark leaves out the setup coin flip.
  AGMPCSession<nP> sess(party, peer_port(), any_ip ? iptab : nullptr, &pool, 40, lanes,
                        zero_block);
  using Ctx = typename AGMPCSession<nP>::ctx_t;
  using Block = BitVec_T<Ctx, 128>;

  // SP 800-38A AES-128 key, owned by party 2.
  const std::array<uint8_t, 16> key_bytes = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
                                             0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};

  if (party == 1) {
    std::printf("bench_aes parallel AES-128 batch (nP=%d)\n", nP);
    std::printf("  parties         %d\n", nP);
    std::printf("  blocks          %llu\n", (unsigned long long)blocks);
    std::printf("  chunk blocks    %llu\n", (unsigned long long)chunk_blocks);
    std::printf("  threads         %d\n", threads);
    std::printf("  inputs          key owned by party 2; every pt block owned by party 1\n");
  }

  auto t0 = std::chrono::steady_clock::now();
  auto key = sess.template input<Block>(2, party == 2 ? bits_of(key_bytes)
                                                      : std::array<bool, 128>{});
  auto ekey = circuit::crypto::aes128_key_schedule(sess.ctx(), key);  // once, shared
  auto t_input = std::chrono::steady_clock::now();

  // acc starts as block 0's ciphertext; every further ciphertext XORs in (free).
  std::vector<Block> pts;
  Block acc = [&] {
    auto batch = sess.input_batch();
    auto p0 = batch.template add<Block>(1, party == 1 ? bits_of(pt_block(0))
                                                      : std::array<bool, 128>{});
    batch.finish();
    return circuit::crypto::aes128_encrypt_block(sess.ctx(), p0, ekey);
  }();

  uint64_t chunks = 1;
  for (uint64_t done = 1; done < blocks;) {
    const uint64_t n = std::min<uint64_t>(chunk_blocks, blocks - done);
    auto batch = sess.input_batch();
    pts.clear();
    pts.reserve(n);
    for (uint64_t i = 0; i < n; ++i)
      pts.push_back(batch.template add<Block>(1, party == 1 ? bits_of(pt_block(done + i))
                                                            : std::array<bool, 128>{}));
    batch.finish();                                  // one input phase per chunk
    for (auto &pt : pts)
      acc = acc ^ circuit::crypto::aes128_encrypt_block(sess.ctx(), pt, ekey);
    pts.clear();                                     // release before the prune
    sess.checkpoint();                               // keeps acc + ekey (in scope)
    done += n;
    ++chunks;
  }
  auto t_run = std::chrono::steady_clock::now();
  auto opened = sess.reveal(acc, 1);
  auto t_reveal = std::chrono::steady_clock::now();
  const uint64_t ands = sess.num_and();              // exact, post-DCE

  bool ok = true;
  if (party == 1) {
    if (!opened.has_value()) { std::printf("  result          missing reveal at party 1\n"); ok = false; }
    else {
      ::AES_KEY ak;   // OpenSSL's, not emp-tool's AES-NI struct of the same name
      AES_set_encrypt_key(key_bytes.data(), 128, &ak);
      std::array<uint8_t, 16> ref{}, ct{};
      for (uint64_t i = 0; i < blocks; ++i) {
        AES_encrypt(pt_block(i).data(), ct.data(), &ak);
        for (int j = 0; j < 16; ++j) ref[j] ^= ct[j];
      }
      std::array<uint8_t, 16> got{};
      bools_to_bits(got.data(), opened.value().data(), 128);
      ok = std::memcmp(got.data(), ref.data(), got.size()) == 0;
    }
    const double input_s  = std::chrono::duration<double>(t_input - t0).count();
    const double run_s    = std::chrono::duration<double>(t_run - t_input).count();
    const double reveal_s = std::chrono::duration<double>(t_reveal - t_run).count();
    const double total_s  = std::chrono::duration<double>(t_reveal - t0).count();
    std::printf("  protocol chunks %llu\n", (unsigned long long)chunks);
    std::printf("  actual ANDs     %llu  (%.1f per block incl. one key schedule)\n",
                (unsigned long long)ands, (double)ands / (double)blocks);
    std::printf("  wall key        %.3f s\n", input_s);
    std::printf("  wall run        %.3f s\n", run_s);
    std::printf("  wall reveal     %.3f s\n", reveal_s);
    std::printf("  wall total      %.3f s\n", total_s);
    std::printf("  throughput      %.1f blocks/s   %.3f MAND/s\n",
                total_s > 0 ? (double)blocks / total_s : 0.0,
                total_s > 0 ? (double)ands / total_s / 1.0e6 : 0.0);
    std::printf("  comm total      %.3f GiB  (this party, all peers)\n",
                (double)comm_bytes(&sess.io(), sess.group(), lanes) / (1024.0 * 1024.0 * 1024.0));
    std::printf("  peak RSS        %.3f GiB\n",
                (double)peak_rss_kib() / (1024.0 * 1024.0));
    std::printf("bench_aes: %s\n", ok ? "GOOD!" : "BAD!");
  }
  return (party == 1 && !ok) ? 1 : 0;
}

}  // namespace

int main(int argc, char **argv) {
  (void)argc;
  const uint64_t n = env_u64("EMP_N", 2);
  switch (n) {
    case 2: return run_bench<2>(argv);
    case 3: return run_bench<3>(argv);
    case 4: return run_bench<4>(argv);
    case 5: return run_bench<5>(argv);
    case 6: return run_bench<6>(argv);
    case 7: return run_bench<7>(argv);
    case 8: return run_bench<8>(argv);
    default:
      std::fprintf(stderr, "bench_aes: unsupported EMP_N=%llu (2..8)\n",
                   (unsigned long long)n);
      return 1;
  }
}
