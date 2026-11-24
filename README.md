# emp-ag

![build](https://github.com/emp-toolkit/emp-ag/workflows/build/badge.svg)
[![CodeQL](https://github.com/emp-toolkit/emp-ag/actions/workflows/codeql.yml/badge.svg)](https://github.com/emp-toolkit/emp-ag/actions/workflows/codeql.yml)

<img src="https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/art/logo-full.jpg" width=300px/>

Maliciously-secure **multi-party computation via authenticated garbling** for
**n ≥ 2 parties**, built on [emp-tool](https://github.com/emp-toolkit/emp-tool)
and [emp-ot](https://github.com/emp-toolkit/emp-ot). The entire API is one
session, `AGMPCSession<nP>`: authenticate inputs, build circuits over emp-tool's
typed value layer, reveal results — like emp-sh2pc, but malicious-secure and for
any party count. **Two-party is not a separate protocol — it is
`AGMPCSession<2>`**, the `nP == 2` instantiation of the same code.

> **Heads up — AI-assisted rewrite, not yet audited.** This branch is under
> active refactoring and review; do not deploy it without your own audit.

```cpp
#include <emp-ag/emp-ag.h>
using namespace emp;

constexpr int nP = 3;                            // nP == 2 for two-party
int party = parse_party(argv, nP);               // argv[1]; party in [1, nP]
ThreadPool pool(ag::default_pool_size(nP));
AGMPCSession<nP> sess(party, peer_port(),        // port from $EMP_PORT (default 12345)
                      /*ip table*/ nullptr,      // nullptr = localhost for all parties
                      &pool);                    // party 1 = evaluator, 2..n = garblers

using Ctx    = AGMPCSession<nP>::ctx_t;
using UInt32 = UInt_T<Ctx, 32>;
auto a   = sess.input<UInt32>(/*owner*/ 1, party == 1 ? x : 0);   // each party feeds its own input
auto b   = sess.input<UInt32>(/*owner*/ 2, party == 2 ? y : 0);
uint32_t out = sess.reveal(a + b, /*recipient*/ 1).value();       // std::optional<clear_t>
```

This snippet is a real program — [example/add.cpp](example/add.cpp) — built by
default and smoke-run by ctest, so it cannot drift from the library. Two more
examples sit next to it: [example/aes.cpp](example/aes.cpp) (AES-128 with the
plaintext at party 1 and the key at party 2, checked against the FIPS-197 known
answer) and [example/modes.cpp](example/modes.cpp) (the three circuit-execution
modes — direct, body, compiled — plus `run_compose` chaining).

## Requirements

- CMake ≥ 3.25
- A C++20 compiler (Clang ≥ 14, GCC ≥ 10, AppleClang 14+)
- [emp-tool](https://github.com/emp-toolkit/emp-tool) and
  [emp-ot](https://github.com/emp-toolkit/emp-ot) from their `main` branches:
  emp-ag's `main` follows theirs, and CMake's version check (`1.0`) cannot tell
  their 1.0 alpha releases apart
- OpenSSL ≥ 3.0
- pthreads

emp-ag is **header-only**: the protocol lives entirely in headers
(`emp-ag::emp-ag` is an `INTERFACE` target); the compiled OT / crypto bodies come
from emp-ot and emp-tool.

## Build and install

emp-ag consumes emp-tool and emp-ot through their installed CMake packages. Install
those two first, then build emp-ag the same way:

```bash
# emp-tool
git clone https://github.com/emp-toolkit/emp-tool.git
cmake -S emp-tool -B emp-tool/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-tool/build -j
cmake --install emp-tool/build       # respects CMAKE_INSTALL_PREFIX

# emp-ot
git clone https://github.com/emp-toolkit/emp-ot.git
cmake -S emp-ot -B emp-ot/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-ot/build -j
cmake --install emp-ot/build

# emp-ag
git clone https://github.com/emp-toolkit/emp-ag.git
cmake -S emp-ag -B emp-ag/build -DCMAKE_BUILD_TYPE=Release
cmake --build emp-ag/build -j
cmake --install emp-ag/build
```

If you don't want to install the dependencies, point emp-ag directly at their build
trees:

```bash
cmake -S emp-ag -B emp-ag/build \
    -DCMAKE_BUILD_TYPE=Release \
    -Demp-tool_DIR=/abs/path/to/emp-tool/build \
    -Demp-ot_DIR=/abs/path/to/emp-ot/build
```

### CMake options

| Option | Default | Effect |
|---|---|---|
| `EMP_AG_BUILD_TESTS`    | `ON` when top-level | Build the test suite under `test/` (incl. `test/adversarial/`). |
| `EMP_AG_BUILD_BENCHES`  | `OFF` | Build the benchmarks under `bench/` (opt-in; not run by ctest). |
| `EMP_AG_BUILD_EXAMPLES` | `ON` when top-level | Build the examples under `example/` (smoke-run by ctest). |
| `EMP_AG_OT_BACKEND`     | `SoftSpoken` | The build's default COT streams for aShare generation: `SoftSpoken` or `SilentFerret`; a session can choose either through its `GarbleConfig`'s `Cot`. `SilentFerret` sends every message for a planned number of COTs when the session starts (the session's planned COT counts), after which drawing COTs moves no bytes. All of a session's COT streams share one public LPN matrix, so each party applies it to all of its streams in one pass. |
| `EMP_AG_SOFTSPOKEN_K`   | `8` | With `SoftSpoken`, the field parameter `k`. |
| `EMP_AG_DEBUG`          | `OFF` | Enable internal MAC / correctness checks. |
| `EMP_AG_PROFILE`        | `OFF` | Protocol timing / communication profiling (`[ag]` / `[ag-tp]` phase markers); zero-cost when off. |
| `EMP_AG_INSTALL`        | `ON` when top-level | Generate install / `find_package(emp-ag)` export rules. |

For every selected backend, each unordered party pair runs one public-key base
OT. The reverse COT direction derives its base OTs from a 128-COT prefix of the
canonical direction, consistency-checked before the derivation and hashed under
a tweak per row; this is unconditional for every `nP`.
`AGMPCSession` uses `BaseOtKind::CSW` by default. The argument after
`session_id` can select another base OT (e.g. the post-quantum `BMM`); every
party must select the same base OT.

An application can also supply the COT streams themselves, as the session's last
argument: an `ag::CotExtensionFactory` (`backend/ashare/cot_extension_factory.h`,
which states what the streams must guarantee) builds each pair's primary stream,
with its own base OTs, and its reverse stream, over the base OTs derived from the
primary's checked prefix. Supplied streams need the SoftSpoken mint and run on one
lane; a session binds the factory's id into its session id, so a mismatch fails
setup.

The products of the AND gates' masks behind each chunk come, by default, from
half-gate leaky ANDs bucketed per chunk (`backend/triple/leaky_and_prep.h`).
Passing `ag::cut_and_choose_prep<nP>(batch)` as the session's last constructor
argument, or compiling with `-DEMP_AG_CUT_AND_CHOOSE_BATCH=<batch>`, computes them
instead from a bank of cut-and-choose triples
(`backend/triple/cut_and_choose_triples.h`), generated `batch` at a time and
checked before use. This sends fewer bytes per triple when COTs are cheap
(`Ferret`) and batches are large, at the cost of more computation and of memory
proportional to the batch. Batch `i` of a session is held to `2^-ssp / (i(i+1))`;
`ag::cut_and_choose_prep<nP>(batch, batches)` instead declares the number of
batches up front, holds each to `2^-ssp / batches`, and refuses a batch beyond it. Any other protocol for the AND gates can be passed the
same way (`backend/triple/and_prep.h` states what it must guarantee, and how its
factory lists its draws for a session's COT plan). Every party
must make the same choice; a session binds every protocol but the leaky ANDs into
its session id, so a mismatch fails setup.

The garbling options are compile-time: `AGMPCSession<nP, ag::GarbleConfig<A, D, C, L>>`
(`backend/garble/garble_config.h`). Every party must use the same options; a session binds
any non-default choice into its session id, so a mismatch fails setup.
`-DEMP_AG_GARBLE_AUTH=WRK`, `-DEMP_AG_GARBLE_DELIVERY=DIRECT` and
`-DEMP_AG_OT_BACKEND=SilentFerret` change the default for a whole build.

| Option | Values | Effect |
|---|---|---|
| `A` | `Auth::KRRW` (default) | Party 2 sends one extra bit per AND gate, from which party 1 reads its masked values; a check after evaluation certifies them. |
| | `Auth::WRK` | Every garbler also sends party 1 three rows per AND gate, truncated to `ssp + 2` bits, and party 1 checks each gate while it evaluates. More bytes per gate, and no check after evaluation; the garblers then receive the outputs' masked values from party 1, authenticated by their labels. The check is statistical: a forged row passes with probability `2^-ssp`, and a failed attempt aborts the run. |
| `D` (`nP >= 3`) | `Delivery::RING` (default) | The garblers sum their rows along a chain, so party 1 receives three rows per garbler. |
| | `Delivery::DIRECT` | Each garbler sends its own rows to party 1, which sums them: no chain of hops, but every garbler's rows on party 1's link. |
| `C` | `Cot::SoftSpoken` (default) | Each party runs one SoftSpoken extension per peer and direction: 16 bits per COT at `k = 8`, with each stream's consistency check deferred to before the next reveal. At `nP >= 3` every receiver draws its own choice bits, so each share also takes one correction bit per peer, which gives the party one bit toward all its peers. |
| | `Cot::SilentFerret` | One SilentFerret instance per peer and direction, all of them prepaid at setup and folded together with one public LPN matrix: about 0.4 bits per COT, and drawing moves no bytes. At `nP >= 3` a party's receivers share their choice bits (emp-ot's `Ferret::set_choice_seed`), so a share takes no correction bit. |
| `L` (`Cot::SilentFerret`) | `FerretLpn::B12` (default) | emp-ot's `ferret_b12` LPN parameters. |
| | `FerretLpn::B13` | emp-ot's `ferret_b13`: longer rounds, about 0.2 bits per COT, and LPN tables twice the size. |

## Consuming from another CMake project

```cmake
find_package(emp-ag CONFIG REQUIRED)
target_link_libraries(my-app PRIVATE emp-ag::emp-ag)
```

`emp-ag::emp-ag` pulls in `emp-tool::emp-tool` and `emp-ot::emp-ot` transitively,
so consumers don't need to find them separately.

```cpp
#include <emp-ag/emp-ag.h>
```

## Tests

```bash
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure
```

- **`test/`** — the correctness suite: an `n`-party × `nP == 2` matrix of
  typed-frontend circuits, strategy gates, and session tests, each checked
  against a cleartext oracle. Fault injection lives in `test/adversarial/`:
  each test corrupts one protocol message and asserts every honest party
  aborts.
- **`bench/`** — throughput benchmarks; opt-in (`-DEMP_AG_BUILD_BENCHES=ON`),
  not run by ctest. `bench_100m` is a serial sha256 chain (default 3-party);
  `bench_aes` is a data-parallel AES-128 batch (default 2-party) — the wide
  per-chunk circuit is what the engine parallelizes.
- **`example/`** — the usage examples (`add`, `aes`, `modes`); built by
  default, each smoke-run by ctest.

Multi-party tests launch their parties on localhost via the top-level `run`
(3-party) or `runN <nP>` launcher; party 1 (the evaluator) reports the verdict,
so its exit code is the test's. The network tests need an environment that
permits localhost TCP binds.

## Usage

### The session

`AGMPCSession<nP>` owns the I/O boundary, the crypto protocol, and the
authenticated wire state; `sess.ctx()` is the gate context your values are
built over.

- **`sess.input<T>(owner, x)`** normally authenticates one input immediately
  (`PUBLIC` builds a public constant, no OT); **`sess.input_batch()`** normally
  authenticates many inputs — across all owners — in a single phase. While one
  prepared execution is outstanding, secret inputs are instead staged locally
  until that prepared run (or the next ordinary run/reveal/checkpoint).
- **`sess.reveal(v, recipient)`** returns `std::optional<clear_t>` — the value
  at the recipient (or at everyone for `PUBLIC`), `std::nullopt` at any other
  party.
- Wire liveness is **RAII / scope-tracked** (emp-tool's `ChunkRecorderCtx`
  refcounts wires by C++ object lifetime): a reveal keeps every pending value
  still in scope and drops the rest, so revealing one value never invalidates
  another you still hold. **`sess.checkpoint()`** is the explicit prune barrier
  for bounding memory in long compositions. A wire used after it has left scope
  is a hard error.
- Session construction validates party and port ranges, requires a non-null
  `ThreadPool` with at least two workers, and accepts `ssp` only in `[1,126]`
  (default 40). Explicit lane counts must be in `[1,65536]`; a negative value
  selects the production default. The `session_id` constructor argument
  domain-separates the session's coins, commitments and derived OT ids. Left
  empty (the default), the parties agree on a fresh id during construction with
  a commit-then-open coin, two extra rounds; a given id is used as is, so every
  party must pass the same one and logically distinct sessions need distinct
  ids. A benchmark that leaves out setup costs can pass a fixed id.
  The following `base_ot_kind` argument selects the one public-key base OT per
  unordered party pair (with `SilentFerret`, per COT stream) and defaults to
  `BaseOtKind::CSW`. When a session's total COT demand is known in advance, the
  caller may additionally pass exact local sender and receiver COT counts; the
  default `-1` keeps the reusable unbounded stream. With `SoftSpoken` each count
  includes emp-ag's 128-COT bootstrap prefix, matching peers must agree, and the
  session must be one-lane. With
  `SilentFerret` the two counts are equal, count only the COTs drawn, and set what
  every stream prepays at setup. For a session whose work is one `Computation`
  (below), `AGMPCSession<nP, Cfg>::planned_cots(computation, ssp, and_prep)` gives
  the count, the same for every stream; COTs a caller draws for the job add to the
  streams they come from.
- **`sess.traffic()`** reports every byte the session's network has carried, as
  this party sent and received it, over every lane and including the connection
  handshakes that channel counters miss.

### Offline preparation and online execution

A typed immutable circuit can be garbled before its input owners or values are
known. The scalar API intentionally mirrors ordinary `run`:

```cpp
auto adder = frontend::compile_linear<rec::UInt<32>, rec::UInt<32>>(
    [](auto x, auto y) { return x + y; });

auto prepared = sess.prepare(adder);  // OT/triples, garbling, row delivery, COT check

auto a = sess.input<UInt32>(1, party == 1 ? x : 0);  // staged: no communication here
auto b = sess.input<UInt32>(2, party == 2 ? y : 0);
auto c = sess.run(std::move(prepared), a, b);         // bind, evaluate, output check
```

`prepare(circuit)` is owner- and value-independent. Its move-only handle belongs
to that session, the session must outlive it, and it may be consumed at most
once (or simply dropped). `prepare`, the input calls, and `run` must be separate
sequenced statements as above; do not nest `prepare()` and `input()` in one call
expression because C++ does not specify function-argument evaluation order. The
online `run` performs no base OT, COT extension, triple generation, or garbling;
it opens the anonymous input pads to their eventual owners, broadcasts the
selected masks, ships selected
input labels, evaluates the stored rows at party 1, and runs the symmetric
output check.

Arguments may mix inputs staged after `prepare` with authenticated values that
already existed in the session. Existing values are soldered to fresh prepared
pads by an authenticated public opening of the mask difference. An externally
authenticated value adopted while a handle is active skips its unused source
label exchange; labels are generated lazily if a later ordinary circuit needs
that representation. Adopted bundles must already be authenticated under this
session's global keys/Delta; adoption does not translate material between
sessions. `input_batch()` also stages through the same path. Only
staged wires actually passed to the prepared circuit are bound; an unused value
or unused slice remains available
and is authenticated at the next ordinary boundary. Dropping a prepared handle
also leaves its staged values for ordinary authentication, and a later
`prepare()` settles them before beginning another job. A session prepares
and consumes one circuit execution at a time; there is no batch-of-online-runs
API and no serialized prepared artifact. An ordinary run, reveal, or
checkpoint first settles any staged inputs through the normal batched
authentication path, after which the
prepared handle can still consume them through soldering.

### Declared owners and recipients

A `Computation` (emp-tool, `circuits/frontend/computation_fn.h`) names each
input's owner and each output's recipient up front, so more of the work moves
offline:

```cpp
namespace cf = emp::frontend;
auto comp = cf::computation(adder, cf::to(2), cf::from(1), cf::from(PUBLIC));
auto [sum, x_in, k_in] = comp.handles();
auto job = cf::prepare(sess, comp);                        // offline
auto res = party == 1 ? cf::run(sess, std::move(job), cf::bind(x_in, x), cf::bind(k_in, k))
                      : cf::run(sess, std::move(job), cf::bind(k_in, k));
std::optional<uint64_t> s = res[sum];                      // present at party 2 only
```

`prepare` runs all preprocessing and garbles the whole program (party 1 stores
every row), then, after every check completes, opens each Party input's mask
to its owner and each Public input's to every party. `run` binds this party's
own inputs and every Public input: the owners broadcast their masked inputs
(echoed at nP >= 3), the garblers send the input labels, party 1 evaluates the
stored rows, and each output opens only to its recipients, under `Auth::KRRW`
after the output check and under `Auth::WRK` in the first flight after the
inputs, with party 1 handing each garbler recipient the outputs' masked values.
A program built elsewhere, with any number of slots, runs through
`prepare_computation` / `run_computation` directly. A composed program, a
`ComposePlan` of glue gates and calls of compiled units (emp-tool's
`ComposeCtx` or `frontend::compose`), goes to `prepare_computation(plan, io)`
with its slots: the session lays the plan out once, lowers each distinct unit
once, and replays the layout in every walk, so no walk copies a unit per call.
One job is outstanding at a
time; while it is, every other call of the session that sends anything is
fatal. Values do not cross between this path and the prepared API above.

With two parties, a Party slot can instead take a value the session already
holds authenticated: `run_computation(job, bindings, authenticated)` gives such
a slot aShare bundles under the session's global keys, and every party opens
the value XOR the slot's mask under a MAC check in place of the owner's
broadcast, so the input is exactly the authenticated value. The bundles can
come from another protocol run on the session's own COTs between
`prepare_computation` and `run_computation`: `sess.draw_cots(job, peer,
as_sender, out, n)` draws raw COTs from one stream (SoftSpoken mint), and
`sess.check_cots(job)` runs the session's COT check over them, which must pass
before that protocol releases anything that depends on them; `run_computation`
runs it again before it opens anything. While the job is outstanding these two
are the only way to the streams.

At any party count, a Party slot can take share-mode values (below) at prepare:
`prepare_computation(art, bound)`, or `(plan, io, bound)` for a composed program,
takes one `const SharedWires *` per input slot, null for an ordinary slot. Each
bound wire takes its value as its mask, with masked value 0, so nothing about
the value is opened: no mask opens for the slot, the garblers send party 1 its
labels during `prepare`, and `run_computation` takes no bits for it. The bound
wires draw no masks: `planned_cots(computation, ssp, and_prep, bound)` leaves
them out.

For experts only, under `Auth::WRK`: `expert_open_output_masks(job)` opens a
prepared job's output masks to their recipients before `run_computation`, which
then opens none. emp-ag does not check that this is safe for the circuit. It is
safe only if every output is an AND gate's output that depends on an input bound
at run, such as a Public input. Otherwise a recipient can learn its output before
the run, even from a job that never runs, and an XOR output's mask can give away
input bits. With the masks open, `expert_output_key(job, pos, value, domain)`
gives a garbler a key from its label for output `pos` taking `value`, and
`run_computation(job, bindings, positions, domain, keys)` gives party 1 its keys
from the labels it ends with, one per garbler. Garbler `j`'s key equals party 1's
key from `j` exactly when the output takes that value, so a payload encrypted under
it opens at party 1 only for that output. No `Delta` leaves the session.

### Share mode

A session can also hold Boolean values as aShares under its global keys and
evaluate circuits on them (authenticated GMW). `SharedWires` is a vector of
such values, which only the session builds:

```cpp
auto a = sess.share_input(1, bits);       // party 1's bits; the others pass as many, ignored
auto r = sess.share_random(128);          // random shares
auto y = sess.share_evaluate(prog, AGMPCSession<nP>::SharedWires::concat({&a, &r}));
std::optional<emp::session::Bits> v = sess.share_reveal(y, PUBLIC);   // or to one party
```

XOR, NOT and constants are local (`a ^ b`, `share_public`, `share_xor_public`),
and each layer of AND gates of the dense program `prog` is one Beaver
multiplication in one flight, whose MAC tags are checked before its products
are formed. The triples come from the session's protocol for the AND gates, which
must keep a bank: `ag::cut_and_choose_prep<nP>(batch[, batches])`, whose bank the
garbling's own AND gates draw from too. A session on the leaky ANDs refuses
`share_evaluate`. A reveal flushes the COT check and settles the share
consistency check before it opens anything. `-DEMP_AG_SHARE_TAG_BYTES=<10..16>`
truncates share mode's tags (16 bytes by default; a forged tag passes with
probability `2^-(8 bytes)`), and binds the session id. For a session's COT plan,
`planned_cots_of_draws(draws)` takes the lengths of its pool draws: one per
`share_input` and `share_random`, and the bank's, `and_prep.draws(T, ssp)` for
`T` triples taken in all.

An application that checks an opening itself, say under one digest per pair that
also covers values of its own, calls `share_opening(v)` at every party before it
sends anything about `v`. The call settles the session's checks first, as
`share_reveal` does, and returns this party's share bits and its MACs on them under
each peer's key. On receiving a peer's bits, `absorb_expected_macs(hash, v, peer,
bits)` puts into the application's hash the MACs that peer's shares must carry,
so no `Delta` leaves the session. Both also work between `prepare_computation` and
`run_computation`, while nothing is drawn.

### Values and circuits

Circuit values are emp-tool's context-bound types over the session's gate
context `AGMPCSession<nP>::ctx_t`: `Bit_T<Ctx>`, `UInt_T<Ctx,N>`,
`Int_T<Ctx,N>`, `Float_T<Ctx,W>`, and `BitVec_T<Ctx,N>`, with the usual
operators (`+ - * / %`, comparisons, bit ops, shifts/rotates, slice/concat).
A reusable circuit is written once as a pure body and compiled with the
emp-tool frontend:

```cpp
auto adder = frontend::compile<rec::UInt<32>, rec::UInt<32>>(
    [](auto x, auto y) { return x + y; });   // record once, over RecordCtx
auto c = sess.run(adder, a, b);              // replay on the session
```

The same compiled circuit runs on any session (plaintext, this protocol, ZK, …);
the context is always explicit — there is no global backend. A pure body can
also be replayed live with `sess.run(body, args...)`, and a hand-authored or
loaded `BooleanProgram` (an AES/SHA builtin) runs via
`sess.run_artifact<RetV>(program, args...)`.

### Two-party is `nP == 2`

The same passes run at every party count; the algebra is special-cased only
where it genuinely collapses at two parties: one garbler means no cross-garbler
`S` terms and no aggregation ring (party 1 receives garbler 2's rows directly);
the leaky ANDs need no `F_Zero` and check with the 2-party `F_eq`; and the output
check's zero-test uses the 2-party `F_eq` instead of the multiparty commit-open. There is no separate 2pc backend: two-party callers use
`AGMPCSession<2>`, where party 1 evaluates and party 2 garbles, the same
convention as every larger instance.

## Protocol

Multi-party authenticated garbling in the WRK17b / KRRW18 line, generalized to
`n >= 2` parties. Party 1 is the evaluator; parties 2..n are the garblers. The
per-AND garbling is the half-gate construction of
[ZRE15](https://eprint.iacr.org/2014/756) (Eurocrypt 2015); malicious security
uses the authenticated-garbling framework of **WRK17b** with the
[KRRW18](https://eprint.iacr.org/2018/578) half-gate leaky-AND and batched
`F_eq` consistency check. For every AND, preprocessing generates `B` leaky
triples, combines them by cyclic-shift bucketing, and then uses Beaver
correction to compute the product of the circuit's input masks. The first
triple of each bucket, the one the rotations leave in place, takes the gate's
second input mask as its `b`: the leaky AND leaks only `a`, and bucketing
keeps that `b`, so the bucket's triple is `(a, λ_β, a·λ_β)` and Beaver
opens only `x = λ_α ⊕ a`. The values opened on the way, the bucket
differences and `x`, are checked against their MACs before the product is used:
by default with a pairwise AES tag at `nP = 2` (the batched opening of
[TinyTable](https://eprint.iacr.org/2016/695)) and a symmetric
random-linear-combination check at `nP >= 3`. The circuit output receives a
separate fresh authenticated mask.
This costs `3B` COTs per AND per direction per peer, excluding input masks
and session overhead. The first input's mask never enters a leaky AND:
successful selective-failure guesses concern only the triples' `a`, which
bucketing hides, rather than disclose a real wire mask. At
`nP >= 3` the garbler rows are combined by default through a **garbler-row
aggregation ring** (following the YWZ20 idea), collapsing the O(n²)
cross-garbler `S`-term cube to O(n) per gate at party 1. By default the output
check is a symmetric SPDZ `c_gamma` MACCheck that certifies every party at once.
Under `Auth::WRK`, party 1 instead checks each gate during evaluation against
MACs under its own key that every garbler sends in its rows: the technique of
WRK17 carried on half-gate rows, as
[DILO22](https://eprint.iacr.org/2022/836) does for two parties. Correlated OT uses a long-lived emp-ot
extension whose consistency check runs before every reveal, so it gates output
release.

## Layout

`AGMPCSession<nP>` (with an optional garbling configuration, `AGMPCSession<nP, Cfg>`) is
the only public handle; under it sit the gate recorder,
the engine, and the crypto protocol. Headers live under the `emp-ag/` include
root (`<emp-ag/...>`):

- **`frontend/agmpc_session.h`** — `emp::AGMPCSession<nP>`, the public session
  (the only piece a caller needs), and its live-body replay.
- **`backend/`** — the building blocks, each including only the ones below it:
  - **`common/`** — the party mesh (`netmp.h`, with `lane_mesh.h` for the bulk
    openings' fan-out), the threading plumbing (`runtime.h`), profiling, and the
    generic sub-protocols every layer uses:
    `fs_hash.h`, `protocols.h` (`EchoBC`, `sampleRandom`, `check_MAC`),
    `feq.h` / `fzero.h`, and `laand_window.h` (exact bit windows for packed rows).
  - **`ashare/`** — authenticated shares: the share type (`share.h`, aShares
    `MAC = KEY ⊕ x·Δ`), the share pool over emp-ot COT (`ashare_gen.h`,
    with `buffer_ot.h` for the base OTs), checked openings (`open.h`), and the
    open checks (`open_check.h`: pairwise and symmetric).
  - **`triple/`** — the products of the AND gates' masks, over the share pool:
    the interface (`and_prep.h`), the leaky ANDs (`laand.h`), a row of triples
    (`triple_row.h`), bucketing (`merge.h`, with its bound in `bucketing.h`), Beaver
    (`beaver.h`), and the two protocols, `leaky_and_prep.h` and the
    cut-and-choose bank (`cut_and_choose_triples.h`, `cut_and_choose_bound.h`).
  - **`garble/`** — authenticated garbling: the options (`garble_config.h`),
    `protocol.h` (`AGMPCProtocol<nP>`), `engine.h` (`AGMPCEngine<nP>`, which
    drives the gate passes over a BooleanProgram / ComposePlan / live body — the
    same gate stream through every phase, so the transcript is identical across
    strategies), `input_auth.h` (inputs, outputs and their hand-offs), the wire
    container (`wires.h`), `halfgate.h` (the half-gate row kernels + tweak),
    `spdz.h` (the SPDZ `c_gamma` collapse + RLC helpers), and `passes/`, the
    circuit walks: `draw_beaver.h`, `garble.h`, `garble_transport.h` (how the
    rows reach party 1: direct, or the `nP >= 3` aggregation ring), `evaluate.h`,
    `mask_witness.h` (the SPDZ `c_gamma` MACCheck) and `wire_format.h` (the
    garbler↔evaluator byte contract).

Per-wire state uses a slot-reuse map, so memory is linear in #AND gates + live
width, not #wires. Each header carries a design-rationale comment at the top of
its section; the headers are the authority for the live contract.

## [Acknowledgement, Reference, and Questions](https://github.com/emp-toolkit/emp-readme/blob/master/README.md#citation)

## License

Licensed under the Apache License, Version 2.0 — see [LICENSE](LICENSE).
