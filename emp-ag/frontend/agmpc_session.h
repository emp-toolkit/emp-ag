#ifndef EMP_AG_FRONTEND_AGMPC_SESSION_H__
#define EMP_AG_FRONTEND_AGMPC_SESSION_H__

// AGMPCSession<nP, Cfg> — the public handle for nP-party authenticated garbling,
// including two-party (AGMPCSession<2>). The DIRECT/chunked session flow
// (input / input_batch / reveal / checkpoint / run(circuit) / run_artifact, RAII
// scope-based liveness, the flush machinery) is shared with every chunked session
// in emp-tool's ChunkedSession<Derived> base; this class supplies only the AG-MPC
// protocol binding (the CRTP hooks below) plus run(body), which here replays the
// pure body live over the engine's passes (no materialized program).
//
//   AGMPCSession<nP> sess(party, port, /*ip=*/nullptr, &pool);  // lanes on by default
//   using Ctx = AGMPCSession<nP>::ctx_t; using UInt32 = UInt_T<Ctx,32>;
//   auto a   = sess.input<UInt32>(/*owner party*/1, x);   // eager, authenticated now
//   auto out = sess.reveal(a + b, PUBLIC);                 // std::optional
//
// Liveness is RAII / scope-tracked (ChunkRecorderCtx): reveal keeps every pending
// wire still in C++ scope; checkpoint() prunes to exactly what is in scope. Inputs
// are eager in the ordinary session flow. While a prepare(circuit) handle is
// outstanding, secret sess.input calls stage owner/value descriptors locally for
// run(std::move(prepared), ...); PUBLIC inputs remain eager/local, and any ordinary
// run/reveal/checkpoint first settles staged inputs through normal authentication.

#include "emp-tool/emp-tool.h"
#include "emp-tool/ir/context/context.h"            // RecordCtx
#include "emp-tool/ir/context/compose.h"            // ComposeCtx, ComposePlan
#include "emp-tool/circuits/frontend/circuit_fn.h"  // frontend::compile / is_circuit_v
#include "emp-tool/circuits/frontend/compose.h"     // frontend::compose (record a ComposePlan)
#include "emp-tool/ir/session/chunked_session.h"     // ChunkedSession<Derived> (ctx_t = ChunkRecorderCtx)
#include "emp-ag/backend/garble/protocol.h"             // AGMPCProtocol, SecureWires, AShareBundle
#include "emp-ag/backend/garble/engine.h"                   // emp::ag::AGMPCEngine<nP>
#include "emp-ag/backend/common/netmp.h"                    // NetIOMP / NetIOMPGroup (owned below)
#include "emp-ag/backend/common/runtime.h"                  // ag::lanes_for (production lane count)
#include <memory>                                    // owned NetIOMP / NetIOMPGroup

#include <array>
#include <cstdint>
#include <optional>
#include <tuple>
#include <type_traits>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

// Live body replay (sole consumer: the AGMPCSession::run(body) overload below). Re-execute a
// pure circuit body LIVE over one protocol pass with no materialized IR: build typed args over
// `pass` from input wire ids [0,total), invoke the body (both the [](a,b){...} and
// [](auto& ctx, a, b){...} forms), and pack the output wire ids. Protocol-agnostic -- depends
// only on emp-tool's frontend value / circuit_fn layer.
namespace emp::ag {

template <class F, class Pass, class... AS, std::size_t... I>
inline std::vector<uint32_t> body_replay_impl(Pass &pass, F &body,
                                              std::index_sequence<I...>) {
  using W = typename Pass::Wire;   // uint32_t
  const std::array<int, sizeof...(AS)> widths{{(int)value_traits<AS>::width()...}};
  std::array<int, sizeof...(AS)> base{};
  uint32_t total = 0;
  for (std::size_t k = 0; k < sizeof...(AS); ++k) { base[k] = (int)total; total += (uint32_t)widths[k]; }
  std::vector<W> ids((size_t)total);
  for (uint32_t i = 0; i < total; ++i) ids[i] = (W)i;

  using PassTr = frontend::circuit_fn_traits<Pass, F, typename AS::template rebind<Pass>...>;
  (void)sizeof(frontend::circuit_contract<PassTr>);
  if constexpr (PassTr::ok) {
    std::tuple<typename AS::template rebind<Pass>...> targs{
        AS::template rebind<Pass>::from_wires(pass, ids.data() + base[I])...};
    auto ret = [&] {
      if constexpr (PassTr::wants_ctx)
        return std::apply([&](auto &&...a) { return body(pass, std::move(a)...); }, targs);
      else
        return std::apply([&](auto &&...a) { return body(std::move(a)...); }, targs);
    }();
    using Ret = std::decay_t<decltype(ret)>;
    std::array<W, (std::size_t)Ret::width()> ow{};
    ret.pack_wires(ow.data());
    return std::vector<uint32_t>(ow.begin(), ow.end());
  } else {
    return {};
  }
}

template <class... AS, class F, class Pass>
inline std::vector<uint32_t> body_replay(Pass &pass, F &body) {
  return body_replay_impl<F, Pass, AS...>(pass, body, std::index_sequence_for<AS...>{});
}

}  // namespace emp::ag

namespace emp {
// Backend protocol/engine/share types live in emp::ag; the public session is
// emp::AGMPCSession<nP>. Pull the backend names it references into scope here.
using emp::ag::AShareBundle;
using emp::ag::SecureWires;
using emp::ag::AGMPCProtocol;

// Cfg (backend/garble/garble_config.h) fixes the garbling options; every party must use the same.
template <int nP, class Cfg = emp::ag::GarbleConfig<>>
class AGMPCSession : public ChunkedSession<AGMPCSession<nP, Cfg>> {
  friend class ChunkedSession<AGMPCSession<nP, Cfg>>;
  using Base = ChunkedSession<AGMPCSession<nP, Cfg>>;

public:
  using ctx_t = typename Base::ctx_t;
  // AGMPCEngine accounts every executed program after DCE, so the shared
  // ChunkedSession base must not rescan its gates just to maintain an unused
  // duplicate counter.
  static constexpr bool kCountsAndsInternally = true;

  // The engine (backend/garble/engine.h) drives the AGMPCProtocol<nP> passes; it exposes
  // run_source/run_program/run_composed over SecureWires bundles.
  using Engine = emp::ag::AGMPCEngine<nP, Cfg>;

  // Internal overload-routing tag. Prepared handles must never fall through to
  // the live-body run() template when a caller forgets std::move or supplies a
  // mismatched signature.
  struct PreparedExecutionTag {};

  // A session holds at most one prepared job, of either kind.
  enum class JobKind : uint8_t { None, Prepared, Computation };

  // What every job handle holds: the session's job slot (owner, kind, token)
  // and the offline material. Move-only; a handle destroyed unrun frees the slot.
  class JobSlot_ {
    friend class AGMPCSession<nP, Cfg>;
    using Material = typename Engine::Material;

    AGMPCSession *owner_ = nullptr;
    JobKind kind_ = JobKind::None;
    uint64_t token_ = 0;
    std::unique_ptr<Material> material_;

    JobSlot_(AGMPCSession *owner, JobKind kind, uint64_t token,
             std::unique_ptr<Material> material)
        : owner_(owner), kind_(kind), token_(token), material_(std::move(material)) {}
    void release_() {
      if (owner_ != nullptr) owner_->end_job_(kind_, token_);
      owner_ = nullptr;
      kind_ = JobKind::None;
      token_ = 0;
      material_.reset();
    }

  public:
    JobSlot_(const JobSlot_ &) = delete;
    JobSlot_ &operator=(const JobSlot_ &) = delete;
    JobSlot_(JobSlot_ &&other) noexcept
        : owner_(std::exchange(other.owner_, nullptr)),
          kind_(std::exchange(other.kind_, JobKind::None)),
          token_(std::exchange(other.token_, 0)),
          material_(std::move(other.material_)) {}
    JobSlot_ &operator=(JobSlot_ &&other) noexcept {
      if (this != &other) {
        release_();
        owner_ = std::exchange(other.owner_, nullptr);
        kind_ = std::exchange(other.kind_, JobKind::None);
        token_ = std::exchange(other.token_, 0);
        material_ = std::move(other.material_);
      }
      return *this;
    }
    ~JobSlot_() { release_(); }
  };

  // Same-session, one-use owner for an offline-prepared circuit execution.
  // The type carries the circuit's typed signature, so run(std::move(p), ...)
  // accepts exactly the same argument/return types as run(circuit, ...).
  template <frontend::RecordValue RetV, frontend::RecordValue... ArgVs>
  class PreparedExecution : private PreparedExecutionTag {
    friend class AGMPCSession<nP, Cfg>;
    JobSlot_ slot_;
    explicit PreparedExecution(JobSlot_ slot) : slot_(std::move(slot)) {}

  public:
    PreparedExecution(PreparedExecution &&) noexcept = default;
    PreparedExecution &operator=(PreparedExecution &&) noexcept = default;
  };

  // Circuit mode (emp-tool ComputationSession): a prepared Computation, one use,
  // this session only. Destroying it unrun drops it: its preprocessing is never
  // reused, and the session continues.
  class ComputationJob {
    friend class AGMPCSession<nP, Cfg>;
    JobSlot_ slot_;
    std::shared_ptr<const circuit::ComputationArtifact> artifact_;
    std::vector<unsigned char> mask_;   // per input wire: its mask where opened to this party

    ComputationJob(JobSlot_ slot,
                   std::shared_ptr<const circuit::ComputationArtifact> artifact,
                   std::vector<unsigned char> mask)
        : slot_(std::move(slot)), artifact_(std::move(artifact)), mask_(std::move(mask)) {}

  public:
    ComputationJob(ComputationJob &&) noexcept = default;
    ComputationJob &operator=(ComputationJob &&) noexcept = default;
  };
  using job_t = ComputationJob;

  // The session OWNS its network: it builds `lanes` NetIOMP meshes over one port
  // per party (port+party listen, dial port+peer) and runs COT/aShare generation
  // lane-parallel across them. `ip` is the
  // 1-based peer IP table (nullptr => loopback). `lanes < 0` selects the
  // production ag::lanes_for(nP) (lanes ON by default); `lanes == 1` is the
  // single-mesh path (plain NetIOMP); a
  // larger value pins an explicit count. `ssp` = statistical security parameter
  // in [1,126] (threaded to TriplePool for bucket sizing + the windowed F_eq
  // check). `session_id` domain-separates the session's coins, commitments and
  // derived OT ids. Left empty (the default), the parties agree on a fresh one
  // here with a two-round commit-then-open coin; a given id is used as is, so
  // related sessions need distinct ids. `base_ot_kind` selects the one
  // public-key base OT per unordered party pair (CSW by default), from which the
  // reverse COT direction is derived (with SilentFerret, one per COT stream);
  // every party must select the same kind. `planned_sender_cots` /
  // `planned_receiver_cots` optionally bound each local COT stream when its total
  // demand is known; -1 keeps the ordinary reusable stream. With SoftSpoken, IKNP
  // and Ferret the counts include emp-ag's 128-COT bootstrap prefix, each local
  // sender count must match the peer's receiver count and vice versa (so one
  // identical pair at every party is valid only when sender == receiver), and a
  // SoftSpoken session must be one-lane. With SilentFerret the two counts are
  // equal and count only the COTs drawn: a plan is the batch every stream prepays
  // at setup, and a stream that runs past it prepays another batch of that size.
  // The worker pool is mandatory and needs
  // at least two workers because interactive send/receive progress runs as
  // mutually-dependent tasks. Invalid party/port/security/lane/pool settings
  // are rejected before sockets open. The
  // setup handshake is flushed here; callers do not flush the io themselves;
  // reach the channels for transcript/byte checks via io() / group().
  AGMPCSession(int party, int port, const char* const* ip, ThreadPool* pool,
              int ssp = 40, int lanes = -1,
              std::optional<block> session_id = std::nullopt,
              BaseOtKind base_ot_kind = BaseOtKind::CSW,
              int64_t planned_sender_cots = -1,
              int64_t planned_receiver_cots = -1)
      : L_(checked_owned_lanes_(party, port, pool, ssp, lanes)),
        owned_io_(L_ > 1 ? nullptr
                         : std::make_unique<NetIOMP<nP>>(party, port, ip)),
        owned_grp_(L_ > 1 ? std::make_unique<NetIOMPGroup<nP>>(party, port, L_, ip)
                          : nullptr),
        io_view_(L_ > 1 ? &owned_grp_->mesh(0) : owned_io_.get()),
        group_view_(owned_grp_.get()),
        proto_(io_view_, pool, party, ssp, group_view_, session_id,
               base_ot_kind, planned_sender_cots, planned_receiver_cots),
        engine_{&proto_} {
    io().flush();
  }
  // LOW-LEVEL: adopt a caller-owned NetIOMP (and optional NetIOMPGroup whose
  // mesh(0) == io). The session does NOT own the network and does NOT flush it.
  // Only for infrastructure that must own+inspect the raw io itself — tests that
  // share one io across many sessions or read its digests (golden snapshot,
  // session id, trace digest) and the NetIOMPGroup unit test. Production code
  // uses the owning ctor above.
  AGMPCSession(NetIOMP<nP>* io, ThreadPool* pool, int party, int ssp = 40,
              NetIOMPGroup<nP>* grp = nullptr,
              std::optional<block> session_id = std::nullopt,
              BaseOtKind base_ot_kind = BaseOtKind::CSW,
              int64_t planned_sender_cots = -1,
              int64_t planned_receiver_cots = -1)
      : L_(checked_borrowed_lanes_(io, pool, party, ssp, grp)),
        io_view_(io), group_view_(grp),
        proto_(io_view_, pool, party, ssp, group_view_, session_id,
               base_ot_kind, planned_sender_cots, planned_receiver_cots),
        engine_{&proto_} {}
  AGMPCSession(const AGMPCSession&) = delete;
  AGMPCSession& operator=(const AGMPCSession&) = delete;
  ~AGMPCSession() {
    expecting(job_ != JobKind::Prepared,
              "AGMPCSession: a prepared execution outlived its session");
    expecting(job_ != JobKind::Computation,
              "AGMPCSession: a Computation job outlived its session");
  }

  // The session's mesh-0 NetIOMP (the io for all non-lane traffic) and, when
  // lanes are on, its group. These views work for both owned and adopted IO.
  NetIOMP<nP>& io() { return *io_view_; }
  const NetIOMP<nP>& io() const { return *io_view_; }
  NetIOMPGroup<nP>* group() { return group_view_; }
  const NetIOMPGroup<nP>* group() const { return group_view_; }
  int lanes() const { return L_; }

  int party() const { return proto_.party; }
  // Total ANDs garbled across every flush / run, all strategies (the engine counts
  // run_source too, which the base's gate-counting can't see).
  uint64_t num_and() const { return engine_.total_ands; }
  int process_input_calls() const { return process_input_calls_; }
  AGMPCProtocol<nP, Cfg>& protocol() { return proto_; }

  // Output goes to every party: under Auth::KRRW the symmetric SPDZ c_gamma MACCheck
  // certifies every party; under Auth::WRK P1 checks every gate and each garbler the
  // outputs' Lambda against its labels (backend/garble/garble_config.h). Choose who
  // reconstructs a given value at reveal time via reveal(..., recipient) / PUBLIC.

  using Base::run;

  // Prepare exactly one execution of an immutable typed circuit.  The offline
  // phase is independent of input ownership and clear values; all OT/triple
  // work, garbling, row delivery, and the deferred COT check finish here.
  template <frontend::RecordValue RetV, frontend::RecordValue... ArgVs>
  PreparedExecution<RetV, ArgVs...>
  prepare(const frontend::Circuit<RetV, ArgVs...> &c) {
    expecting(job_ != JobKind::Prepared,
              "AGMPCSession::prepare: another prepared execution is outstanding");
    require_no_computation_job_("AGMPCSession::prepare");
    materialize_deferred_inputs_();
    std::unique_ptr<typename Engine::Material> material =
        engine_.prepare_program(c.program_shared());
    return PreparedExecution<RetV, ArgVs...>(
        begin_job_(JobKind::Prepared, std::move(material)));
  }

  // Bind staged sess.input() values and/or existing authenticated values to the
  // anonymous offline input pads, evaluate the stored rows, and consume the job.
  // Call prepare(), input(), and run() as separate statements: C++ does not
  // sequence evaluation of function arguments.
  template <frontend::RecordValue RetV, frontend::RecordValue... ArgVs>
  typename RetV::template rebind<ctx_t>
  run(PreparedExecution<RetV, ArgVs...> &&prepared,
      const typename ArgVs::template rebind<ctx_t> &...args) {
    using Out = typename RetV::template rebind<ctx_t>;
    require_no_computation_job_("AGMPCSession::run(prepared)");
    expecting(holds_job_(prepared.slot_, JobKind::Prepared),
              "AGMPCSession::run: invalid, foreign, abandoned, or consumed prepared execution");

    std::vector<uint32_t> in_ids;
    (append_prepared_arg_ids_(in_ids, args), ...);
    expecting(in_ids.size() == prepared.slot_.material_->program->num_inputs,
              "AGMPCSession::run: total argument width != prepared circuit input count");

    typename Engine::Binding binding;
    const size_t n = in_ids.size();
    binding.owner.assign(n, 0);
    binding.clear.assign(n, 0);
    binding.source_lambda.assign(n, 0);
    binding.source_bundle.resize(n);
    std::unordered_set<uint32_t> staged_used;
    std::unordered_map<uint32_t, size_t> first_target;
    bool has_staged = false;
    for (size_t w = 0; w < n; ++w) {
      const uint32_t id = in_ids[w];
      auto sit = staged_by_id_.find(id);
      if (sit != staged_by_id_.end()) {
        const StagedLoc loc = sit->second;
        const StagedInput &s = staged_inputs_[loc.record];
        expecting(s.token == prepared.slot_.token_,
                  "AGMPCSession::run: staged input belongs to another prepared execution");
        binding.owner[w] = s.owner;
        binding.clear[w] = s.bits[loc.bit];
        zero_share(binding.source_bundle[w]);
        staged_used.insert(id);
        first_target.try_emplace(id, w);
        has_staged = true;
      } else {
        auto cit = carried_.find(id);
        expecting(cit != carried_.end(),
                  "AGMPCSession::run: prepared argument is stale or unbound");
        binding.source_lambda[w] = cit->second.Lambda;
        binding.source_bundle[w] = cit->second.bundle;
      }
    }
    // Consume before the first online message: transcript advancement makes a
    // failed or aborted prepared run non-retryable.
    std::unique_ptr<typename Engine::Material> material = take_job_(prepared.slot_);
    typename Engine::PreparedRunResult result =
        engine_.run_prepared(*material, binding);

    // A staged input becomes an ordinary reusable authenticated value.  If the
    // same recorder id was supplied more than once, either target is a valid
    // representation; retain the first circuit-input occurrence.
    for (const auto &[id, w] : first_target)
      carry_load_(carried_[id], result.bound_inputs, w);
    retain_unused_staged_(staged_used);
    if (has_staged) ++process_input_calls_;

    std::vector<uint32_t> out_ids =
        this->ctx_.reserve_ids(result.outputs.size());
    materialize_into_(out_ids, result.outputs);
    return Base::template from_ids_<Out>(this->ctx_, out_ids);
  }

  // ---- Circuit mode (emp-tool ComputationSession; the typed surface is
  // emp-tool's cf::computation / cf::prepare / cf::run). ----
  //
  // prepare_computation does every step that needs no input value: all
  // preprocessing and the garbling of the whole program (P1 stores the rows),
  // then one MAC-checked round that opens each Party input's mask to its owner
  // and each Public input's to every party. Its checks all complete before that
  // round. At most one job (of this kind or a prepared execution) is outstanding,
  // and while a job is outstanding every other call of the session that sends
  // anything is fatal.
  job_t prepare_computation(std::shared_ptr<const circuit::ComputationArtifact> art) {
    expecting(art != nullptr, "AGMPCSession::prepare_computation: null computation");
    circuit::validate_computation(*art);
    for (const circuit::InputRole &r : art->io.inputs)
      expecting(r.kind == circuit::InputKind::Public || r.owner <= nP,
                "AGMPCSession::prepare_computation: an input owner is above the party count");
    for (const circuit::OutputRole &r : art->io.outputs)
      expecting(r.kind == circuit::OutputKind::Public || r.recipient <= nP,
                "AGMPCSession::prepare_computation: an output recipient is above the party count");
    expecting(job_ != JobKind::Prepared,
              "AGMPCSession::prepare_computation: a prepared execution is outstanding");
    require_no_computation_job_("AGMPCSession::prepare_computation");

    std::unique_ptr<typename Engine::Material> material =
        engine_.prepare_program(art->program);
    std::vector<int> owner = computation_input_owners_(*art);
    std::vector<unsigned char> mask = engine_.open_input_masks(*material, owner);
    return job_t(begin_job_(JobKind::Computation, std::move(material)), std::move(art),
                 std::move(mask));
  }

  // The online half: this party binds its own Party slots and every Public slot
  // (emp-tool check_bindings), checked before any traffic; the job is consumed
  // before the first message. The owners broadcast their masked inputs (echoed
  // at nP >= 3), the garblers send P1 the input labels, P1 evaluates the stored
  // rows, and each output slot opens to its recipients: under KRRW after the
  // output check, under WRK in the first flight after the inputs, with P1's
  // masked values handed to each garbler recipient after evaluation.
  session::RawResult run_computation(job_t &&job, const session::RawBindings &b) {
    expecting(holds_job_(job.slot_, JobKind::Computation),
              "AGMPCSession::run_computation: invalid, foreign, abandoned, or consumed job");
    const std::shared_ptr<const circuit::ComputationArtifact> art = job.artifact_;
    const circuit::IoSignature &io_sig = art->io;
    const int me = party();
    session::check_bindings(*art, me, b);

    const std::vector<uint32_t> in_off = circuit::input_slot_offsets(io_sig);
    std::vector<int> owner = computation_input_owners_(*art);
    std::vector<unsigned char> lambda(owner.size(), 0);
    for (size_t s = 0; s < io_sig.inputs.size(); ++s) {
      if (!session::binds(io_sig.inputs[s], me)) continue;
      const session::Bits &bits = *b.inputs[s];
      for (uint32_t k = 0; k < io_sig.inputs[s].width; ++k) {
        const size_t w = (size_t)in_off[s] + k;
        lambda[w] = (unsigned char)((job.mask_[w] ^ (bits[k] != 0 ? 1 : 0)) & 1);
      }
    }
    const std::vector<uint32_t> out_off = circuit::output_slot_offsets(io_sig);
    std::vector<std::vector<int>> open_to(nP + 1);
    for (size_t s = 0; s < io_sig.outputs.size(); ++s)
      for (int t = 1; t <= nP; ++t)
        if (session::receives(io_sig.outputs[s], t))
          for (uint32_t k = 0; k < io_sig.outputs[s].width; ++k)
            open_to[(size_t)t].push_back((int)(out_off[s] + k));

    // Consume before the first online message: an aborted run is not retryable.
    std::unique_ptr<typename Engine::Material> material = take_job_(job.slot_);
    job.artifact_.reset();
    job.mask_.clear();
    const std::vector<unsigned char> bits =
        engine_.run_computation(*material, owner, lambda, open_to);

    session::RawResult r;
    r.outputs.resize(io_sig.outputs.size());
    for (size_t s = 0; s < io_sig.outputs.size(); ++s) {
      if (!session::receives(io_sig.outputs[s], me)) continue;
      session::Bits v(io_sig.outputs[s].width);
      for (uint32_t k = 0; k < io_sig.outputs[s].width; ++k) v[k] = bits[out_off[s] + k];
      r.outputs[s] = std::move(v);
    }
    return r;
  }

  // COMPILED replay retains Circuit's immutable shared owner so the engine can
  // cache lowering and the AND count without rescanning gates or trusting a raw
  // address across object lifetimes.
  template <frontend::RecordValue RetV, frontend::RecordValue... ArgVs>
    requires RebindableWireBundle<RetV, ctx_t> &&
             (RebindableWireBundle<ArgVs, ctx_t> && ...)
  wire_bundle_rebind_t<RetV, ctx_t>
  run(const frontend::Circuit<RetV, ArgVs...>& c,
      const wire_bundle_rebind_t<ArgVs, ctx_t>&... args) {
    require_no_computation_job_("AGMPCSession::run(circuit)");
    materialize_deferred_inputs_();
    using Out = wire_bundle_rebind_t<RetV, ctx_t>;
    std::vector<uint32_t> in_ids;
    (this->append_arg_ids_(in_ids, args), ...);
    std::shared_ptr<const circuit::BooleanProgram> prog = c.program_shared();
    expecting((uint32_t)in_ids.size() == prog->num_inputs,
              "AGMPCSession::run: total argument width != circuit input count");
    expecting((uint32_t)Out::width() == prog->outputs.size(),
              "AGMPCSession::run: return width != circuit output count");
    std::vector<uint32_t> out_ids = this->ctx_.reserve_ids(prog->outputs.size());
    materialize_into_(out_ids, engine_.run_program(prog, gather_carried_(in_ids)));
    return Base::template from_ids_<Out>(this->ctx_, out_ids);
  }

  // ---- LIVE BODY replay: re-execute the pure body once per protocol pass over the
  // engine's passes (ag::body_replay), with NO materialized BooleanProgram
  // — the liveness pass derives the slot-reuse layout from two body replays, then the
  // crypto passes re-run the body through the SAME unified run_pass driver that serves
  // program/compose.
  template <class F, class... Args,
            std::enable_if_t<
                !frontend::is_circuit_v<std::decay_t<F>> &&
                    !std::is_base_of_v<PreparedExecutionTag, std::decay_t<F>>,
                int> = 0>
  auto run(F&& body, const Args&... args) {
    using Tr = frontend::circuit_fn_traits<
        RecordCtx, std::decay_t<F>,
        typename std::decay_t<Args>::template rebind<RecordCtx>...>;
    (void)sizeof(frontend::circuit_contract<Tr>);
    if constexpr (Tr::ok) {
      require_no_computation_job_("AGMPCSession::run(body)");
      materialize_deferred_inputs_();
      std::vector<uint32_t> in_ids;
      (this->append_arg_ids_(in_ids, args), ...);
      SecureWires<nP> bundle = gather_carried_(in_ids);
      auto source = [&body](auto& pass) -> std::vector<uint32_t> {
        return ag::body_replay<
            typename std::decay_t<Args>::template rebind<RecordCtx>...>(pass, body);
      };
      SecureWires<nP> out = engine_.run_source(bundle, source);
      using RetV = typename Tr::value_return;
      std::vector<uint32_t> out_ids = this->ctx_.reserve_ids(out.size());
      materialize_into_(out_ids, out);
      return Base::template from_ids_<typename RetV::template rebind<ctx_t>>(this->ctx_, out_ids);
    } else {
      return frontend::invalid_circuit_fn{};
    }
  }

  // ---- COMPOSE: run a body that calls pre-compiled units via run(ctx, unit, args)
  // (run is opaque on the ComposeCtx — see frontend/circuit_fn.h). The body is
  // recorded into a ComposePlan (O(#instances); units NOT inlined), then each
  // instance is replayed on the fly through run_composed (no materialized program) —
  // the win for repeated / composed units. Each unit must be WireReuse::Linear
  // (use compile_linear).
  template <class F, class... Args,
            class Tr = frontend::circuit_fn_traits<
                ComposeCtx, std::decay_t<F>,
                typename std::decay_t<Args>::template rebind<ComposeCtx>...>>
  auto run_compose(F&& body, const Args&... args) {
    (void)sizeof(frontend::circuit_contract<Tr>);
    if constexpr (Tr::ok) {
      require_no_computation_job_("AGMPCSession::run_compose");
      materialize_deferred_inputs_();
      ComposePlan plan = frontend::compose<
          typename std::decay_t<Args>::template rebind<RecordCtx>...>(std::forward<F>(body));
      std::vector<uint32_t> in_ids;
      (this->append_arg_ids_(in_ids, args), ...);
      SecureWires<nP> bundle = gather_carried_(in_ids);
      SecureWires<nP> out = engine_.run_composed(plan, bundle);
      using RetV = typename Tr::value_return;   // over ComposeCtx
      std::vector<uint32_t> out_ids = this->ctx_.reserve_ids(out.size());
      materialize_into_(out_ids, out);
      return Base::template from_ids_<typename RetV::template rebind<ctx_t>>(this->ctx_, out_ids);
    } else {
      return frontend::invalid_circuit_fn{};
    }
  }

  // Sugar over run_compose for the common state->state chain: invoke `unit` `repeats`
  // times, feeding each output to the next. `unit` is a Linear Circuit whose
  // input/output type is V (use compile_linear). No separate code path.
  template <class Unit, class V>
  auto run_tiled(const Unit& unit, int repeats, const V& state) {
    return run_compose([&unit, repeats](auto& ctx, auto s) {
      for (int i = 0; i < repeats; ++i) s = frontend::run(ctx, unit, s);
      return s;
    }, state);
  }

  // Adopt an externally-authenticated value (V::width() aShare bundles) as an input
  // wire, reusing its IT-MAC (the mask λ, Λ=0) instead of a fresh authentication --
  // the generic reactive-input entry (e.g. a value authenticated by another protocol).
  // Every bundle must be authenticated under this session's existing global
  // keys/Delta; this API does not translate material between sessions.
  // If a prepared execution is active, source garbling labels are unnecessary:
  // soldering uses only the authenticated mask. They are generated lazily only
  // if a later ordinary circuit actually consumes this value.
  // See backend/garble/input_auth.h::adopt_authenticated_input.
  template <class V>
  V adopt_authenticated_input(const AShareBundle<nP>* bundles) {
    require_no_computation_job_("AGMPCSession::adopt_authenticated_input");
    std::vector<uint32_t> ids = this->ctx_.reserve_ids(V::width());
    if (job_ != JobKind::Prepared) {
      materialize_into_(
          ids, proto_.adopt_authenticated_input(bundles, (int)V::width()));
    } else {
      for (size_t i = 0; i < ids.size(); ++i) {
        CarriedState &c = carried_[ids[i]];
        c.bundle = bundles[i];
        c.Lambda = 0;
        c.labels_ready = false;
      }
      lazy_label_count_ += ids.size();
    }
    return Base::template from_ids_<V>(this->ctx_, ids);
  }

private:
  static int checked_owned_lanes_(int party, int port, ThreadPool *pool,
                                  int ssp, int lanes) {
    ag::validate_protocol_runtime(pool, party, nP);
    (void)ag::checked_statistical_security(ssp);
    expecting(valid_netmp_base_port<nP>(port),
              "AGMPCSession: base port must keep port+nP in [1, 65535]");
    const int L = lanes < 0 ? ag::lanes_for(nP) : lanes;
    expecting(valid_netmp_mesh_count<nP>(L),
              "AGMPCSession: lanes must be in [1, 65536], or negative for the default");
    return L;
  }

  static int checked_borrowed_lanes_(NetIOMP<nP> *io, ThreadPool *pool,
                                     int party, int ssp,
                                     NetIOMPGroup<nP> *grp) {
    ag::validate_protocol_runtime(pool, party, nP);
    (void)ag::checked_statistical_security(ssp);
    expecting(io != nullptr, "AGMPCSession: adopted NetIOMP must not be null");
    expecting(io->party == party,
              "AGMPCSession: adopted NetIOMP party does not match session party");
    const int L = grp ? grp->size() : 1;
    expecting(valid_netmp_mesh_count<nP>(L),
              "AGMPCSession: adopted group has an invalid mesh count");
    expecting(grp == nullptr || &grp->mesh(0) == io,
              "AGMPCSession: adopted group mesh(0) must equal the adopted NetIOMP");
    return L;
  }

  // Per-party authenticated state. P1 (evaluator) holds eval_label[2..nP];
  // Pi>=2 (garblers) hold label0.
  struct CarriedState {
    AShareBundle<nP> bundle;
    unsigned char Lambda = 0;
    bool labels_ready = true;
    block label0 = zero_block;
    block eval_label[nP + 1] = {};   // P1 fills [2..nP]; zero-init the unused slots
  };

  struct StagedInput {
    int owner = 0;
    uint64_t token = 0;
    std::vector<uint8_t> bits;
    std::vector<uint32_t> ids;
  };
  struct StagedLoc {
    size_t record = 0;
    size_t bit = 0;
  };

  // Network state (init order: L_ -> owned_* -> views -> proto_). Exactly one of
  // owned_io_ (L==1) / owned_grp_ (L>1) is non-null for the owning constructor;
  // the views also cover adopted IO. proto_ always binds io_view_ / group_view_.
  int L_;
  std::unique_ptr<NetIOMP<nP>> owned_io_;
  std::unique_ptr<NetIOMPGroup<nP>> owned_grp_;
  NetIOMP<nP> *io_view_;
  NetIOMPGroup<nP> *group_view_;
  AGMPCProtocol<nP, Cfg> proto_;
  Engine engine_;
  std::unordered_map<uint32_t, CarriedState> carried_;
  std::vector<StagedInput> staged_inputs_;
  std::unordered_map<uint32_t, StagedLoc> staged_by_id_;
  JobKind job_ = JobKind::None;      // the outstanding job's kind, if any
  uint64_t job_token_ = 0;            // and the token that names it
  uint64_t next_job_token_ = 0;
  size_t lazy_label_count_ = 0;
  int process_input_calls_ = 0;

  // ============ CRTP hooks the ChunkedSession base calls (id-based) ============
  void authenticate_into_(int owner, const std::vector<uint8_t>& bits,
                          const std::vector<uint32_t>& ids) {
    require_no_computation_job_("AGMPCSession::input");
    if (job_ == JobKind::Prepared && owner != PUBLIC)
      stage_input_(owner, bits, ids);
    else
      materialize_into_(ids, authenticate_(owner, bits));
  }
  void batch_authenticate_into_(const std::vector<int>& owners,
                                const std::vector<std::vector<uint8_t>>& bits,
                                const std::vector<std::vector<uint32_t>>& ids) {
    require_no_computation_job_("AGMPCSession::input_batch");
    if (job_ != JobKind::Prepared) {
      batch_finish_eager_(owners, bits, ids);
      return;
    }
    for (size_t a = 0; a < owners.size(); ++a) {
      if (owners[a] == PUBLIC)
        materialize_into_(ids[a], authenticate_(PUBLIC, bits[a]));
      else
        stage_input_(owners[a], bits[a], ids[a]);
    }
  }
  void run_program_into_(const circuit::BooleanProgram& prog,
                         const std::vector<uint32_t>& in_ids,
                         const std::vector<uint32_t>& out_ids) {
    require_no_computation_job_("AGMPCSession: a flush");
    materialize_into_(out_ids, engine_.run_program(prog, gather_carried_(in_ids)));
  }
  void validate_recipient_(int recipient) const {
    expecting(recipient == PUBLIC || (recipient >= 1 && recipient <= nP),
              "AGMPCSession::reveal: recipient must be a party id in [1, nP] or PUBLIC");
  }
  std::vector<uint8_t> decode_(const std::vector<uint32_t>& ids, int recipient) {
    require_no_computation_job_("AGMPCSession::reveal");
    validate_recipient_(recipient);   // also checked pre-flush by the base
    std::vector<bool> b = proto_.decode(
        gather_carried_(ids, /*require_labels=*/false), recipient);
    return std::vector<uint8_t>(b.begin(), b.end());
  }
  bool is_materialized_(uint32_t id) const { return carried_.count(id) != 0; }
  template <class Pred>
  void prune_carried_(Pred keep) {
    for (auto it = carried_.begin(); it != carried_.end(); ) {
      if (keep(it->first)) {
        ++it;
        continue;
      }
      if (!it->second.labels_ready) {
        expecting(lazy_label_count_ != 0,
                  "AGMPCSession: lazy-label accounting underflow");
        --lazy_label_count_;
      }
      it = carried_.erase(it);
    }
  }

  // Optional ChunkedSession normal-operation barrier.  A normal run/reveal/
  // checkpoint turns every staged descriptor into the ordinary eager input form;
  // the outstanding prepared job remains valid and may solder those values later.
  void materialize_deferred_inputs_() {
    if (staged_inputs_.empty()) return;
    require_no_computation_job_("AGMPCSession: settling staged inputs");
    std::vector<int> owners;
    std::vector<std::vector<uint8_t>> bits;
    std::vector<std::vector<uint32_t>> ids;
    owners.reserve(staged_inputs_.size());
    bits.reserve(staged_inputs_.size());
    ids.reserve(staged_inputs_.size());
    for (const StagedInput &s : staged_inputs_) {
      owners.push_back(s.owner);
      bits.push_back(s.bits);
      ids.push_back(s.ids);
    }
    batch_finish_eager_(owners, bits, ids);
    staged_inputs_.clear();
    staged_by_id_.clear();
  }

  // ============ protocol-specific bundle / carried helpers ============
  SecureWires<nP> authenticate_(int owner, const std::vector<uint8_t>& bits) {
    std::vector<bool> bb(bits.begin(), bits.end());
    if (owner == PUBLIC) return proto_.public_wires(bb);   // eager, local, no OT
    expecting(owner >= 1 && owner <= nP,
              "AGMPCSession::input: owner must be a party id in [1, nP] or PUBLIC");
    ++process_input_calls_;
    return std::move(proto_.process_inputs(std::vector<int>{owner},
                                           std::vector<std::vector<bool>>{bb})[0]);
  }
  void batch_finish_eager_(const std::vector<int>& owners,
                           const std::vector<std::vector<uint8_t>>& bits,
                           const std::vector<std::vector<uint32_t>>& ids) {
    std::vector<int> sec_owners; std::vector<std::vector<bool>> sec_bits; std::vector<int> sec_add;
    for (size_t a = 0; a < owners.size(); ++a) {
      std::vector<bool> bb(bits[a].begin(), bits[a].end());
      if (owners[a] == PUBLIC) materialize_into_(ids[a], proto_.public_wires(bb));
      else if (owners[a] >= 1 && owners[a] <= nP) {
        sec_owners.push_back(owners[a]); sec_bits.push_back(std::move(bb)); sec_add.push_back((int)a);
      } else expecting(false,
                       "AGMPCSession::input_batch: owner must be a party id in [1, nP] or PUBLIC");
    }
    if (!sec_owners.empty()) {
      std::vector<SecureWires<nP>> subs = proto_.process_inputs(sec_owners, sec_bits);
      ++process_input_calls_;
      for (size_t j = 0; j < sec_add.size(); ++j) materialize_into_(ids[sec_add[j]], subs[j]);
    }
  }

  void stage_input_(int owner, const std::vector<uint8_t> &bits,
                    const std::vector<uint32_t> &ids) {
    expecting(owner >= 1 && owner <= nP,
              "AGMPCSession::input: owner must be a party id in [1, nP] or PUBLIC");
    expecting(bits.size() == ids.size(),
              "AGMPCSession::input: encoded bit/id width mismatch");
    const size_t record = staged_inputs_.size();
    staged_inputs_.push_back(
        StagedInput{owner, job_token_, bits, ids});
    for (size_t bit = 0; bit < ids.size(); ++bit) {
      auto [it, inserted] = staged_by_id_.emplace(
          ids[bit], StagedLoc{record, bit});
      (void)it;
      expecting(inserted, "AGMPCSession::input: duplicate staged recorder id");
    }
  }

  void retain_unused_staged_(const std::unordered_set<uint32_t> &used) {
    std::vector<StagedInput> remaining;
    remaining.reserve(staged_inputs_.size());
    for (const StagedInput &s : staged_inputs_) {
      StagedInput rest;
      rest.owner = s.owner;
      rest.token = s.token;
      rest.bits.reserve(s.bits.size());
      rest.ids.reserve(s.ids.size());
      for (size_t bit = 0; bit < s.ids.size(); ++bit) {
        if (used.count(s.ids[bit]) != 0) continue;
        rest.bits.push_back(s.bits[bit]);
        rest.ids.push_back(s.ids[bit]);
      }
      if (!rest.ids.empty()) remaining.push_back(std::move(rest));
    }
    staged_inputs_ = std::move(remaining);
    staged_by_id_.clear();
    for (size_t record = 0; record < staged_inputs_.size(); ++record)
      for (size_t bit = 0; bit < staged_inputs_[record].ids.size(); ++bit)
        staged_by_id_.emplace(staged_inputs_[record].ids[bit],
                              StagedLoc{record, bit});
  }

  template <class A>
  void append_prepared_arg_ids_(std::vector<uint32_t> &dst, const A &a) const {
    static_assert(std::is_same_v<typename A::context_type, ctx_t>,
                  "AGMPCSession::run(prepared): argument must use this session context type");
    std::vector<uint32_t> ids = this->value_ids_(a);
    for (uint32_t id : ids)
      expecting(carried_.count(id) != 0 || staged_by_id_.count(id) != 0,
                "AGMPCSession::run(prepared): argument is stale or unbound");
    dst.insert(dst.end(), ids.begin(), ids.end());
  }

  // The party that supplies each input wire, PUBLIC for a Public slot.
  static std::vector<int> computation_input_owners_(const circuit::ComputationArtifact &art) {
    std::vector<int> owner;
    owner.reserve(art.program->num_inputs);
    for (const circuit::InputRole &r : art.io.inputs)
      owner.insert(owner.end(), r.width,
                   r.kind == circuit::InputKind::Public ? (int)PUBLIC : r.owner);
    return owner;
  }
  // The session's one job slot. begin_job_ fills it, take_job_ consumes a job
  // before its first online message (an aborted run is not retryable), and
  // end_job_ frees it when a handle is dropped unrun.
  JobSlot_ begin_job_(JobKind kind, std::unique_ptr<typename Engine::Material> material) {
    job_ = kind;
    job_token_ = ++next_job_token_;
    return JobSlot_(this, kind, job_token_, std::move(material));
  }
  bool holds_job_(const JobSlot_ &slot, JobKind kind) const {
    return slot.owner_ == this && slot.kind_ == kind && slot.material_ != nullptr &&
           job_ == kind && slot.token_ == job_token_;
  }
  std::unique_ptr<typename Engine::Material> take_job_(JobSlot_ &slot) {
    std::unique_ptr<typename Engine::Material> material = std::move(slot.material_);
    slot.owner_ = nullptr;
    slot.kind_ = JobKind::None;
    slot.token_ = 0;
    job_ = JobKind::None;
    job_token_ = 0;
    return material;
  }
  // A dropped prepared execution leaves its staged descriptors usable: the next
  // ordinary boundary authenticates them through materialize_deferred_inputs_,
  // and new inputs are eager again.
  void end_job_(JobKind kind, uint64_t token) {
    if (job_ != kind || token != job_token_) return;
    job_ = JobKind::None;
    job_token_ = 0;
  }
  // While a Computation job is outstanding, nothing else of this session sends:
  // the job's openings and checks then stand alone, and no value crosses between
  // a Computation and the direct-mode paths. Recording gates sends nothing and
  // stays allowed.
  void require_no_computation_job_(const char *what) const {
    expecting(job_ != JobKind::Computation,
              [&] { return std::string(what) + ": a Computation job is outstanding"; });
  }
  void carry_load_(CarriedState& c, const SecureWires<nP>& s, size_t i) const {
    const int party = proto_.party;
    c.Lambda = s.Lambda[i]; c.bundle = s.wire_bundle[i];
    c.labels_ready = true;
    if (party != 1) c.label0 = s.label0[i];
    else for (int j = 2; j <= nP; ++j) c.eval_label[j] = s.eval_label[j][i];
  }
  void carry_store_(const CarriedState& c, SecureWires<nP>& s, size_t i) const {
    const int party = proto_.party;
    s.Lambda[i] = c.Lambda; s.wire_bundle[i] = c.bundle;
    if (party != 1) s.label0[i] = c.label0;
    else for (int j = 2; j <= nP; ++j) s.eval_label[j][i] = c.eval_label[j];
  }
  void materialize_into_(const std::vector<uint32_t>& ids, const SecureWires<nP>& bundle) {
    expecting(bundle.size() == ids.size(), "AGMPCSession: materialize width mismatch");
    for (size_t i = 0; i < ids.size(); ++i) carry_load_(carried_[ids[i]], bundle, i);
  }
  void materialize_lazy_labels_(const std::vector<uint32_t> &ids) {
    std::vector<uint32_t> pending_ids;
    std::vector<AShareBundle<nP>> bundles;
    std::unordered_set<uint32_t> seen;
    pending_ids.reserve(ids.size());
    bundles.reserve(ids.size());
    for (uint32_t id : ids) {
      if (!seen.insert(id).second) continue;
      auto it = carried_.find(id);
      expecting(it != carried_.end(),
                "AGMPCSession: wire has no carried state");
      if (it->second.labels_ready) continue;
      expecting(it->second.Lambda == 0,
                "AGMPCSession: lazy adopted input must retain Lambda=0");
      pending_ids.push_back(id);
      bundles.push_back(it->second.bundle);
    }
    if (pending_ids.empty()) return;
    SecureWires<nP> labeled = proto_.adopt_authenticated_input(
        bundles.data(), (int)bundles.size());
    expecting(lazy_label_count_ >= pending_ids.size(),
              "AGMPCSession: lazy-label accounting underflow");
    lazy_label_count_ -= pending_ids.size();
    for (size_t i = 0; i < pending_ids.size(); ++i)
      carry_load_(carried_[pending_ids[i]], labeled, i);
  }

  SecureWires<nP> gather_carried_(const std::vector<uint32_t>& ids,
                                  bool require_labels = true) {
    if (require_labels && lazy_label_count_ != 0)
      materialize_lazy_labels_(ids);
    SecureWires<nP> s;
    const int party = proto_.party;
    s.Lambda.resize(ids.size()); s.wire_bundle.resize(ids.size());
    if (party != 1) s.label0.resize(ids.size());
    else for (int j = 2; j <= nP; ++j) s.eval_label[j].resize(ids.size());
    for (size_t i = 0; i < ids.size(); ++i) {
      auto it = carried_.find(ids[i]);
      expecting(it != carried_.end(),
                "AGMPCSession: wire has no carried state (stale, or unflushed pending wire)");
      carry_store_(it->second, s, i);
    }
    return s;
  }
};

// Contract check on a representative party count (the API is uniform in nP).
static_assert(Session<AGMPCSession<3>>);
static_assert(DirectSession<AGMPCSession<3>>);
static_assert(SessionIO<AGMPCSession<3>, UInt_T<AGMPCSession<3>::ctx_t, 32>>);
static_assert(CheckpointingSession<AGMPCSession<3>>);
static_assert(ComputationSession<AGMPCSession<3>>);

}  // namespace emp
#endif  // EMP_AG_FRONTEND_AGMPC_SESSION_H__
