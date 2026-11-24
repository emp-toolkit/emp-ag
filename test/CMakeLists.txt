# Correctness tests. Only added when EMP_AG_BUILD_TESTS is ON (gated at the top level);
# benchmarks live in ../bench and the README example in ../example. Test binaries land in
# the build's bin/ for a uniform ./bin/test_X path.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# The tests are built with emp-ag's test hooks (backend/common/test_hooks.h) unless
# EMP_AG_TEST_HOOKS is OFF; the library, examples and benches are never built with them.
if(EMP_AG_TEST_HOOKS)
    add_compile_definitions(EMP_AG_TEST_HOOKS)
endif()

# Tests that need multiple parties depend on the repo-root `run` / `runN` helpers that spawn
# the right number of processes. The shared helpers _apply_strict_memaccess and add_np_variant
# live in cmake/AgTestHelpers.cmake (included at the top level, so in scope here and in
# adversarial/).

function(add_test_case _name)
    add_executable(test_${_name} ${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-ag::emp-ag)
    _apply_strict_memaccess(test_${_name})
    add_test(NAME ${_name}
             COMMAND test_${_name}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

function(add_test_case_with_run _name)
    add_executable(test_${_name} ${_name}.cpp)
    target_link_libraries(test_${_name} PRIVATE emp-ag::emp-ag)
    _apply_strict_memaccess(test_${_name})
    add_test(NAME ${_name}
             COMMAND ${PROJECT_SOURCE_DIR}/run $<TARGET_FILE:test_${_name}>
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endfunction()

# Transport: k meshes over ONE listening port per party (tagged handshake),
# incl. a full session on mesh 0 concurrent with traffic on mesh 1.
add_test_case_with_run(netmp_group)

# The share layer on its own: ashare_test runs an AShareGen over both mints (SoftSpokenMint,
# and SilentFerretMint unplanned and prepaid), checking every share in both directions of
# every pair, at 2, 3 and 4 parties.
add_np_variant(ashare_test_np2 ashare_test.cpp 2 DEFS ASHARE_NP=2)
add_np_variant(ashare_test_np3 ashare_test.cpp 3 DEFS ASHARE_NP=3)
add_np_variant(ashare_test_np4 ashare_test.cpp 4 DEFS ASHARE_NP=4)

# Typed-value frontend over AGMPCSession (BooleanProgram -> AGMPCEngine) + IR.
# agmpc_reactive also hosts the direct-recording checks (const-only first chunk,
# NOT gate, PUBLIC-const input) and the RAII scope-liveness cases; agmpc_artifact
# runs both stored builtins (aes128 + sha256_256) vs the ClearCtx oracle through
# the production owning ctor; agmpc_wire_reuse also hosts the three-strategy
# (body / compiled / run_artifact) agreement block.
add_test_case_with_run(program_engine_test)
add_test_case_with_run(agmpc_artifact)
add_test_case_with_run(agmpc_rounds)
add_test_case_with_run(agmpc_chain)
add_test_case_with_run(agmpc_reactive)
add_test_case_with_run(agmpc_wire_reuse)
add_test_case_with_run(agmpc_compose)

# Single-process circuit analysis (no parties). The Delta bit-pinning property
# bit1(+_p Delta_p)=1 is checked by a static_assert next to the pinning in
# backend/ashare/ashare_gen.h.
add_test_case(bucketing_test)              # bucket_size matches the n-party leakage bound
add_test_case(cut_and_choose_bound_test)   # cut-and-choose parameters vs exact small-batch bounds
add_test_case(laand_window_test)           # exact bit windows, independent codec oracle
add_test_case(feq_test)                    # nonce-only F_eq wire count and adversarial openings
add_test_case(ashare_joint_fold)           # the SilentFerret mint's joint LPN step == emp-ot's Lpn, per stream
set_tests_properties(feq_test PROPERTIES TIMEOUT 15)
add_test_case(ev_records_equiv)            # P1 draw-time record extraction == live-bundle kernels
add_test_case(halfgate_hash_test)          # each AND half under its own gid; evaluator streams match

# 2-party session tests on AGMPCSession<2>: the ChunkedSession base + typed value
# surface are shared with the n-party path, so these pin the nP==2 instantiation
# (IO = NetIOMP<2>; party 1 = evaluator/verdict, party 2 = garbler) against the
# agmpc_test::clear_eval oracle. Single-process compile/logic gates run with no run
# helper; the 2-party network ones run via runN 2 below.
add_test_case(agmpc_session_concepts)      # compile-time: AGMPCSession<2> models the session concepts
add_test_case(agmpc_flush_plan)            # session::plan_flush DCE/compaction/stale-operand (session-agnostic)

# Golden snapshot: a strategy x circuit matrix gated on OUTPUT CORRECTNESS vs a
# cleartext oracle (the transcript is non-deterministic at nP>=3, so it is not
# byte-frozen). One source, party count via GOLDEN_NP: nP=2 exercises the nP==2
# special cases (single garbler / no S-alloc / streamlined leaky-AND); nP=3 is
# the n-party path (add_np_variant -> runN <nP>).
# np4 = the deeper 2->3->4->P1 aggregation ring.
add_np_variant(agmpc_golden_np2 agmpc_golden_snapshot.cpp 2 DEFS GOLDEN_NP=2)
add_np_variant(agmpc_golden_np3 agmpc_golden_snapshot.cpp 3  DEFS GOLDEN_NP=3)
add_np_variant(agmpc_golden_np4 agmpc_golden_snapshot.cpp 4 DEFS GOLDEN_NP=4)
# The same matrix under the open checker that is not the default for the party count
# (ashare/open_check.h: pairwise at nP=2, symmetric above).
add_np_variant(agmpc_golden_symmetric_np2 agmpc_golden_snapshot.cpp 2 DEFS GOLDEN_NP=2 ARGS open_check=symmetric)
add_np_variant(agmpc_golden_pairwise_np3 agmpc_golden_snapshot.cpp 3 DEFS GOLDEN_NP=3 ARGS open_check=pairwise)
add_np_variant(agmpc_golden_pairwise_np4 agmpc_golden_snapshot.cpp 4 DEFS GOLDEN_NP=4 ARGS open_check=pairwise)

# Garbling options (backend/garble/garble_config.h): the golden matrix and prepared runs under each
# option that is not the default.
add_np_variant(agmpc_golden_direct_np3 agmpc_golden_snapshot.cpp 3 DEFS GOLDEN_NP=3 ARGS delivery=direct)
add_np_variant(agmpc_golden_direct_np4 agmpc_golden_snapshot.cpp 4 DEFS GOLDEN_NP=4 ARGS delivery=direct)
add_np_variant(agmpc_prepared_direct_np3 agmpc_prepared.cpp 3 DEFS PREP_NP=3 ARGS delivery=direct)
add_np_variant(agmpc_golden_wrk_np2 agmpc_golden_snapshot.cpp 2 DEFS GOLDEN_NP=2 EMP_AG_GARBLE_AUTH=WRK)
add_np_variant(agmpc_golden_wrk_np3 agmpc_golden_snapshot.cpp 3 DEFS GOLDEN_NP=3 EMP_AG_GARBLE_AUTH=WRK)
add_np_variant(agmpc_golden_wrk_np4 agmpc_golden_snapshot.cpp 4 DEFS GOLDEN_NP=4 EMP_AG_GARBLE_AUTH=WRK)
add_np_variant(agmpc_golden_wrk_direct_np3 agmpc_golden_snapshot.cpp 3
               DEFS GOLDEN_NP=3 EMP_AG_GARBLE_AUTH=WRK ARGS delivery=direct)
add_np_variant(agmpc_golden_wrk_direct_np4 agmpc_golden_snapshot.cpp 4
               DEFS GOLDEN_NP=4 EMP_AG_GARBLE_AUTH=WRK ARGS delivery=direct)
add_np_variant(agmpc_prepared_wrk_np2 agmpc_prepared.cpp 2 DEFS PREP_NP=2 EMP_AG_GARBLE_AUTH=WRK)
add_np_variant(agmpc_prepared_wrk_np3 agmpc_prepared.cpp 3 DEFS PREP_NP=3 EMP_AG_GARBLE_AUTH=WRK)
add_np_variant(agmpc_linear_wrk_np3 agmpc_linear.cpp 3 DEFS LIN_NP=3 EMP_AG_GARBLE_AUTH=WRK)
# Three-party runs that chain (an AND-derived output of one run is an input of the next,
# revealed to every party), compose and reuse wires, under WRK and under direct delivery.
foreach(_t agmpc_chain agmpc_reactive agmpc_compose agmpc_wire_reuse agmpc_artifact)
    add_np_variant(${_t}_wrk ${_t}.cpp 3 DEFS EMP_AG_GARBLE_AUTH=WRK)
endforeach()
foreach(_t agmpc_chain agmpc_reactive)
    add_np_variant(${_t}_direct ${_t}.cpp 3 ARGS delivery=direct)
    add_np_variant(${_t}_wrk_direct ${_t}.cpp 3 DEFS EMP_AG_GARBLE_AUTH=WRK ARGS delivery=direct)
endforeach()

# Cut-and-choose triples (backend/triple/cut_and_choose_triples.h). The generator alone,
# white-box (check_MAC sends Delta: EMP_AG_DEBUG_CHECKS), across batches and the bank, under
# each checker; then the golden matrix with every session's triples from it, which covers
# the Beaver step and the per-call half-gate seed.
#
# The sessions' batch: every session generates at least one whole batch, so a Debug build,
# where generating one is far slower, uses a smaller batch. The cnc goldens carry the
# debug_heavy label, which CI's macOS Debug job leaves out (.github/workflows/build.yml).
set(AG_TEST_CNC_BATCH "$<IF:$<CONFIG:Debug>,1024,16384>")
add_np_variant(agmpc_cut_and_choose_np2 agmpc_cut_and_choose.cpp 2 DEFS CNC_NP=2 EMP_AG_DEBUG_CHECKS)
add_np_variant(agmpc_cut_and_choose_np3 agmpc_cut_and_choose.cpp 3 DEFS CNC_NP=3 EMP_AG_DEBUG_CHECKS)
add_np_variant(agmpc_cut_and_choose_np4 agmpc_cut_and_choose.cpp 4 DEFS CNC_NP=4 EMP_AG_DEBUG_CHECKS)
add_np_variant(agmpc_cut_and_choose_over_declared_np2 agmpc_cut_and_choose.cpp 2
               DEFS CNC_NP=2 EMP_AG_DEBUG_CHECKS ARGS over_declared PASS_RE "more batches than declared")
add_np_variant(agmpc_cut_and_choose_symmetric_np2 agmpc_cut_and_choose.cpp 2
               DEFS CNC_NP=2 EMP_AG_DEBUG_CHECKS ARGS open_check=symmetric)
add_np_variant(agmpc_cut_and_choose_pairwise_np3 agmpc_cut_and_choose.cpp 3
               DEFS CNC_NP=3 EMP_AG_DEBUG_CHECKS ARGS open_check=pairwise)
add_np_variant(agmpc_golden_cnc_np2 agmpc_golden_snapshot.cpp 2
               DEFS GOLDEN_NP=2 ARGS cnc=${AG_TEST_CNC_BATCH})
add_np_variant(agmpc_golden_cnc_np3 agmpc_golden_snapshot.cpp 3
               DEFS GOLDEN_NP=3 ARGS cnc=${AG_TEST_CNC_BATCH})
add_np_variant(agmpc_golden_cnc_pairwise_np3 agmpc_golden_snapshot.cpp 3
               DEFS GOLDEN_NP=3 ARGS cnc=${AG_TEST_CNC_BATCH} open_check=pairwise)
set_tests_properties(agmpc_golden_cnc_np2 agmpc_golden_cnc_np3 agmpc_golden_cnc_pairwise_np3
                     PROPERTIES LABELS debug_heavy)
# At nP = 4 the four parties share the macOS runners' three cores, and these become the
# slowest Debug tests there, so they carry debug_heavy too. Every other job runs them.
set_tests_properties(agmpc_golden_np4 agmpc_golden_pairwise_np4 agmpc_golden_direct_np4
                     agmpc_golden_wrk_np4 agmpc_golden_wrk_direct_np4 agmpc_cut_and_choose_np4
                     PROPERTIES LABELS debug_heavy)

# Pure-linear (zero AND gates) revealed to a GARBLER: covers the num_ands==0
# garbler-MASK propagation (a garbler sets its fabric MASK only in the output-check walk,
# which must run even at num_ands==0). Gated on exit code (reveal == cleartext a^b). np2 + np3.
add_np_variant(agmpc_linear_np2 agmpc_linear.cpp 2 DEFS LIN_NP=2)
add_np_variant(agmpc_linear_np3 agmpc_linear.cpp 3  DEFS LIN_NP=3)

# Scalar offline/online prepared execution: nP=2 covers the one-garbler stored-G
# path; nP=3 covers stored aggregate rows plus input-Lambda EchoBC.
add_np_variant(agmpc_prepared_np2 agmpc_prepared.cpp 2 DEFS PREP_NP=2)
add_np_variant(agmpc_prepared_np3 agmpc_prepared.cpp 3 DEFS PREP_NP=3)
add_np_variant(agmpc_prepared_adopt_np3 agmpc_prepared.cpp 3 DEFS PREP_NP=3 ARGS adopt_above_two
               PASS_RE "authenticated inputs need two parties")
# A long offline phase as the session's first work: every receiver of a party must
# already be aligned when the draws run past the first COT chunk (see the source).
add_np_variant(agmpc_long_offline_np3 agmpc_long_offline.cpp 3 DEFS LONG_NP=3)
add_np_variant(agmpc_long_offline_np4 agmpc_long_offline.cpp 4 DEFS LONG_NP=4)

# WRK generation must consume the planned 3B COTs per AND (one output mask, and B
# leaky triples whose first takes the gate's second input mask as its b) in both
# execution paths. One fewer COT must be rejected by the live stream; a construction
# that reused any other circuit mask would stay below that budget.
# COT streams the application supplies (ashare/cot_extension_factory.h): SoftSpoken over a
# BMM base OT at nP = 2 and 3, and the two misuses the session refuses.
add_np_variant(agmpc_cot_extension_factory_np2 agmpc_cot_extension_factory.cpp 2 DEFS COT_FACTORY_NP=2)
add_np_variant(agmpc_cot_extension_factory_np3 agmpc_cot_extension_factory.cpp 3 DEFS COT_FACTORY_NP=3)
add_np_variant(agmpc_cot_extension_factory_lanes agmpc_cot_extension_factory.cpp 2
               DEFS COT_FACTORY_NP=2 ARGS case=1 PASS_RE "supplied streams run on one lane")
add_np_variant(agmpc_cot_extension_factory_noid agmpc_cot_extension_factory.cpp 2
               DEFS COT_FACTORY_NP=2 ARGS case=2 PASS_RE "supplied factory needs an id")
add_np_variant(agmpc_cot_extension_factory_owndelta agmpc_cot_extension_factory.cpp 2
               DEFS COT_FACTORY_NP=2 ARGS case=3 PASS_RE "does not run under the Delta it was given")
# The AND gates' protocol a session is given: an id without a protocol, or a protocol
# without an id, is refused before any traffic.
add_np_variant(agmpc_and_prep_factory_noprotocol agmpc_and_prep_factory.cpp 2 ARGS case=1 PASS_RE "an id without a protocol")
add_np_variant(agmpc_and_prep_factory_noid agmpc_and_prep_factory.cpp 2 ARGS case=2 PASS_RE "a supplied protocol needs an id")
# A computation's Party slot bound to authenticated bundles made from one-way draw_cots()
# COTs, and the opening's MAC check catching a false claim.
add_np_variant(agmpc_computation_authenticated agmpc_computation_authenticated.cpp 2)
add_np_variant(agmpc_computation_authenticated_cheat agmpc_computation_authenticated.cpp 2 ARGS case=1 PASS_RE "share-MAC hash mismatch")
# Above two parties, nothing checks a supplied bundle across receivers: refused.
add_np_variant(agmpc_computation_authenticated_np3 agmpc_computation_authenticated.cpp 3
               DEFS AUTH_NP=3 PASS_RE "authenticated slots need two parties")
# While the job is outstanding, the share pool refuses its own draws and COT check: they go
# through the job (draw_cots(job, ...), check_cots(job)).
add_np_variant(agmpc_computation_authenticated_draw agmpc_computation_authenticated.cpp 2 ARGS case=3 PASS_RE "draw through AGMPCSession::draw_cots")
add_np_variant(agmpc_computation_authenticated_check agmpc_computation_authenticated.cpp 2 ARGS case=4 PASS_RE "check through AGMPCSession::check_cots")
# A session's COT plan (AGMPCSession::planned_cots) is exactly what its streams draw: the
# leaky ANDs, cut-and-choose over several batches, no AND gates, job draws at nP = 2, the
# B13 LPN set on SilentFerret streams, share mode planned from its draws, and a slot bound at
# prepare.
add_np_variant(agmpc_planned_cots_np2 agmpc_planned_cots.cpp 2 DEFS PLANNED_NP=2)
add_np_variant(agmpc_planned_cots_np3 agmpc_planned_cots.cpp 3 DEFS PLANNED_NP=3)
add_np_variant(agmpc_independent_triples_direct_np2 agmpc_independent_triples.cpp 2)
add_np_variant(agmpc_independent_triples_prepared_np2 agmpc_independent_triples.cpp 2 ARGS prepared)
# SilentFerret takes a plan as the size of its prepaid batch and prepays another batch
# when a stream runs past it, so only the other backends reject the extra COT.
if(NOT EMP_AG_OT_BACKEND STREQUAL "SilentFerret")
  add_np_variant(agmpc_independent_triples_short_np2 agmpc_independent_triples.cpp 2 ARGS prepared short
                 PASS_RE "exceeds declared element count")
endif()

# SoftSpoken lane-parallel COT end-to-end over a NetIOMPGroup (L=2), one source
# with the party count via LANE_NP. BOTH registrations are load-bearing: nP=2 is
# the ONLY regime with no runtime cross-consistency backstop (the guard that both
# parties used an identical lane partition / cadence / clone order); nP=3 exercises the
# malicious-check paths under lanes -- check1's csp tail (assembled after the
# lane join) and check2's universal-hash fold (the nP>2 cross-peer x^me backstop).
add_np_variant(lane_np2 lane.cpp 2 DEFS LANE_NP=2)
add_np_variant(lane_np3 lane.cpp 3 DEFS LANE_NP=3)

# Wire-byte-identity oracle (NOT a ctest: build-only, run manually via ./run or ./runN to
# dump per-channel wire digests, then diff before/after -- the committed reference for the
# DEFAULT (SHA) build is test/trace_np2.golden). It needs a test-mode build: configure
# against emp-tool + emp-ot built with -DEMP_TEST_MODE=ON (a build option; no environment
# variable enables it). Valid at nP==2 only -- at nP>=3 the aggregation ring's concurrent
# sends make the per-channel digest thread-schedule-dependent. One source, two party
# counts via TRACE_NP. These are the ONLY targets allowed to run in a test-mode build
# (they diff wire digests), so they opt past the AShareGen production guard via
# EMP_AG_ALLOW_TEST_MODE.
add_executable(test_trace_np2 trace_digest.cpp)
target_link_libraries(test_trace_np2 PRIVATE emp-ag::emp-ag)
target_compile_definitions(test_trace_np2 PRIVATE TRACE_NP=2 EMP_AG_ALLOW_TEST_MODE)
_apply_strict_memaccess(test_trace_np2)
add_executable(test_trace_np3 trace_digest.cpp)
target_link_libraries(test_trace_np3 PRIVATE emp-ag::emp-ag)
target_compile_definitions(test_trace_np3 PRIVATE TRACE_NP=3 EMP_AG_ALLOW_TEST_MODE)
_apply_strict_memaccess(test_trace_np3)

# 2-party network tests on AGMPCSession<2>. Each runs as 2 processes via runN 2
# (NOT run, which is 3-party); party 1 is the evaluator that compares the revealed
# output to the oracle.
foreach(_agmpc2 agmpc_context_api agmpc_direct_chunks agmpc_program_replay agmpc_body_replay_equiv
                agmpc_session_id)
    add_executable(test_${_agmpc2} ${_agmpc2}.cpp)
    target_link_libraries(test_${_agmpc2} PRIVATE emp-ag::emp-ag)
    _apply_strict_memaccess(test_${_agmpc2})
    add_test(NAME ${_agmpc2}
             COMMAND ${PROJECT_SOURCE_DIR}/runN 2 $<TARGET_FILE:test_${_agmpc2}>
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endforeach()
# The session id of a build that chose a non-default open checker is bound to it.
add_np_variant(agmpc_session_id_open_check agmpc_session_id.cpp 2 ARGS open_check=symmetric)

# Circuit mode (Computation): the knob matrix, Auth x Delivery x triple source x nP
# (the two Delivery options coincide at nP = 2), plus a non-default ssp, and the
# misuse cases that must stop before any traffic.
foreach(_np 2 3 4)
    foreach(_auth KRRW WRK)
        foreach(_src leaky cnc)
            string(TOLOWER "agmpc_computation_${_auth}_${_src}_np${_np}" _name)
            set(_defs COMP_NP=${_np} EMP_AG_GARBLE_AUTH=${_auth})
            set(_args "")
            if(_src STREQUAL "cnc")
                set(_args cnc=${AG_TEST_CNC_BATCH})
            endif()
            add_np_variant(${_name} agmpc_computation.cpp ${_np} DEFS ${_defs} ARGS ${_args})
            if(NOT _np EQUAL 2)
                add_np_variant(${_name}_direct agmpc_computation.cpp ${_np}
                               DEFS ${_defs} ARGS delivery=direct ${_args})
            endif()
        endforeach()
    endforeach()
endforeach()
add_np_variant(agmpc_computation_ssp60_np3 agmpc_computation.cpp 3 DEFS COMP_NP=3 ARGS ssp=60)
add_np_variant(agmpc_computation_wrk_ssp60_np2 agmpc_computation.cpp 2
               DEFS COMP_NP=2 EMP_AG_GARBLE_AUTH=WRK ARGS ssp=60)
add_np_variant(agmpc_computation_busy_np2 agmpc_computation.cpp 2 DEFS COMP_NP=2 ARGS busy
               PASS_RE "a Computation job is outstanding")
add_np_variant(agmpc_computation_bad_owner_np2 agmpc_computation.cpp 2 DEFS COMP_NP=2 ARGS bad_owner
               PASS_RE "an input owner is above the party count")
add_np_variant(agmpc_computation_full_reuse_np2 agmpc_computation.cpp 2 DEFS COMP_NP=2 ARGS full_reuse
               PASS_RE "WireReuse::Full is not supported")
add_np_variant(agmpc_computation_ssp_skew_np2 agmpc_computation.cpp 2 DEFS COMP_NP=2 ARGS ssp_skew=20
               PASS_RE "check failed")
add_np_variant(agmpc_computation_composed_full_np2 agmpc_computation.cpp 2
               DEFS COMP_NP=2 ARGS composed_full_unit
               PASS_RE "WireReuse::Full composition unit not supported")

# Share mode (authenticated GMW) against the circuits evaluated in the clear, at nP = 2, 3, 4
# and with 80-bit tags; a session whose AND-gate protocol keeps no triple bank refuses it.
foreach(_np 2 3 4)
    add_np_variant(agmpc_share_eval_np${_np} agmpc_share_eval.cpp ${_np} DEFS SHARE_NP=${_np})
endforeach()
add_np_variant(agmpc_share_eval_tag80_np3 agmpc_share_eval.cpp 3
               DEFS SHARE_NP=3 ARGS tag_bytes=10)
add_np_variant(agmpc_share_eval_no_bank_np2 agmpc_share_eval.cpp 2 DEFS SHARE_NP=2 ARGS no_bank
               PASS_RE "keeps no triple bank")
# Openings the caller checks itself (share_opening, absorb_expected_macs), at nP = 2 and 3; a
# flipped bit must fail the caller's digest check.
foreach(_np 2 3)
    add_np_variant(agmpc_share_opening_np${_np} agmpc_share_opening.cpp ${_np} DEFS SHARE_OPEN_NP=${_np})
endforeach()
add_np_variant(agmpc_share_opening_flip_np3 agmpc_share_opening.cpp 3
               DEFS SHARE_OPEN_NP=3 ARGS flip PASS_RE "a peer's bits do not match its MACs")

# Party slots bound at prepare to share-mode values (prepare_computation(art, bound)), against
# the circuits in the clear: at nP = 2, 3, 4 under each Auth, WRK with direct delivery, and on
# the leaky ANDs from share_input and share_random alone; under WRK also with the output masks
# opened ahead of the run. The misuses are refused before any traffic.
foreach(_np 2 3 4)
    add_np_variant(agmpc_computation_bound_np${_np} agmpc_computation_bound.cpp ${_np}
                   DEFS BOUND_NP=${_np})
    add_np_variant(agmpc_computation_bound_wrk_np${_np} agmpc_computation_bound.cpp ${_np}
                   DEFS BOUND_NP=${_np} EMP_AG_GARBLE_AUTH=WRK BOUND_EXPERT)
endforeach()
add_np_variant(agmpc_computation_bound_wrk_direct_np3 agmpc_computation_bound.cpp 3
               DEFS BOUND_NP=3 EMP_AG_GARBLE_AUTH=WRK BOUND_EXPERT ARGS delivery=direct)
add_np_variant(agmpc_computation_bound_leaky_np3 agmpc_computation_bound.cpp 3
               DEFS BOUND_NP=3 BOUND_LEAKY)
add_np_variant(agmpc_computation_bound_leaky_wrk_np2 agmpc_computation_bound.cpp 2
               DEFS BOUND_NP=2 BOUND_LEAKY EMP_AG_GARBLE_AUTH=WRK)
add_np_variant(agmpc_computation_bound_width_np2 agmpc_computation_bound.cpp 2
               DEFS BOUND_NP=2 BOUND_MISUSE=1 PASS_RE "a bound value differs from its slot's width")
add_np_variant(agmpc_computation_bound_public_np2 agmpc_computation_bound.cpp 2
               DEFS BOUND_NP=2 BOUND_MISUSE=2 PASS_RE "a bound slot must be a Party slot")
add_np_variant(agmpc_computation_bound_foreign_np2 agmpc_computation_bound.cpp 2
               DEFS BOUND_NP=2 BOUND_MISUSE=3 PASS_RE "wires from another session")
add_np_variant(agmpc_computation_bound_key_closed_np2 agmpc_computation_bound.cpp 2
               DEFS BOUND_NP=2 BOUND_MISUSE=4 EMP_AG_GARBLE_AUTH=WRK
               PASS_RE "AGMPCSession::expert_output_key")

# Fault-injection / adversarial tests: turn on the test hooks and assert the protocol
# aborts. They need a hooks build.
if(EMP_AG_TEST_HOOKS)
    add_subdirectory(adversarial)
endif()
