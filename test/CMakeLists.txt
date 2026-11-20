# Correctness tests. Only added when EMP_AG_BUILD_TESTS is ON (gated at the top level);
# benchmarks live in ../bench and the README example in ../example. Test binaries land in
# the build's bin/ for a uniform ./bin/test_X path.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

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

# Lower-layer protocol tests (auth-shares / IKNP). Both use the white-box check_MAC COT
# correlation check, compiled only under EMP_AG_DEBUG_CHECKS.
add_test_case_with_run(three_party_iknp)
target_compile_definitions(test_three_party_iknp PRIVATE EMP_AG_DEBUG_CHECKS)
add_test_case_with_run(auth_share)
target_compile_definitions(test_auth_share PRIVATE EMP_AG_DEBUG_CHECKS)

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
# backend/preproc/auth_share_pool.h.
add_test_case(bucketing_test)              # bucket_size matches the n-party leakage bound
add_test_case(cut_and_choose_bound_test)   # cut-and-choose parameters vs exact small-batch bounds
add_test_case(laand_window_test)           # exact bit windows, independent codec oracle
add_test_case(feq_test)                    # nonce-only F_eq wire count and adversarial openings
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
# (crypto/open_check.h: pairwise at nP=2, symmetric above).
add_np_variant(agmpc_golden_symmetric_np2 agmpc_golden_snapshot.cpp 2 DEFS GOLDEN_NP=2 EMP_AG_OPEN_CHECK_SYMMETRIC)
add_np_variant(agmpc_golden_pairwise_np3 agmpc_golden_snapshot.cpp 3 DEFS GOLDEN_NP=3 EMP_AG_OPEN_CHECK_PAIRWISE)
add_np_variant(agmpc_golden_pairwise_np4 agmpc_golden_snapshot.cpp 4 DEFS GOLDEN_NP=4 EMP_AG_OPEN_CHECK_PAIRWISE)

# Cut-and-choose triples (backend/preproc/cut_and_choose_triples.h). The generator alone,
# white-box (check_MAC sends Delta: EMP_AG_DEBUG_CHECKS), across batches and the bank, under
# each checker; then the golden matrix with every session's triples from it, which covers
# the Beaver step and the per-call half-gate seed.
add_np_variant(agmpc_cut_and_choose_np2 agmpc_cut_and_choose.cpp 2 DEFS CNC_NP=2 EMP_AG_DEBUG_CHECKS)
add_np_variant(agmpc_cut_and_choose_np3 agmpc_cut_and_choose.cpp 3 DEFS CNC_NP=3 EMP_AG_DEBUG_CHECKS)
add_np_variant(agmpc_cut_and_choose_np4 agmpc_cut_and_choose.cpp 4 DEFS CNC_NP=4 EMP_AG_DEBUG_CHECKS)
add_np_variant(agmpc_cut_and_choose_symmetric_np2 agmpc_cut_and_choose.cpp 2
               DEFS CNC_NP=2 EMP_AG_DEBUG_CHECKS EMP_AG_OPEN_CHECK_SYMMETRIC)
add_np_variant(agmpc_cut_and_choose_pairwise_np3 agmpc_cut_and_choose.cpp 3
               DEFS CNC_NP=3 EMP_AG_DEBUG_CHECKS EMP_AG_OPEN_CHECK_PAIRWISE)
add_np_variant(agmpc_golden_cnc_np2 agmpc_golden_snapshot.cpp 2 DEFS GOLDEN_NP=2 EMP_AG_CUT_AND_CHOOSE_BATCH=16384)
add_np_variant(agmpc_golden_cnc_np3 agmpc_golden_snapshot.cpp 3 DEFS GOLDEN_NP=3 EMP_AG_CUT_AND_CHOOSE_BATCH=16384)
add_np_variant(agmpc_golden_cnc_pairwise_np3 agmpc_golden_snapshot.cpp 3
               DEFS GOLDEN_NP=3 EMP_AG_CUT_AND_CHOOSE_BATCH=16384 EMP_AG_OPEN_CHECK_PAIRWISE)

# Pure-linear (zero AND gates) revealed to a GARBLER: covers the num_ands==0
# garbler-MASK propagation (a garbler sets its fabric MASK only in the output-check walk,
# which must run even at num_ands==0). Gated on exit code (reveal == cleartext a^b). np2 + np3.
add_np_variant(agmpc_linear_np2 agmpc_linear.cpp 2 DEFS LIN_NP=2)
add_np_variant(agmpc_linear_np3 agmpc_linear.cpp 3  DEFS LIN_NP=3)

# Scalar offline/online prepared execution: nP=2 covers the one-garbler stored-G
# path; nP=3 covers stored aggregate rows plus input-Lambda EchoBC.
add_np_variant(agmpc_prepared_np2 agmpc_prepared.cpp 2 DEFS PREP_NP=2)
add_np_variant(agmpc_prepared_np3 agmpc_prepared.cpp 3 DEFS PREP_NP=3)
# A long offline phase as the session's first work: every receiver of a party must
# already be aligned when the draws run past the first COT chunk (see the source).
add_np_variant(agmpc_long_offline_np3 agmpc_long_offline.cpp 3 DEFS LONG_NP=3)
add_np_variant(agmpc_long_offline_np4 agmpc_long_offline.cpp 4 DEFS LONG_NP=4)

# WRK generation must consume the independently planned 3B+1 COTs per AND in
# both execution paths.  One fewer COT must be rejected by the live stream; a
# construction that reused circuit masks as triple operands would stay below
# that budget.
add_np_variant(agmpc_independent_triples_direct_np2 agmpc_independent_triples.cpp 2)
add_np_variant(agmpc_independent_triples_prepared_np2 agmpc_independent_triples.cpp 2
               DEFS INDEPENDENT_TRIPLES_PREPARED=1)
add_np_variant(agmpc_independent_triples_short_np2 agmpc_independent_triples.cpp 2
               DEFS INDEPENDENT_TRIPLES_PREPARED=1 INDEPENDENT_TRIPLES_SHORT=1
               PASS_RE "exceeds declared element count")

# SoftSpoken lane-parallel COT end-to-end over a NetIOMPGroup (L=2), one source
# with the party count via LANE_NP. BOTH registrations are load-bearing: nP=2 is
# the ONLY regime with no runtime cross-consistency backstop (the guard that both
# parties used an identical lane partition / salt / cadence); nP=3 exercises the
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
# (they diff wire digests), so they opt past the AuthSharePool production guard via
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

# Fault-injection / adversarial tests: compile the production-guarded EMP_AG_TEST_FLIP_*
# hooks and assert the protocol aborts.
add_subdirectory(adversarial)
