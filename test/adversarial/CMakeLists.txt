# Adversarial (fault-injection) tests, nested under test/ but kept in their own tree: each
# compiles a production-guarded EMP_AG_TEST_FLIP_* hook (backend/) and asserts the protocol
# ABORTS: expecting() prints a message + exits nonzero, so every test is gated on its abort message
# via add_np_variant's PASS_RE. Reaching the end of a test means the injected fault went
# UNDETECTED -> nonzero exit + no abort line -> the regex fails. add_np_variant and
# _apply_strict_memaccess are the shared helpers from cmake/AgTestHelpers.cmake (included at the
# top level, so in scope here). Binaries land in bin/ like the functional tests.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# FLIP_LAMBDA: a malicious P1 flips one broadcast AND-output Lambda (open_and_masks). Every
# honest party must abort in the c_gamma MACCheck; at nP=3 the two GARBLERS (not just the
# evaluator) catch a P1 flip.
add_np_variant(agmpc_output_cheat_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_LAMBDA PASS_RE "cheat in c_gamma MACCheck")
add_np_variant(agmpc_output_cheat_np3 agmpc_output_cheat.cpp 3  DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_LAMBDA PASS_RE "cheat in c_gamma MACCheck")

# FLIP_AGG (nP>=3): the garbler-row-aggregation ring tail corrupts one aggregate row -> wrong
# Lambda_gamma -> the same MACCheck aborts.
add_np_variant(agmpc_cheat_agg_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_AGG PASS_RE "cheat in c_gamma MACCheck")

# FLIP_INPUT_LAMBDA (nP>=3): a malicious owner equivocates the input Lambda on a PURE-LINEAR
# circuit -- the c_gamma MACCheck has no AND to bind, so only the input-Lambda echo agreement
# can catch it, and every honest party must abort.
add_np_variant(agmpc_input_equiv_np3 agmpc_input_equiv.cpp 3 DEFS EQUIV_NP=3 EMP_AG_TEST_FLIP_INPUT_LAMBDA PASS_RE "input Lambda equivocation")

# FLIP_B (nP==2): a malicious GARBLER flips one transmitted designated bit b -> P1 derives a
# wrong Lambda_gamma. c_gamma is the SOLE malicious-garbler guard at nP==2, so every honest
# party must abort -- the core 2-party garbler soundness case.
add_np_variant(agmpc_cheat_b_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_B PASS_RE "cheat in c_gamma MACCheck")

# FLIP_LAAND: corrupt the derived two-party LaAND value (deterministically) / shipped
# multiparty rows -> the preprocessing consistency check must abort (F_eq at nP==2 /
# the batched windowed-alpha RLC at nP>=3; both abort messages contain "LaAND").
add_np_variant(agmpc_cheat_laand_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_LAAND PASS_RE "LaAND")
add_np_variant(agmpc_cheat_laand_np3 agmpc_output_cheat.cpp 3  DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_LAAND PASS_RE "LaAND")

# The final retained coordinate must be checked, even in a partial row byte.
add_np_variant(agmpc_cheat_laand_high_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_LAAND_HIGH PASS_RE "LaAND")
add_np_variant(agmpc_cheat_laand_high_39_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 CHEAT_SSP=39 EMP_AG_TEST_FLIP_LAAND_HIGH PASS_RE "LaAND")
add_np_variant(agmpc_cheat_laand_high_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_LAAND_HIGH PASS_RE "LaAND")

# FLIP_D / FLIP_XY: a malicious party flips its share of one opened bucket d-bit / Beaver x
# and sends it to everyone, keeping it itself. Every party then derives the same validly
# authenticated but wrong sigma, which the c_gamma MACCheck cannot see, so the open check
# (crypto/open_check.h) must abort. Each runs under the default checker (pairwise at nP=2,
# symmetric above) and under the other one.
add_np_variant(agmpc_cheat_d_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_D PASS_RE "open check")
add_np_variant(agmpc_cheat_d_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_D PASS_RE "open check")
add_np_variant(agmpc_cheat_xy_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_XY PASS_RE "open check")
add_np_variant(agmpc_cheat_xy_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_XY PASS_RE "open check")
add_np_variant(agmpc_cheat_d_symmetric_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_D EMP_AG_OPEN_CHECK_SYMMETRIC PASS_RE "open check")
add_np_variant(agmpc_cheat_xy_symmetric_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_XY EMP_AG_OPEN_CHECK_SYMMETRIC PASS_RE "open check")
add_np_variant(agmpc_cheat_d_pairwise_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_D EMP_AG_OPEN_CHECK_PAIRWISE PASS_RE "open check")
add_np_variant(agmpc_cheat_xy_pairwise_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_XY EMP_AG_OPEN_CHECK_PAIRWISE PASS_RE "open check")

# FLIP_AGG_MID (nP>=4): a MIDDLE aggregation-ring node (not head/tail) corrupts a row -> the tail
# forwards it -> the c_gamma MACCheck aborts. Complements the tail-only FLIP_AGG and is the
# suite's only nP=4 adversarial case.
add_np_variant(agmpc_cheat_agg_mid_np4 agmpc_output_cheat.cpp 4 DEFS CHEAT_NP=4 EMP_AG_TEST_FLIP_AGG_MID PASS_RE "cheat in c_gamma MACCheck")

# The same integrity boundaries after an offline/online split: the row fault is
# delivered and stored during prepare(), then detected only after online binding;
# the zero-AND input split is still caught by the shared Lambda echo.
add_np_variant(agmpc_prepared_cheat_b_np2 agmpc_prepared_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_B PASS_RE "cheat in c_gamma MACCheck")
add_np_variant(agmpc_prepared_cheat_agg_np3 agmpc_prepared_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_AGG PASS_RE "cheat in c_gamma MACCheck")
add_np_variant(agmpc_prepared_input_equiv_np3 agmpc_prepared_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_INPUT_LAMBDA PASS_RE "input Lambda equivocation")

# A caller-provided adopted bundle must be authenticated under this session's
# Delta. Corrupt a non-value MAC bit after ordinary authentication and require
# the prepared soldering open to reject it before evaluation.
add_np_variant(agmpc_prepared_adopt_mac_np2 agmpc_prepared_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_CORRUPT_ADOPTED_SHARE PASS_RE "open_to_targets: share-MAC hash mismatch")

# The paired prepare-only runs prove row corruption is stored without aborting
# during the offline phase; the variants above then require its online MACCheck
# abort. Keeping this as a separate successful run avoids a fragile cross-process
# output-order regex.
add_test(NAME agmpc_prepared_cheat_b_np2_offline
         COMMAND ${PROJECT_SOURCE_DIR}/runN 2
                 $<TARGET_FILE:test_agmpc_prepared_cheat_b_np2> prepare-only
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
add_test(NAME agmpc_prepared_cheat_agg_np3_offline
         COMMAND ${PROJECT_SOURCE_DIR}/runN 3
                 $<TARGET_FILE:test_agmpc_prepared_cheat_agg_np3> prepare-only
         WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
