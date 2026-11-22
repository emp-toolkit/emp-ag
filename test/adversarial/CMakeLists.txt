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
# (ashare/open_check.h) must abort. Each runs under the default checker (pairwise at nP=2,
# symmetric above) and under the other one.
add_np_variant(agmpc_cheat_d_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_D PASS_RE "open check")
add_np_variant(agmpc_cheat_d_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_D PASS_RE "open check")
add_np_variant(agmpc_cheat_xy_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_XY PASS_RE "open check")
add_np_variant(agmpc_cheat_xy_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_XY PASS_RE "open check")
add_np_variant(agmpc_cheat_d_symmetric_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_D EMP_AG_OPEN_CHECK_SYMMETRIC PASS_RE "open check")
add_np_variant(agmpc_cheat_xy_symmetric_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_XY EMP_AG_OPEN_CHECK_SYMMETRIC PASS_RE "open check")
add_np_variant(agmpc_cheat_d_pairwise_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_D EMP_AG_OPEN_CHECK_PAIRWISE PASS_RE "open check")
add_np_variant(agmpc_cheat_xy_pairwise_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_XY EMP_AG_OPEN_CHECK_PAIRWISE PASS_RE "open check")
# aShare consistency (check2, nP>=3): every verifier checks each party's tag on its hash
# value at the fold, and the parties agree on the hash values later -- in the symmetric
# open check's zero test, or on their own after the pairwise check and before a reveal.
# FLIP_BW: party 2 sends party 3 a different hash value; SPLIT_CHOICE: party 2's bits
# differ between peers, every MAC valid; both fail party 3's tag check. TWO_WORLD +
# SPLIT_CHOICE: party 2 also sends each peer the value its bits toward that peer give, so
# every tag passes and only the agreement on the views catches it.
# agmpc_share_consistency.cpp has no AND, so its agreement is the settle before the
# reveal; with CONSISTENCY_AND it has one, and SPLIT_FIRST_DRAW splits only the input
# draw, so the triples stay consistent and the triple call's open check agrees on the
# views. SPLIT_DELTA (check1): party 2's global key toward party 3 differs from the
# one toward everyone else; check1, on the session's first draw, must abort.
add_np_variant(agmpc_cheat_bw_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_BW PASS_RE "cheat aShare")
add_np_variant(agmpc_cheat_bw_pairwise_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_BW EMP_AG_OPEN_CHECK_PAIRWISE PASS_RE "cheat aShare")
add_np_variant(agmpc_share_split_choice_np3 agmpc_share_consistency.cpp 3 DEFS CONSISTENCY_NP=3 EMP_AG_TEST_SPLIT_CHOICE PASS_RE "cheat aShare")
add_np_variant(agmpc_share_flip_bw_np3 agmpc_share_consistency.cpp 3 DEFS CONSISTENCY_NP=3 EMP_AG_TEST_FLIP_BW PASS_RE "cheat aShare")
add_np_variant(agmpc_share_two_world_np3 agmpc_share_consistency.cpp 3 DEFS CONSISTENCY_NP=3 EMP_AG_TEST_SPLIT_CHOICE EMP_AG_TEST_TWO_WORLD PASS_RE "cheat aShare: parties saw different consistency values")
add_np_variant(agmpc_share_two_world_np4 agmpc_share_consistency.cpp 4 DEFS CONSISTENCY_NP=4 EMP_AG_TEST_SPLIT_CHOICE EMP_AG_TEST_TWO_WORLD PASS_RE "cheat aShare: parties saw different consistency values")
add_np_variant(agmpc_share_two_world_and_np3 agmpc_share_consistency.cpp 3 DEFS CONSISTENCY_NP=3 CONSISTENCY_AND EMP_AG_TEST_SPLIT_CHOICE EMP_AG_TEST_SPLIT_FIRST_DRAW EMP_AG_TEST_TWO_WORLD PASS_RE "open check: parties saw different values opened without an echo")
add_np_variant(agmpc_share_two_world_and_np4 agmpc_share_consistency.cpp 4 DEFS CONSISTENCY_NP=4 CONSISTENCY_AND EMP_AG_TEST_SPLIT_CHOICE EMP_AG_TEST_SPLIT_FIRST_DRAW EMP_AG_TEST_TWO_WORLD PASS_RE "open check: parties saw different values opened without an echo")
add_np_variant(agmpc_share_split_delta_np3 agmpc_share_consistency.cpp 3 DEFS CONSISTENCY_NP=3 EMP_AG_TEST_SPLIT_DELTA PASS_RE "cheat check1")
add_np_variant(agmpc_share_split_delta_np4 agmpc_share_consistency.cpp 4 DEFS CONSISTENCY_NP=4 EMP_AG_TEST_SPLIT_DELTA PASS_RE "cheat check1")
# TAMPER_PREFIX: party 1, the primary COT receiver toward party 2, flips one bit of the
# first correction of the 128-COT bootstrap prefix on the wire. Party 2 must abort in its
# check of that prefix, before the reverse direction's base OTs are derived from it. Without
# that check, party 1's own reverse PPRF check fails first and party 2 never checks, so the
# regex distinguishes the two. Only SoftSpokenMint derives a reverse direction from a prefix.
if(EMP_AG_OT_BACKEND STREQUAL "SoftSpoken")
  add_np_variant(agmpc_cheat_prefix_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_TAMPER_PREFIX PASS_RE "SoftSpoken subspace VOLE check failed")
  add_np_variant(agmpc_cheat_prefix_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_TAMPER_PREFIX PASS_RE "SoftSpoken subspace VOLE check failed")
endif()

# FLIP_AGG_MID (nP>=4): a MIDDLE aggregation-ring node (not head/tail) corrupts a row -> the tail
# forwards it -> the c_gamma MACCheck aborts. Complements the tail-only FLIP_AGG and is the
# suite's only nP=4 adversarial case.
add_np_variant(agmpc_cheat_agg_mid_np4 agmpc_output_cheat.cpp 4 DEFS CHEAT_NP=4 EMP_AG_TEST_FLIP_AGG_MID PASS_RE "cheat in c_gamma MACCheck")
# FLIP_DIRECT (nP>=3, direct delivery): the last garbler corrupts a row it sends P1 directly ->
# wrong Lambda_gamma -> the c_gamma MACCheck aborts, in streaming and prepared runs.
add_np_variant(agmpc_cheat_direct_np3 agmpc_output_cheat.cpp 3
               DEFS CHEAT_NP=3 EMP_AG_GARBLE_DELIVERY=DIRECT EMP_AG_TEST_FLIP_DIRECT PASS_RE "cheat in c_gamma MACCheck")
add_np_variant(agmpc_cheat_direct_np4 agmpc_output_cheat.cpp 4
               DEFS CHEAT_NP=4 EMP_AG_GARBLE_DELIVERY=DIRECT EMP_AG_TEST_FLIP_DIRECT PASS_RE "cheat in c_gamma MACCheck")
# Auth::WRK, where P1 checks every gate itself. FLIP_P1_ROW: a garbler (the last, or party 2
# with EMP_AG_TEST_FLIP_PARTY=2) flips a bit of its unconditional row toward P1, so P1's check
# of that gate fails. FLIP_G (nP=2), FLIP_AGG / FLIP_AGG_MID (ring) and FLIP_DIRECT corrupt
# half-gate or cross rows instead: P1 recovers a wrong label, which fails the garbler's check
# of the output masks P1 hands it or, with CHEAT_DEPTH2, P1's own check of the next gate.
# FLIP_DELIVERED_LAMBDA: P1 hands garbler 2 a flipped output mask.
add_np_variant(agmpc_cheat_wrk_p1row_np2 agmpc_output_cheat.cpp 2
               DEFS CHEAT_NP=2 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_P1_ROW PASS_RE "WRK: a garbled gate failed")
add_np_variant(agmpc_cheat_wrk_p1row_np3 agmpc_output_cheat.cpp 3
               DEFS CHEAT_NP=3 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_P1_ROW PASS_RE "WRK: a garbled gate failed")
add_np_variant(agmpc_cheat_wrk_p1row_direct_np3 agmpc_output_cheat.cpp 3
               DEFS CHEAT_NP=3 EMP_AG_GARBLE_AUTH=WRK EMP_AG_GARBLE_DELIVERY=DIRECT EMP_AG_TEST_FLIP_P1_ROW
               PASS_RE "WRK: a garbled gate failed")
add_np_variant(agmpc_cheat_wrk_p1row_party2_np3 agmpc_output_cheat.cpp 3
               DEFS CHEAT_NP=3 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_P1_ROW EMP_AG_TEST_FLIP_PARTY=2
               PASS_RE "WRK: a garbled gate failed")
add_np_variant(agmpc_cheat_wrk_p1row_party2_direct_np3 agmpc_output_cheat.cpp 3
               DEFS CHEAT_NP=3 EMP_AG_GARBLE_AUTH=WRK EMP_AG_GARBLE_DELIVERY=DIRECT EMP_AG_TEST_FLIP_P1_ROW
                    EMP_AG_TEST_FLIP_PARTY=2 PASS_RE "WRK: a garbled gate failed")
add_np_variant(agmpc_cheat_wrk_g_np2 agmpc_output_cheat.cpp 2
               DEFS CHEAT_NP=2 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_G PASS_RE "WRK: P1's output masks")
add_np_variant(agmpc_cheat_wrk_g_depth2_np2 agmpc_output_cheat.cpp 2
               DEFS CHEAT_NP=2 CHEAT_DEPTH2 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_G
               PASS_RE "WRK: a garbled gate failed")
add_np_variant(agmpc_cheat_wrk_agg_np3 agmpc_output_cheat.cpp 3
               DEFS CHEAT_NP=3 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_AGG PASS_RE "WRK: P1's output masks")
add_np_variant(agmpc_cheat_wrk_agg_depth2_np3 agmpc_output_cheat.cpp 3
               DEFS CHEAT_NP=3 CHEAT_DEPTH2 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_AGG
               PASS_RE "WRK: a garbled gate failed")
add_np_variant(agmpc_cheat_wrk_agg_mid_np4 agmpc_output_cheat.cpp 4
               DEFS CHEAT_NP=4 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_AGG_MID PASS_RE "WRK: P1's output masks")
add_np_variant(agmpc_cheat_wrk_direct_np3 agmpc_output_cheat.cpp 3
               DEFS CHEAT_NP=3 EMP_AG_GARBLE_AUTH=WRK EMP_AG_GARBLE_DELIVERY=DIRECT EMP_AG_TEST_FLIP_DIRECT
               PASS_RE "WRK: P1's output masks")
add_np_variant(agmpc_cheat_wrk_lambda_np2 agmpc_output_cheat.cpp 2
               DEFS CHEAT_NP=2 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_DELIVERED_LAMBDA
               PASS_RE "WRK: P1's output masks")
add_np_variant(agmpc_cheat_wrk_lambda_np3 agmpc_output_cheat.cpp 3
               DEFS CHEAT_NP=3 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_DELIVERED_LAMBDA
               PASS_RE "WRK: P1's output masks")
add_np_variant(agmpc_prepared_cheat_wrk_p1row_np3 agmpc_prepared_cheat.cpp 3
               DEFS CHEAT_NP=3 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_P1_ROW PASS_RE "WRK: a garbled gate failed")

# The same integrity boundaries after an offline/online split: the row fault is
# delivered and stored during prepare(), then detected only after online binding;
# the zero-AND input split is still caught by the shared Lambda echo.
add_np_variant(agmpc_prepared_cheat_b_np2 agmpc_prepared_cheat.cpp 2 DEFS CHEAT_NP=2 EMP_AG_TEST_FLIP_B PASS_RE "cheat in c_gamma MACCheck")
add_np_variant(agmpc_prepared_cheat_agg_np3 agmpc_prepared_cheat.cpp 3 DEFS CHEAT_NP=3 EMP_AG_TEST_FLIP_AGG PASS_RE "cheat in c_gamma MACCheck")
add_np_variant(agmpc_prepared_cheat_direct_np3 agmpc_prepared_cheat.cpp 3
               DEFS CHEAT_NP=3 EMP_AG_GARBLE_DELIVERY=DIRECT EMP_AG_TEST_FLIP_DIRECT PASS_RE "cheat in c_gamma MACCheck")
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

# Cut-and-choose triples (EMP_AG_CUT_AND_CHOOSE_BATCH, backend/triple/cut_and_choose_triples.h).
# FLIP_PRODUCT: party 2 flips every product correction it sends party 1, so about half the
# candidates are wrong. FLIP_ZR: party 2 opens a wrong z ^ r for one candidate to everyone.
# FLIP_OPEN: party 2 opens a wrong share of one sacrifice difference to everyone. The open
# check (sacrifice residuals, opened values) or the cut must abort. SPLIT_ZR (nP >= 3): party
# 2 sends party 3 a different opening of z ^ r than everyone else, so parties 1 and 3 correct
# the candidates differently, which the aShare check's tags catch at the cut-and-choose
# coin, before the agreement on the views runs. KING_SPLIT (nP >= 3, kings): as a king, party 2 sends party 3 a different opened
# value, which leaves party 3 a residual the symmetric check catches.
set(_cnc EMP_AG_CUT_AND_CHOOSE_BATCH=1024)
add_np_variant(agmpc_cheat_cnc_product_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 ${_cnc} EMP_AG_TEST_CNC_FLIP_PRODUCT PASS_RE "cut-and-choose")
add_np_variant(agmpc_cheat_cnc_product_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_FLIP_PRODUCT PASS_RE "cut-and-choose")
add_np_variant(agmpc_cheat_cnc_zr_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 ${_cnc} EMP_AG_TEST_CNC_FLIP_ZR PASS_RE "cut-and-choose")
add_np_variant(agmpc_cheat_cnc_zr_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_FLIP_ZR PASS_RE "cut-and-choose")
add_np_variant(agmpc_cheat_cnc_open_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 ${_cnc} EMP_AG_TEST_CNC_FLIP_OPEN PASS_RE "cut-and-choose")
add_np_variant(agmpc_cheat_cnc_open_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_FLIP_OPEN PASS_RE "cut-and-choose")
add_np_variant(agmpc_cheat_cnc_split_zr_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_SPLIT_ZR PASS_RE "cheat aShare: MAC tag mismatch")
add_np_variant(agmpc_cheat_cnc_split_zr_pairwise_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_SPLIT_ZR EMP_AG_OPEN_CHECK_PAIRWISE PASS_RE "cheat aShare: MAC tag mismatch")
add_np_variant(agmpc_cheat_cnc_king_split_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_KING_SPLIT PASS_RE "cut-and-choose: opened values")
add_np_variant(agmpc_cheat_cnc_king_split_np4 agmpc_output_cheat.cpp 4 DEFS CHEAT_NP=4 ${_cnc} EMP_AG_TEST_CNC_KING_SPLIT PASS_RE "cut-and-choose: opened values")
# FLIP_ALL_ZR: party 2 opens every candidate's z ^ r wrong, so every candidate is wrong in
# the same way, which every sacrifice passes: only the cut can abort, and always does.
# FLIP_RECEIVER: as party 1's receiver, party 2 combines every correction under the wrong
# choice bit, an error it knows (the binding the hashed correlation gives). The forced
# checkers: FLIP_OPEN and FLIP_PRODUCT under the other checker; FLIP_RESIDUAL (pairwise,
# nP > 2): party 2 sends everyone a wrong share of a sacrifice residual, caught by its MAC.
add_np_variant(agmpc_cheat_cnc_all_zr_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 ${_cnc} EMP_AG_TEST_CNC_FLIP_ALL_ZR PASS_RE "a cut triple is incorrect")
add_np_variant(agmpc_cheat_cnc_all_zr_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_FLIP_ALL_ZR PASS_RE "a cut triple is incorrect")
add_np_variant(agmpc_cheat_cnc_receiver_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 ${_cnc} EMP_AG_TEST_CNC_FLIP_RECEIVER PASS_RE "cut-and-choose")
add_np_variant(agmpc_cheat_cnc_receiver_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_FLIP_RECEIVER PASS_RE "cut-and-choose")
add_np_variant(agmpc_cheat_cnc_open_symmetric_np2 agmpc_output_cheat.cpp 2 DEFS CHEAT_NP=2 ${_cnc} EMP_AG_TEST_CNC_FLIP_OPEN EMP_AG_OPEN_CHECK_SYMMETRIC PASS_RE "cut-and-choose: opened values")
add_np_variant(agmpc_cheat_cnc_open_pairwise_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_FLIP_OPEN EMP_AG_OPEN_CHECK_PAIRWISE PASS_RE "cut-and-choose: MAC tag mismatch")
add_np_variant(agmpc_cheat_cnc_product_pairwise_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_FLIP_PRODUCT EMP_AG_OPEN_CHECK_PAIRWISE PASS_RE "cut-and-choose")
add_np_variant(agmpc_cheat_cnc_residual_pairwise_np3 agmpc_output_cheat.cpp 3 DEFS CHEAT_NP=3 ${_cnc} EMP_AG_TEST_CNC_FLIP_RESIDUAL EMP_AG_OPEN_CHECK_PAIRWISE PASS_RE "cut-and-choose: MAC tag mismatch")

# Circuit mode (Computation, ../agmpc_computation.cpp). FLIP_OUTPUT_SHARE: the last party
# flips its share of the first output position, keeping its MACs; the recipient's MAC check
# aborts, under KRRW after the output check and under WRK before evaluation.
# FLIP_DELIVERED_LAMBDA: P1 hands garbler 2 a flipped masked value; garbler 2's label check
# aborts. FLIP_INPUT_LAMBDA: an owner equivocates a masked input; the echo aborts.
foreach(_np 2 3)
    add_np_variant(agmpc_computation_flip_share_np${_np} ../agmpc_computation.cpp ${_np}
                   DEFS COMP_NP=${_np} EMP_AG_TEST_FLIP_OUTPUT_SHARE PASS_RE "share-MAC hash mismatch")
    add_np_variant(agmpc_computation_flip_share_wrk_np${_np} ../agmpc_computation.cpp ${_np}
                   DEFS COMP_NP=${_np} EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_OUTPUT_SHARE
                   PASS_RE "share-MAC hash mismatch")
    add_np_variant(agmpc_computation_flip_handoff_np${_np} ../agmpc_computation.cpp ${_np}
                   DEFS COMP_NP=${_np} EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_DELIVERED_LAMBDA
                   PASS_RE "WRK: P1's output masks do not match its labels")
endforeach()
add_np_variant(agmpc_computation_equiv_np3 ../agmpc_computation.cpp 3
               DEFS COMP_NP=3 EMP_AG_TEST_FLIP_INPUT_LAMBDA PASS_RE "input Lambda equivocation")
add_np_variant(agmpc_computation_equiv_wrk_np3 ../agmpc_computation.cpp 3
               DEFS COMP_NP=3 EMP_AG_GARBLE_AUTH=WRK EMP_AG_TEST_FLIP_INPUT_LAMBDA
               PASS_RE "input Lambda equivocation")
