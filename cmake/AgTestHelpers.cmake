# Shared build/run helpers used by test/ (functional), test/adversarial/ (fault-injection),
# and example/. Included once at the top level before those subdirectories, so the functions
# are visible in all of them. The localhost run launchers live at the repo root and are
# resolved through ${PROJECT_SOURCE_DIR}, so the helpers work from any subdirectory depth.

# Strict-memaccess guard: a memcpy/memset over a non-trivial type is an error (per compiler).
function(_apply_strict_memaccess _tgt)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
        target_compile_options(${_tgt} PRIVATE -Werror=nontrivial-memaccess)
    elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
        target_compile_options(${_tgt} PRIVATE -Werror=class-memaccess)
    endif()
endfunction()

# add_np_variant(<name> <source> <nP> [DEFS <d>...] [PASS_RE <regex>])
# One parametrized-party test: build test_<name> from <source> with DEFS as PRIVATE compile
# definitions, run it as an <nP>-party job via the runN launcher at the repo root, and (if
# PASS_RE is given) gate on that abort-message regex. Used by the golden/linear matrices in
# test/ and the fault-injection variants in test/adversarial/.
function(add_np_variant _name _src _np)
    cmake_parse_arguments(NV "" "PASS_RE" "DEFS" ${ARGN})
    add_executable(test_${_name} ${_src})
    target_link_libraries(test_${_name} PRIVATE emp-ag::emp-ag)
    if(NV_DEFS)
        target_compile_definitions(test_${_name} PRIVATE ${NV_DEFS})
    endif()
    _apply_strict_memaccess(test_${_name})
    add_test(NAME ${_name}
             COMMAND ${PROJECT_SOURCE_DIR}/runN ${_np} $<TARGET_FILE:test_${_name}>
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    if(NV_PASS_RE)
        set_tests_properties(${_name} PROPERTIES PASS_REGULAR_EXPRESSION "${NV_PASS_RE}")
    endif()
endfunction()
