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

# add_np_variant(<name> <source> <nP> [DEFS <d>...] [HOOKS <h>...] [ARGS <a>...]
#                [PASS_RE <regex>])
# One parametrized-party test <name>: run <source>'s executable as an <nP>-party job via the
# runN launcher at the repo root and, if PASS_RE is given, gate on that regex (an abort
# message, for a test that must abort).
#   DEFS   the executable's PRIVATE compile definitions. Every variant with the same source
#          and DEFS shares one executable: test_<source name>, or test_<source name>_np<nP>
#          when it has DEFS.
#   HOOKS  the test hooks (emp-ag/backend/common/test_hooks.h) the run turns on, through the
#          EMP_AG_TEST_HOOKS environment variable. Without a hooks build
#          (EMP_AG_TEST_HOOKS=OFF) a variant with hooks is not added.
#   ARGS   arguments every party gets after its party id.
# Used by the matrices in test/ and the fault-injection variants in test/adversarial/.
function(add_np_variant _name _src _np)
    cmake_parse_arguments(NV "" "PASS_RE" "DEFS;HOOKS;ARGS" ${ARGN})
    if(NV_HOOKS AND NOT EMP_AG_TEST_HOOKS)
        return()
    endif()
    get_filename_component(_path "${_src}" ABSOLUTE)
    set(_defs ${NV_DEFS})
    list(SORT _defs)
    string(SHA1 _key "${_path}|${_defs}")
    get_property(_exe GLOBAL PROPERTY "AG_NP_VARIANT_EXE_${_key}")
    if(NOT _exe)
        get_filename_component(_stem "${_src}" NAME_WE)
        if(NV_DEFS)
            set(_exe test_${_stem}_np${_np})
        else()
            set(_exe test_${_stem})
        endif()
        if(TARGET ${_exe})
            message(FATAL_ERROR "add_np_variant(${_name}): ${_exe} is already built with other DEFS")
        endif()
        add_executable(${_exe} ${_src})
        target_link_libraries(${_exe} PRIVATE emp-ag::emp-ag)
        if(NV_DEFS)
            target_compile_definitions(${_exe} PRIVATE ${NV_DEFS})
        endif()
        _apply_strict_memaccess(${_exe})
        set_property(GLOBAL PROPERTY "AG_NP_VARIANT_EXE_${_key}" ${_exe})
    endif()
    add_test(NAME ${_name}
             COMMAND ${PROJECT_SOURCE_DIR}/runN ${_np} $<TARGET_FILE:${_exe}> ${NV_ARGS}
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
    if(NV_HOOKS)
        string(REPLACE ";" "," _hooks "${NV_HOOKS}")
        set_tests_properties(${_name} PROPERTIES ENVIRONMENT "EMP_AG_TEST_HOOKS=${_hooks}")
    endif()
    if(NV_PASS_RE)
        set_tests_properties(${_name} PROPERTIES PASS_REGULAR_EXPRESSION "${NV_PASS_RE}")
    endif()
endfunction()
