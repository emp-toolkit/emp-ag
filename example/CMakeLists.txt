# Usage examples, built by default (EMP_AG_BUILD_EXAMPLES) and each smoke-run by
# ctest as a 3-party localhost job, so they cannot drift from the library API.
# Binaries land in the build's bin/ like the tests.
#   add   — the README snippet: two owned inputs, reveal the sum to party 1
#   aes   — AES-128 with split ownership (pt @ party 1, key @ party 2), checked
#           against the FIPS-197 known answer
#   modes — the three circuit-execution modes (direct / body / compiled) plus
#           run_compose chaining, all checked against cleartext
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

foreach(_ex add aes modes)
    add_executable(example_${_ex} ${_ex}.cpp)
    target_link_libraries(example_${_ex} PRIVATE emp-ag::emp-ag)
    _apply_strict_memaccess(example_${_ex})
    add_test(NAME example_${_ex}
             COMMAND ${PROJECT_SOURCE_DIR}/runN 3 $<TARGET_FILE:example_${_ex}>
             WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endforeach()
