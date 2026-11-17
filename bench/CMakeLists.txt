# Throughput benchmarks. Opt-in (-DEMP_AG_BUILD_BENCHES=ON) and NOT run by ctest —
# a benchmark's runtime and its resource appetite have no place in a correctness gate.
# Binaries land in the build's bin/ like the tests.
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Both benches are generic in nP via $EMP_N; see each header comment for the
# workload and the environment knobs.
#   bench_100m — serial sha256 chain (each iteration feeds the next), default nP=3
#   bench_aes  — data-parallel AES-128 batch (independent blocks), default nP=2
find_package(OpenSSL REQUIRED)
foreach(_b bench_100m bench_aes)
    add_executable(${_b} ${_b}.cpp)
    target_link_libraries(${_b} PRIVATE emp-ag::emp-ag OpenSSL::Crypto)
    _apply_strict_memaccess(${_b})
endforeach()
