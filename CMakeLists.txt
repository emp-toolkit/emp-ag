cmake_minimum_required(VERSION 3.25)   # emp-tool's floor
project(emp-ag VERSION 1.0.0 LANGUAGES CXX)

# emp-ag is authenticated garbling for n>=2 parties (AGMPCProtocol<nP> /
# AGMPCSession<nP>). The 2-party case is the nP==2 instantiation, special-cased only
# where the algebra collapses (the c_gamma equality fold, the streamlined 2-party
# leaky-AND, the one-garbler garble path). There is no separate 2pc backend or
# session: 2-party is AGMPCSession<2>.
#
# Header-only: the protocol lives in headers; the compiled OT / crypto bodies come
# from emp-ot and emp-tool. Include root is the repo root, so consumers write
# `#include "emp-ag/emp-ag.h"`.

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "In-source builds are not allowed; use a separate build dir.")
endif()

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
    set_property(CACHE CMAKE_BUILD_TYPE PROPERTY STRINGS
        Debug Release RelWithDebInfo MinSizeRel)
endif()

include(GNUInstallDirs)
include(CMakePackageConfigHelpers)
include(CTest)

# ---------------------------------------------------------------------
# Options
# ---------------------------------------------------------------------
option(EMP_AG_BUILD_TESTS    "Build emp-ag tests" ${PROJECT_IS_TOP_LEVEL})
option(EMP_AG_BUILD_BENCHES  "Build emp-ag benchmarks (opt-in; not run by ctest)" OFF)
option(EMP_AG_BUILD_EXAMPLES "Build emp-ag examples" ${PROJECT_IS_TOP_LEVEL})
option(EMP_AG_DEBUG         "Enable internal MAC / correctness checks" OFF)
option(EMP_AG_PROFILE       "Enable protocol timing / communication profiling" OFF)
option(EMP_AG_INSTALL
       "Generate install / find_package(emp-ag) export rules" ${PROJECT_IS_TOP_LEVEL})
set(EMP_AG_OT_BACKEND "SoftSpoken" CACHE STRING
    "COT backend for aShare generation: SoftSpoken, IKNP, or Ferret")
set_property(CACHE EMP_AG_OT_BACKEND PROPERTY STRINGS SoftSpoken IKNP Ferret)
set(EMP_AG_SOFTSPOKEN_K "8" CACHE STRING
    "SoftSpoken k parameter when EMP_AG_OT_BACKEND=SoftSpoken (8 = fewest COT bytes; smaller k trades COT bytes for less compute)")
set_property(CACHE EMP_AG_SOFTSPOKEN_K PROPERTY STRINGS 2 4 8)

# ---------------------------------------------------------------------
# Dependencies
# ---------------------------------------------------------------------
# Local-dev tip: point at sibling build trees with
#   -Demp-tool_DIR=/path/to/emp-tool/build  -Demp-ot_DIR=/path/to/emp-ot/build
find_package(emp-tool 1.0 REQUIRED)
find_package(emp-ot   1.0 REQUIRED)

# ---------------------------------------------------------------------
# Library target (header-only)
# ---------------------------------------------------------------------
add_library(emp-ag INTERFACE)
add_library(emp-ag::emp-ag ALIAS emp-ag)

target_compile_features(emp-ag INTERFACE cxx_std_20)

# Repo root on the include path so `#include "emp-ag/..."` resolves (the include root
# is the emp-ag/ dir beneath it).
target_include_directories(emp-ag INTERFACE
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
    $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

target_link_libraries(emp-ag INTERFACE emp-tool::emp-tool emp-ot::emp-ot)

if(EMP_AG_OT_BACKEND STREQUAL "IKNP")
    target_compile_definitions(emp-ag INTERFACE EMP_AG_OT_BACKEND=0)
elseif(EMP_AG_OT_BACKEND STREQUAL "SoftSpoken")
    target_compile_definitions(emp-ag INTERFACE
        EMP_AG_OT_BACKEND=1 EMP_AG_SOFTSPOKEN_K=${EMP_AG_SOFTSPOKEN_K})
elseif(EMP_AG_OT_BACKEND STREQUAL "Ferret")
    target_compile_definitions(emp-ag INTERFACE EMP_AG_OT_BACKEND=2)
else()
    message(FATAL_ERROR "EMP_AG_OT_BACKEND must be one of: SoftSpoken, IKNP, Ferret")
endif()

if(EMP_AG_DEBUG)
    target_compile_definitions(emp-ag INTERFACE EMP_AG_DEBUG_CHECKS)
endif()
if(EMP_AG_PROFILE)
    target_compile_definitions(emp-ag INTERFACE AG_PROFILE)
endif()

# ---------------------------------------------------------------------
# Install / export — find_package(emp-ag)
# ---------------------------------------------------------------------
set(_cmake_install_dir ${CMAKE_INSTALL_LIBDIR}/cmake/emp-ag)
configure_package_config_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/cmake/emp-ag-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/emp-ag-config.cmake
    INSTALL_DESTINATION ${_cmake_install_dir})
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/emp-ag-config-version.cmake
    VERSION ${PROJECT_VERSION} COMPATIBILITY SameMajorVersion)

if(EMP_AG_INSTALL)
    install(TARGETS emp-ag EXPORT emp-agTargets)
    install(DIRECTORY emp-ag
        DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
        FILES_MATCHING
        PATTERN "Testing" EXCLUDE      # stray CTest scratch, never a header dir
        PATTERN "*.h")
    install(EXPORT emp-agTargets
        NAMESPACE emp-ag:: DESTINATION ${_cmake_install_dir}
        FILE emp-agTargets.cmake)
    install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/emp-ag-config.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/emp-ag-config-version.cmake
        DESTINATION ${_cmake_install_dir})
endif()

# Build-tree export so siblings can consume without `make install`.
export(TARGETS emp-ag NAMESPACE emp-ag::
       FILE ${CMAKE_CURRENT_BINARY_DIR}/emp-agTargets.cmake)

# ---------------------------------------------------------------------
# Tests, benchmarks, examples
# ---------------------------------------------------------------------
if(EMP_AG_BUILD_TESTS OR EMP_AG_BUILD_BENCHES OR EMP_AG_BUILD_EXAMPLES)
    include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/AgTestHelpers.cmake)  # shared build/run helpers
    if(EMP_AG_BUILD_TESTS)
        add_subdirectory(test)                 # correctness tests (+ test/adversarial fault injection)
    endif()
    if(EMP_AG_BUILD_BENCHES)
        add_subdirectory(bench)                # throughput benchmarks (not run by ctest)
    endif()
    if(EMP_AG_BUILD_EXAMPLES)
        add_subdirectory(example)              # README usage example (smoke-run by ctest)
    endif()
endif()
