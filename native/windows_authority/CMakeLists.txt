cmake_minimum_required(VERSION 4.2)

project(FaultLoomWindowsAuthority VERSION 0.1.0 LANGUAGES CXX)

if(NOT WIN32 OR NOT MSVC)
  message(FATAL_ERROR "FaultLoom Windows Authority requires Windows and MSVC")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
  message(FATAL_ERROR "FaultLoom Windows Authority requires x64")
endif()

option(FAULTLOOM_STATIC_CRT "Use the static MSVC runtime" ON)
include(cmake/StaticRuntime.cmake)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
set(CMAKE_UNITY_BUILD OFF)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION OFF)

function(faultloom_harden target)
  target_compile_definitions(${target} PRIVATE UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX)
  target_compile_options(${target} PRIVATE /W4 /WX /permissive- /sdl /guard:cf)
  target_link_options(${target} PRIVATE /guard:cf)
endfunction()

add_executable(faultloom_broker
  src/broker/broker_main.cpp
  src/broker/broker_args.cpp
  src/broker/broker_ready.cpp
  src/broker/broker_runtime.cpp
  src/broker/broker_security.cpp
  src/broker/client_identity.cpp
  src/broker/reviewer_child.cpp
  src/broker/scm_query.cpp
  src/reviewer/reviewer_identity.cpp
  src/reviewer/reviewer_io.cpp
  src/reviewer/reviewer_security.cpp
  src/common/broker_contract.cpp
  src/common/policy.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
target_include_directories(faultloom_broker PRIVATE include src/broker src/reviewer)
target_link_libraries(faultloom_broker PRIVATE bcrypt advapi32 ntdll)
faultloom_harden(faultloom_broker)

add_executable(faultloom_broker_post_approval_fixture
  src/broker/broker_main.cpp
  src/broker/broker_args.cpp
  src/broker/broker_ready.cpp
  src/broker/broker_runtime.cpp
  src/broker/broker_security.cpp
  src/broker/client_identity.cpp
  src/broker/reviewer_child.cpp
  src/broker/scm_query.cpp
  src/reviewer/reviewer_identity.cpp
  src/reviewer/reviewer_io.cpp
  src/reviewer/reviewer_security.cpp
  src/common/broker_contract.cpp
  src/common/policy.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
add_dependencies(faultloom_broker_post_approval_fixture faultloom_reviewer)
target_include_directories(faultloom_broker_post_approval_fixture PRIVATE
  include src/broker src/reviewer)
target_link_libraries(faultloom_broker_post_approval_fixture PRIVATE bcrypt advapi32 ntdll)
target_compile_definitions(faultloom_broker_post_approval_fixture PRIVATE
  FAULTLOOM_TEST_POST_APPROVAL_STALL=1)
faultloom_harden(faultloom_broker_post_approval_fixture)

add_executable(faultloom_ctl
  src/ctl/ctl_main.cpp
  src/ctl/ctl_args.cpp
  src/ctl/ctl_local.cpp
  src/ctl/ctl_runtime.cpp
  src/reviewer/reviewer_identity.cpp
  src/reviewer/reviewer_io.cpp
  src/reviewer/reviewer_security.cpp
  src/common/broker_contract.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
target_include_directories(faultloom_ctl PRIVATE include src/ctl src/reviewer)
target_link_libraries(faultloom_ctl PRIVATE bcrypt advapi32)
target_compile_definitions(faultloom_ctl PRIVATE $<$<CONFIG:Debug>:FAULTLOOM_TEST_RAW=1>)
faultloom_harden(faultloom_ctl)

add_executable(faultloom_reviewer
  src/reviewer/reviewer_main.cpp
  src/reviewer/reviewer_args.cpp
  src/reviewer/reviewer_decision.cpp
  src/reviewer/reviewer_identity.cpp
  src/reviewer/reviewer_io.cpp
  src/reviewer/reviewer_ready.cpp
  src/reviewer/reviewer_security.cpp
  src/reviewer/reviewer_runtime.cpp
  src/reviewer/signer_bcrypt.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
  src/common/policy.cpp
)
target_include_directories(faultloom_reviewer PRIVATE include src/reviewer)
target_link_libraries(faultloom_reviewer PRIVATE bcrypt advapi32 ntdll)
faultloom_harden(faultloom_reviewer)

add_executable(faultloom_protocol_tests
  tests/protocol_tests.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
target_include_directories(faultloom_protocol_tests PRIVATE include)
target_link_libraries(faultloom_protocol_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_protocol_tests)

add_executable(faultloom_protocol_allocation_tests
  tests/protocol_allocation_tests.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
target_include_directories(faultloom_protocol_allocation_tests PRIVATE include)
target_link_libraries(faultloom_protocol_allocation_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_protocol_allocation_tests)

add_executable(faultloom_policy_tests
  tests/policy_tests.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
  src/common/policy.cpp
)
target_include_directories(faultloom_policy_tests PRIVATE include)
target_link_libraries(faultloom_policy_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_policy_tests)

add_executable(faultloom_reviewer_tests
  tests/reviewer_tests.cpp
  tests/fake_signer.cpp
  src/reviewer/reviewer_args.cpp
  src/reviewer/signer_bcrypt.cpp
)
target_include_directories(faultloom_reviewer_tests PRIVATE include tests src/reviewer)
target_link_libraries(faultloom_reviewer_tests PRIVATE bcrypt ntdll)
faultloom_harden(faultloom_reviewer_tests)

add_executable(faultloom_reviewer_process_tests
  tests/reviewer_process_tests.cpp
  tests/reviewer_process_fixture.cpp
  tests/reviewer_process_lifecycle.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
add_dependencies(faultloom_reviewer_process_tests faultloom_reviewer)
target_include_directories(faultloom_reviewer_process_tests PRIVATE include tests)
target_link_libraries(faultloom_reviewer_process_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_reviewer_process_tests)

add_executable(faultloom_reviewer_io_tests
  tests/reviewer_io_tests.cpp
  src/reviewer/reviewer_io.cpp
)
target_include_directories(faultloom_reviewer_io_tests PRIVATE include src/reviewer)
faultloom_harden(faultloom_reviewer_io_tests)

add_executable(faultloom_reviewer_decision_tests
  tests/reviewer_decision_tests.cpp
  tests/fake_signer.cpp
  tests/reviewer_process_fixture.cpp
  src/reviewer/reviewer_decision.cpp
  src/reviewer/reviewer_io.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
target_include_directories(faultloom_reviewer_decision_tests PRIVATE include tests src/reviewer)
target_link_libraries(faultloom_reviewer_decision_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_reviewer_decision_tests)

add_executable(faultloom_reviewer_ready_tests
  tests/reviewer_ready_tests.cpp
  src/reviewer/reviewer_ready.cpp
  src/reviewer/reviewer_io.cpp
)
target_include_directories(faultloom_reviewer_ready_tests PRIVATE include src/reviewer)
faultloom_harden(faultloom_reviewer_ready_tests)

add_executable(faultloom_broker_contract_tests
  tests/broker_contract_tests.cpp
  tests/reviewer_process_fixture.cpp
  src/reviewer/reviewer_decision.cpp
  src/reviewer/reviewer_io.cpp
  src/reviewer/signer_bcrypt.cpp
  src/broker/reviewer_child.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
  src/common/broker_contract.cpp
)
target_include_directories(faultloom_broker_contract_tests PRIVATE include tests src/reviewer src/broker)
target_link_libraries(faultloom_broker_contract_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_broker_contract_tests)

add_executable(faultloom_broker_scm_tests
  tests/broker_scm_tests.cpp
  src/broker/scm_query.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
target_include_directories(faultloom_broker_scm_tests PRIVATE include src/broker src/reviewer)
target_link_libraries(faultloom_broker_scm_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_broker_scm_tests)

add_executable(faultloom_broker_security_tests
  tests/broker_security_tests.cpp
  src/broker/broker_security.cpp
  src/reviewer/reviewer_identity.cpp
  src/reviewer/reviewer_security.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
target_include_directories(faultloom_broker_security_tests PRIVATE include src/broker src/reviewer)
target_link_libraries(faultloom_broker_security_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_broker_security_tests)

add_executable(faultloom_broker_identity_tests
  tests/broker_identity_tests.cpp
  src/broker/client_identity.cpp
)
target_include_directories(faultloom_broker_identity_tests PRIVATE include tests src/broker)
faultloom_harden(faultloom_broker_identity_tests)

add_executable(faultloom_integration_tests
  tests/integration_tests.cpp
  tests/integration_process.cpp
  tests/integration_oracle.cpp
  tests/integration_status.cpp
  tests/integration_scenarios.cpp
  tests/integration_death.cpp
  tests/integration_regressions.cpp
)
add_dependencies(faultloom_integration_tests
  faultloom_broker faultloom_ctl faultloom_reviewer
  faultloom_broker_process_tests faultloom_broker_invalid_signature_process_tests
  faultloom_broker_scm_tests faultloom_reviewer_process_tests
  faultloom_reviewer_ready_tests)
target_compile_definitions(faultloom_integration_tests PRIVATE
  FAULTLOOM_SOURCE_ROOT=L"${CMAKE_CURRENT_SOURCE_DIR}")
target_include_directories(faultloom_integration_tests PRIVATE tests)
target_link_libraries(faultloom_integration_tests PRIVATE advapi32 psapi)
faultloom_harden(faultloom_integration_tests)

add_executable(faultloom_broker_process_tests
  tests/broker_process_tests.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
add_dependencies(faultloom_broker_process_tests faultloom_broker faultloom_ctl faultloom_reviewer)
target_include_directories(faultloom_broker_process_tests PRIVATE include tests)
target_link_libraries(faultloom_broker_process_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_broker_process_tests)

add_executable(faultloom_broker_post_approval_process_tests
  tests/broker_post_approval_process_tests.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
add_dependencies(faultloom_broker_post_approval_process_tests
  faultloom_broker_post_approval_fixture faultloom_ctl faultloom_reviewer)
target_include_directories(faultloom_broker_post_approval_process_tests PRIVATE include tests)
target_link_libraries(faultloom_broker_post_approval_process_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_broker_post_approval_process_tests)

add_executable(faultloom_reviewer_corrupt
  src/reviewer/reviewer_main.cpp
  src/reviewer/reviewer_args.cpp
  src/reviewer/reviewer_decision.cpp
  src/reviewer/reviewer_identity.cpp
  src/reviewer/reviewer_io.cpp
  src/reviewer/reviewer_ready.cpp
  src/reviewer/reviewer_security.cpp
  src/reviewer/reviewer_runtime.cpp
  src/reviewer/signer_bcrypt.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
  src/common/policy.cpp
)
target_include_directories(faultloom_reviewer_corrupt PRIVATE include src/reviewer)
target_link_libraries(faultloom_reviewer_corrupt PRIVATE bcrypt advapi32 ntdll)
target_compile_definitions(faultloom_reviewer_corrupt PRIVATE FAULTLOOM_TEST_CORRUPT_SIGNATURE=1)
faultloom_harden(faultloom_reviewer_corrupt)

add_executable(faultloom_broker_invalid_signature_fixture
  src/broker/broker_main.cpp
  src/broker/broker_args.cpp
  src/broker/broker_ready.cpp
  src/broker/broker_runtime.cpp
  src/broker/broker_security.cpp
  src/broker/client_identity.cpp
  src/broker/reviewer_child.cpp
  tests/scm_query_forbidden.cpp
  src/reviewer/reviewer_identity.cpp
  src/reviewer/reviewer_io.cpp
  src/reviewer/reviewer_security.cpp
  src/common/broker_contract.cpp
  src/common/policy.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
add_dependencies(faultloom_broker_invalid_signature_fixture faultloom_reviewer_corrupt)
target_include_directories(faultloom_broker_invalid_signature_fixture PRIVATE
  include tests src/broker src/reviewer)
target_link_libraries(faultloom_broker_invalid_signature_fixture PRIVATE bcrypt advapi32 ntdll)
target_compile_definitions(faultloom_broker_invalid_signature_fixture PRIVATE
  FAULTLOOM_TEST_CORRUPT_REVIEWER=1)
faultloom_harden(faultloom_broker_invalid_signature_fixture)

add_executable(faultloom_broker_invalid_signature_process_tests
  tests/broker_invalid_signature_process_tests.cpp
  src/common/protocol.cpp
  src/common/protocol_hash.cpp
)
add_dependencies(faultloom_broker_invalid_signature_process_tests
  faultloom_broker_invalid_signature_fixture)
target_include_directories(faultloom_broker_invalid_signature_process_tests PRIVATE include tests)
target_link_libraries(faultloom_broker_invalid_signature_process_tests PRIVATE bcrypt advapi32)
faultloom_harden(faultloom_broker_invalid_signature_process_tests)

enable_testing()
add_test(NAME protocol_codec COMMAND faultloom_protocol_tests)
set_tests_properties(protocol_codec PROPERTIES LABELS "protocol" TIMEOUT 10)
add_test(NAME protocol_allocation_bounds COMMAND faultloom_protocol_allocation_tests)
set_tests_properties(protocol_allocation_bounds PROPERTIES LABELS "protocol" TIMEOUT 10)
add_test(NAME policy_parser COMMAND faultloom_policy_tests)
set_tests_properties(policy_parser PROPERTIES LABELS "policy" TIMEOUT 10)
add_test(NAME reviewer_boundary COMMAND faultloom_reviewer_tests)
set_tests_properties(reviewer_boundary PROPERTIES LABELS "reviewer" TIMEOUT 10)
add_test(NAME reviewer_process_boundary COMMAND faultloom_reviewer_process_tests)
set_tests_properties(reviewer_process_boundary PROPERTIES LABELS "reviewer" TIMEOUT 45)
add_test(NAME reviewer_io_boundary COMMAND faultloom_reviewer_io_tests)
set_tests_properties(reviewer_io_boundary PROPERTIES LABELS "reviewer" TIMEOUT 10)
add_test(NAME reviewer_decision_boundary COMMAND faultloom_reviewer_decision_tests)
set_tests_properties(reviewer_decision_boundary PROPERTIES LABELS "reviewer" TIMEOUT 10)
add_test(NAME reviewer_ready_boundary COMMAND faultloom_reviewer_ready_tests)
set_tests_properties(reviewer_ready_boundary PROPERTIES LABELS "reviewer" TIMEOUT 10)
add_test(NAME broker_contract COMMAND faultloom_broker_contract_tests)
set_tests_properties(broker_contract PROPERTIES LABELS "broker" TIMEOUT 10)
add_test(NAME broker_scm_contract COMMAND faultloom_broker_scm_tests)
set_tests_properties(broker_scm_contract PROPERTIES LABELS "broker" TIMEOUT 10)
add_test(NAME broker_security_contract COMMAND faultloom_broker_security_tests)
set_tests_properties(broker_security_contract PROPERTIES LABELS "broker" TIMEOUT 10)
add_test(NAME broker_identity_contract COMMAND faultloom_broker_identity_tests)
set_tests_properties(broker_identity_contract PROPERTIES LABELS "broker" TIMEOUT 10)
add_test(NAME integration_scaffold COMMAND faultloom_integration_tests)
set_tests_properties(integration_scaffold PROPERTIES LABELS "integration" TIMEOUT 35)
add_test(NAME broker_process_boundary COMMAND faultloom_broker_process_tests)
set_tests_properties(broker_process_boundary PROPERTIES LABELS "broker" TIMEOUT 30)
add_test(NAME broker_post_approval_process_boundary
         COMMAND faultloom_broker_post_approval_process_tests)
set_tests_properties(broker_post_approval_process_boundary PROPERTIES LABELS "broker" TIMEOUT 20)
add_test(NAME broker_invalid_signature_process_boundary
         COMMAND faultloom_broker_invalid_signature_process_tests)
set_tests_properties(broker_invalid_signature_process_boundary PROPERTIES LABELS "broker" TIMEOUT 15)

find_program(FAULTLOOM_POWERSHELL powershell.exe REQUIRED)
get_filename_component(FAULTLOOM_REPOSITORY_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
add_test(
  NAME capture_leaf_identity
  COMMAND "${FAULTLOOM_POWERSHELL}" -NoLogo -NoProfile -NonInteractive
          -ExecutionPolicy Bypass -File
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/capture_leaf_identity_tests.ps1"
          -RepositoryRoot "${FAULTLOOM_REPOSITORY_ROOT}"
)
set_tests_properties(capture_leaf_identity PROPERTIES LABELS "integration" TIMEOUT 10)
add_test(
  NAME root_creation_identity
  COMMAND "${FAULTLOOM_POWERSHELL}" -NoLogo -NoProfile -NonInteractive
          -ExecutionPolicy Bypass -File
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/root_creation_identity_tests.ps1"
          -RepositoryRoot "${FAULTLOOM_REPOSITORY_ROOT}"
)
set_tests_properties(root_creation_identity PROPERTIES LABELS "integration" TIMEOUT 60)
add_test(
  NAME package_contract
  COMMAND "${FAULTLOOM_POWERSHELL}" -NoLogo -NoProfile -NonInteractive
          -ExecutionPolicy Bypass -File
          "${CMAKE_CURRENT_SOURCE_DIR}/tests/package_tests.ps1"
          -RepositoryRoot "${FAULTLOOM_REPOSITORY_ROOT}"
          -BuildDir "${CMAKE_BINARY_DIR}"
)
set_tests_properties(package_contract PROPERTIES LABELS "package" TIMEOUT 180)
