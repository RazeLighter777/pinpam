cmake_minimum_required(VERSION 3.10)
project(pinpam C)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED True)

# Find required packages
find_package(PkgConfig REQUIRED)
pkg_check_modules(PAM REQUIRED pam)
if (NOT PAM_FOUND)
  message(FATAL_ERROR "PAM library not found")
endif()
pkg_check_modules(TSS2-ESYS REQUIRED tss2-esys)
if (NOT TSS2-ESYS_FOUND)
  message(FATAL_ERROR "TSS2-ESYS library not found")
endif()
pkg_check_modules(TSS2-DEVICE REQUIRED tss2-tcti-device)
if (NOT TSS2-DEVICE_FOUND)
  message(FATAL_ERROR "TSS2-DEVICE library not found")
endif()
pkg_check_modules(OPENSSL REQUIRED openssl)
if (NOT OPENSSL_FOUND)
  message(FATAL_ERROR "OpenSSL library not found")
endif()

# Common TPM library (static)
add_library(tpm_common STATIC src/tpm_common.c include/tpm_common.h)
set_property(TARGET tpm_common PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(tpm_common PUBLIC include)
target_include_directories(tpm_common PUBLIC ${OPENSSL_INCLUDE_DIRS})
target_include_directories(tpm_common PUBLIC ${TSS2-ESYS_INCLUDE_DIRS})
target_include_directories(tpm_common PUBLIC ${TSS2-DEVICE_INCLUDE_DIRS})
target_link_libraries(tpm_common ${OPENSSL_LIBRARIES})
target_link_libraries(tpm_common ${TSS2-ESYS_LIBRARIES})
target_link_libraries(tpm_common ${TSS2-DEVICE_LIBRARIES})

# PAM module (shared library)
add_library(pinpam SHARED src/lib.c include/lib.h)
set_property(TARGET pinpam PROPERTY POSITION_INDEPENDENT_CODE ON)
target_include_directories(pinpam PUBLIC include)
target_include_directories(pinpam PUBLIC ${PAM_INCLUDE_DIRS})
target_link_libraries(pinpam tpm_common)
target_link_libraries(pinpam ${PAM_LIBRARIES})

# PIN setup utility (executable)
add_executable(setup_pin src/setup_pin.c)
target_include_directories(setup_pin PUBLIC include)
target_link_libraries(setup_pin tpm_common)


# Custom target to run pamtester
# Usage: cmake --build . --target run_pamtester -- USERNAME=<username>
# Example: cmake --build . --target run_pamtester -- USERNAME=alice
set(PAM_TEST_USERNAME "justin" CACHE STRING "Username for pamtester")
add_custom_target(
  run_pamtester
  COMMAND pamtester ./service.conf ${PAM_TEST_USERNAME} authenticate
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "Running pamtester to test PAM module with user ${PAM_TEST_USERNAME}"
  VERBATIM
)
