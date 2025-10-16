cmake_minimum_required(VERSION 3.10)
project(pinpam C)
set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED True)
add_library(pinpam SHARED src/lib.c include/lib.h)
set_property(TARGET pinpam PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(pinpam PUBLIC include)
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
add_custom_target(
  run_pamtester
  COMMAND pamtester ./service.conf root authenticate
  WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
  COMMENT "Running pamtester to test PAM module"
  VERBATIM
)
include_directories(${PAM_INCLUDE_DIRS})
target_link_libraries(pinpam ${PAM_LIBRARIES})
include_directories(${TSS2-ESYS_INCLUDE_DIRS})
target_link_libraries(pinpam ${TSS2-ESYS_LIBRARIES})
include_directories(${TSS2-DEVICE_INCLUDE_DIRS})
target_link_libraries(pinpam ${TSS2-DEVICE_LIBRARIES})