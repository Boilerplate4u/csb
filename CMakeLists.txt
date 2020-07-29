cmake_minimum_required (VERSION 3.10)

project (csb)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED True)

add_compile_options(-Wall -Wextra -Werror)

include(CTest)

# Build Types
# - Debug
# - Release
# - asan
# - lsan
# - ubsan
set(build_types_list Release Debug asan lsan ubsan)
IF( NOT CMAKE_BUILD_TYPE )
   SET( CMAKE_BUILD_TYPE Debug )
ENDIF()

set(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE}
    CACHE STRING "Choose the type of build, options are: Debug Release asan lsan ubsan"
    FORCE)

if(NOT (${CMAKE_BUILD_TYPE} IN_LIST build_types_list))
  message(FATAL_ERROR "Unsupported CMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}." )
endif()

if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    
    IF( NOT DEFINED ENABLE_DEBUG_MSG )
        add_definitions(-DCOMMON_DEBUG=1 -DENABLE_DEBUG_MSG=1)
    else()
        if(ENABLE_DEBUG_MSG STREQUAL "1")
            add_definitions(-DCOMMON_DEBUG=1 -DENABLE_DEBUG_MSG=1)
        endif()
    ENDIF()
else()
    IF( ENABLE_DEBUG_MSG )
        add_definitions(-DCOMMON_DEBUG=1 -DENABLE_DEBUG_MSG=1)
    ENDIF()
endif(CMAKE_BUILD_TYPE STREQUAL "Debug")

# AddressSanitize
# Sanitizer usage: cmake -DCMAKE_BUILD_TYPE=asan
set(CMAKE_C_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during AddressSanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_ASAN
    "-fsanitize=address -fno-optimize-sibling-calls -fsanitize-address-use-after-scope -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C++ compiler during AddressSanitizer builds."
    FORCE)

# LeakSanitizer
set(CMAKE_C_FLAGS_LSAN
    "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C compiler during LeakSanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_LSAN
    "-fsanitize=leak -fno-omit-frame-pointer -g -O1"
    CACHE STRING "Flags used by the C++ compiler during LeakSanitizer builds."
    FORCE)

# MemorySanitizer
set(CMAKE_C_FLAGS_MSAN
    "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2"
    CACHE STRING "Flags used by the C compiler during MemorySanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_MSAN
    "-fsanitize=memory -fno-optimize-sibling-calls -fsanitize-memory-track-origins=2 -fno-omit-frame-pointer -g -O2"
    CACHE STRING "Flags used by the C++ compiler during MemorySanitizer builds."
    FORCE)

# UndefinedBehaviour
set(CMAKE_C_FLAGS_UBSAN
    "-fsanitize=undefined"
    CACHE STRING "Flags used by the C compiler during UndefinedBehaviourSanitizer builds."
    FORCE)
set(CMAKE_CXX_FLAGS_UBSAN
    "-fsanitize=undefined"
    CACHE STRING "Flags used by the C++ compiler during UndefinedBehaviourSanitizer builds."
    FORCE)

# Valgrind usage: ctest -T memcheck
find_program(MEMORYCHECK_COMMAND NAMES valgrind)
if(MEMORYCHECK_COMMAND STREQUAL "MEMORYCHECK_COMMAND-NOTFOUND")
    message(WARNING "Valgrind not found, corresponding checks won't be available.")
endif()
set(MEMORYCHECK_COMMAND_OPTIONS "--trace-children=yes --leak-check=full")

add_executable(csb csb.c)

include_directories(PUBLIC ${CMAKE_SOURCE_DIR}/tinycbor/src)

target_include_directories(${PROJECT_NAME} PUBLIC "${PROJECT_SOURCE_DIR}")

find_package(OpenSSL REQUIRED)

target_link_libraries(${PROJECT_NAME} dl) 
target_link_libraries(${PROJECT_NAME} ssl) 
target_link_libraries(${PROJECT_NAME} crypto)
target_link_libraries(${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/tinycbor/lib/libtinycbor.so)

add_custom_target(libtinycbor make
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tinycbor)

add_custom_target(cbordump 
    cp ${CMAKE_SOURCE_DIR}/tinycbor/bin/cbordump ${CMAKE_CURRENT_BINARY_DIR}
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}/tinycbor)
    
add_dependencies(csb libtinycbor)
add_dependencies(cbordump libtinycbor)
add_dependencies(csb cbordump)

add_test(csb_only_sign ${PROJECT_NAME} )
add_test(csb_sign_verify ${PROJECT_NAME} -v)
add_test(csb_sign_verify_one ${PROJECT_NAME} -v -N 1)
#the following test is allowed only after one that creates own key
add_test(csb_1000 ${PROJECT_NAME} -v -N 1000 -k prime256v1.key)


