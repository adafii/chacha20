cmake_minimum_required(VERSION 3.28)
project("ChaCha20" CXX)

option(TESTS "Enable tests" ON)

set(src_dir src)
set(tests_dir tests)

# Library

add_library(chacha20 STATIC ${src_dir}/chacha20.cpp)
target_include_directories(chacha20 PRIVATE src)

target_compile_features(chacha20 PRIVATE cxx_std_23)
target_compile_options(chacha20 PRIVATE $<$<CONFIG:Debug>:-Wall -Wextra -Wpedantic -Wconversion -fsanitize=address -fsanitize=undefined>)
target_compile_options(chacha20 PRIVATE $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-Wall -Wextra -Wpedantic -Wconversion -flto>)
target_link_options(chacha20 PRIVATE $<$<CONFIG:Debug>:-fsanitize=address -fsanitize=undefined>)
target_link_options(chacha20 PRIVATE $<$<OR:$<CONFIG:Release>,$<CONFIG:MinSizeRel>>:-flto>)

# Tests

if(TESTS)
    include(FetchContent)
    
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG        e39786088138f2749d64e9e90e0f9902daa77c40 # 1.15.0
        GIT_PROGRESS ON
    )
    
    FetchContent_MakeAvailable(googletest)
    
    enable_testing()
    
    add_executable(chacha20_test ${tests_dir}/chacha20_test.cpp)
    target_include_directories(chacha20_test PRIVATE ${src_dir})
    target_link_libraries(chacha20_test PRIVATE GTest::gtest_main chacha20)
    
    target_compile_features(chacha20_test PRIVATE cxx_std_23)
    
    include(GoogleTest)
    gtest_discover_tests(chacha20_test)
endif()
