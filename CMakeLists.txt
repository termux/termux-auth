cmake_minimum_required(VERSION 3.2)
project(termux-auth VERSION 1.3)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall")
include_directories(${PROJECT_SOURCE_DIR})

find_library(LIB_CRYPTO crypto)

add_library(termux-auth SHARED termux-auth.c)
target_link_libraries(termux-auth ${LIB_CRYPTO})
install(TARGETS termux-auth DESTINATION lib)
install(FILES ${PROJECT_SOURCE_DIR}/termux-auth.h DESTINATION include)

add_executable(passwd passwd.c)
target_link_libraries(passwd termux-auth)
install(TARGETS passwd DESTINATION bin)

add_executable(pwlogin pwlogin.c)
target_link_libraries(pwlogin termux-auth)
install(TARGETS pwlogin DESTINATION bin)

add_executable(testauth testauth.c)
target_link_libraries(testauth termux-auth)
