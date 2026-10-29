cmake_minimum_required(VERSION 3.13)
project(apmon C)

option(BUILD_DAEMON "Build the apmond daemon (needs libubox, libubus, libuci, libmicrohttpd)" ON)
option(BUILD_TESTS "Build the host unit tests" OFF)
set(CRYPTO_BACKEND "mbedtls" CACHE STRING "Crypto backend: mbedtls (openssl, wolfssl later)")

set(CMAKE_C_STANDARD 99)
add_compile_options(-Wall -Wextra -Werror -D_GNU_SOURCE)

if(NOT CRYPTO_BACKEND STREQUAL "mbedtls")
	message(FATAL_ERROR "Only CRYPTO_BACKEND=mbedtls is implemented so far")
endif()

add_library(apmon STATIC
	src/lib/crypto_mbedtls.c
	src/lib/kdf.c
	src/lib/envelope.c
	src/lib/replay.c
	src/lib/util.c
	src/lib/json.c
)
target_include_directories(apmon PUBLIC src/lib)
set_property(TARGET apmon PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(apmon PUBLIC mbedcrypto m)

if(BUILD_DAEMON)
	add_executable(apmond
		src/apmond/main.c
		src/apmond/config.c
		src/apmond/sender.c
		src/apmond/collect.c
		src/apmond/collector.c
		src/apmond/http_client.c
	)
	target_link_libraries(apmond apmon ubox ubus uci blobmsg_json microhttpd)
	install(TARGETS apmond RUNTIME DESTINATION sbin)
endif()

if(BUILD_TESTS)
	enable_testing()
	add_executable(test_apmon tests/test_apmon.c)
	target_include_directories(test_apmon PRIVATE tests)
	target_link_libraries(test_apmon apmon)
	add_test(NAME libapmon COMMAND test_apmon)
endif()
