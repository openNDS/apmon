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
	src/lib/extra.c
	src/lib/pretty.c
	src/lib/logfile.c
	src/lib/factory_mac.c
)
target_include_directories(apmon PUBLIC src/lib)
set_property(TARGET apmon PROPERTY POSITION_INDEPENDENT_CODE ON)
target_link_libraries(apmon PUBLIC mbedcrypto m)

# Build identity (apmond package_version / build_commit). The OpenWrt Makefile passes both;
# a host build uses git describe / git rev-parse, else "dev" / a .build_commit file / "unknown".
if(NOT DEFINED APMOND_PACKAGE_VERSION)
	set(APMOND_PACKAGE_VERSION "")
endif()
if(APMOND_PACKAGE_VERSION STREQUAL "" AND EXISTS ${CMAKE_SOURCE_DIR}/.git)
	execute_process(COMMAND git describe --tags --always --dirty
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
			OUTPUT_VARIABLE APMOND_PACKAGE_VERSION
			OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
	if(APMOND_PACKAGE_VERSION STREQUAL "")
		set(APMOND_PACKAGE_VERSION "dev")
	endif()
endif()
# .build_commit holds "$Format:%h$"; git archive and GitHub/codeload tarballs replace it with the
# short commit (.gitattributes export-subst). In a plain checkout it is still literal: ask git.
if(NOT DEFINED APMOND_BUILD_COMMIT)
	set(APMOND_BUILD_COMMIT "")
endif()
if(APMOND_BUILD_COMMIT STREQUAL "" AND EXISTS ${CMAKE_SOURCE_DIR}/.build_commit)
	file(STRINGS ${CMAKE_SOURCE_DIR}/.build_commit APMOND_BUILD_COMMIT LIMIT_COUNT 1)
	if(APMOND_BUILD_COMMIT MATCHES "Format")
		set(APMOND_BUILD_COMMIT "")
	endif()
endif()
if(APMOND_BUILD_COMMIT STREQUAL "" AND EXISTS ${CMAKE_SOURCE_DIR}/.git)
	execute_process(COMMAND git rev-parse --short HEAD
			WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
			OUTPUT_VARIABLE APMOND_BUILD_COMMIT
			OUTPUT_STRIP_TRAILING_WHITESPACE ERROR_QUIET)
endif()
if(APMOND_BUILD_COMMIT STREQUAL "")
	set(APMOND_BUILD_COMMIT "unknown")
endif()
message(STATUS "apmond build ${APMOND_PACKAGE_VERSION} ${APMOND_BUILD_COMMIT}")

if(BUILD_DAEMON)
	add_executable(apmond
		src/apmond/main.c
		src/apmond/config.c
		src/apmond/sender.c
		src/apmond/collect.c
		src/apmond/collector.c
		src/apmond/vlan.c
		src/apmond/http_client.c
		src/apmond/log.c
		src/apmond/ula.c
		src/apmond/blocks.c
		src/apmond/cli.c
		src/apmond/identity.c
		src/apmond/privdrop.c
	)
	target_compile_definitions(apmond PRIVATE
		APMOND_PACKAGE_VERSION="${APMOND_PACKAGE_VERSION}"
		APMOND_BUILD_COMMIT="${APMOND_BUILD_COMMIT}")
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
