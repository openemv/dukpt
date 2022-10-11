##############################################################################
# Copyright (c) 2021, 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

# Check whether compiler supports __builtin_popcount()
include(CheckCSourceCompiles)
check_c_source_compiles("int main(void) { return __builtin_popcount(42); }" HAS_BUILTIN_POPCOUNT)

# Check for headers that provide ntohs/htons and friends
include(CheckIncludeFile)
CHECK_INCLUDE_FILE(
	arpa/inet.h
	HAVE_ARPA_INET_H
)
CHECK_INCLUDE_FILE(
	winsock.h
	HAVE_WINSOCK_H
)
if(NOT HAVE_ARPA_INET_H AND NOT HAVE_WINSOCK_H)
	message(FATAL_ERROR "Failed to find either arpa/inet.h or winsock.h")
endif()

# Build DUKPT tool by default
option(BUILD_DUKPT_TOOL "Build dukpt-tool" ON)

# Check for argp or allow the FETCH_ARGP option to download and build a local
# copy of libargp for monolithic builds on platforms without package managers
# like MacOS and Windows.
option(FETCH_ARGP "Download and build libargp")
if(FETCH_ARGP)
	set(ARGP_OSX_ARCHITECTURES ${CMAKE_OSX_ARCHITECTURES})
	include(FetchLibArgp)
else()
	find_package(argp)
endif()
if(NOT argp_FOUND)
	if(BUILD_DUKPT_TOOL)
		message(FATAL_ERROR "Could NOT find argp. Enable FETCH_ARGP to download and build libargp. This is required to build dukpt-tool")
	endif()
endif()

# Check for tr31 but don't be verbose if it cannot be found
# The DUKPT_CONFIG_PACKAGE_DEPENDENCIES variable is set for the parent scope to
# facilitate the generation of CMake package configuration files.
# The DUKPT_PKGCONFIG_REQ_PRIV and DUKPT_PKGCONFIG_LIBS_PRIV variables are
# set for the parent scope to facilitate the generation of pkgconfig files.
set(TR31_MIN_VERSION 0.4.3)
find_package(tr31 ${TR31_MIN_VERSION} QUIET)
if(tr31_FOUND)
	find_package(tr31 ${TR31_MIN_VERSION} REQUIRED)
	string(APPEND DUKPT_CONFIG_PACKAGE_DEPENDENCIES "find_dependency(tr31 ${TR31_MIN_VERSION})\n")
	set(DUKPT_CONFIG_PACKAGE_DEPENDENCIES ${DUKPT_CONFIG_PACKAGE_DEPENDENCIES} PARENT_SCOPE)
	string(APPEND DUKPT_PKGCONFIG_REQ_PRIV "libtr31 >= ${TR31_MIN_VERSION}" PARENT_SCOPE)
	string(APPEND DUKPT_PKGCONFIG_LIBS_PRIV "-ltr31" PARENT_SCOPE)
else()
	message(STATUS "Could NOT find tr31")
endif()

include(GNUInstallDirs) # Provides CMAKE_INSTALL_* variables and good defaults for install()

# Generate config file for internal use only
# This file should NOT be installed or used by an installed header
configure_file(
	dukpt_config.h.in
	dukpt_config.h
)

# TDES DUKPT library
add_library(dukpt_tdes dukpt_tdes.c)
set_target_properties(dukpt_tdes
	PROPERTIES
		PUBLIC_HEADER dukpt_tdes.h
		VERSION ${CMAKE_PROJECT_VERSION}
		SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}
)
target_include_directories(dukpt_tdes PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # For generated config file
target_include_directories(dukpt_tdes INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)
target_link_libraries(dukpt_tdes PRIVATE crypto_tdes crypto_mem crypto_rand pinblock)

# AES DUKPT library
add_library(dukpt_aes dukpt_aes.c)
set_target_properties(dukpt_aes
	PROPERTIES
		PUBLIC_HEADER dukpt_aes.h
		VERSION ${CMAKE_PROJECT_VERSION}
		SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}.${CMAKE_PROJECT_VERSION_MINOR}
)
target_include_directories(dukpt_aes PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # For generated config file
target_include_directories(dukpt_aes INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)
target_link_libraries(dukpt_aes PRIVATE crypto_aes crypto_hmac crypto_mem crypto_rand pinblock)
if(HAVE_WINSOCK_H AND NOT HAVE_ARPA_INET_H)
	target_link_libraries(dukpt_aes PRIVATE ws2_32)
endif()

install(
	TARGETS
		crypto_tdes
		crypto_aes
		crypto_hmac
		crypto_mem
		crypto_rand
		pinblock
		dukpt_tdes
		dukpt_aes
	EXPORT dukptTargets # For use by install(EXPORT) command
	PUBLIC_HEADER
		DESTINATION "include/${PROJECT_NAME}"
		COMPONENT dukpt_development
	RUNTIME
		COMPONENT dukpt_runtime
	LIBRARY
		COMPONENT dukpt_runtime
		NAMELINK_COMPONENT dukpt_development
	ARCHIVE
		COMPONENT dukpt_development
)

# DUKPT command line tool
if(BUILD_DUKPT_TOOL)
	add_executable(dukpt-tool dukpt-tool.c)
	if(TARGET libargp::argp)
		target_link_libraries(dukpt-tool PRIVATE libargp::argp)
	endif()
	if(tr31_FOUND)
		target_compile_definitions(dukpt-tool PRIVATE DUKPT_TOOL_USE_TR31)
		target_link_libraries(dukpt-tool PRIVATE tr31::tr31)
	endif()
	target_link_libraries(dukpt-tool PRIVATE dukpt_tdes dukpt_aes)

	install(
		TARGETS
			dukpt-tool
		EXPORT dukptTargets # For use by install(EXPORT) command
		RUNTIME
			COMPONENT dukpt_runtime
	)
endif()

if(TARGET dukpt-tool AND BUILD_TESTING)
	add_test(NAME dukpt_tool_tdes_test1
		COMMAND dukpt-tool --bdk=0123456789ABCDEFFEDCBA9876543210 --ksn=FFFF9876543210E00000 --derive-ik
	)
	set_tests_properties(dukpt_tool_tdes_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^6AC292FAA1315B4D858AB3A3D7D5933A"
	)

	add_test(NAME dukpt_tool_tdes_test2
		COMMAND dukpt-tool --bdk=0123456789ABCDEFFEDCBA9876543210 --ksn=FFFF9876543210E00003 --derive-ik
	)
	set_tests_properties(dukpt_tool_tdes_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^6AC292FAA1315B4D858AB3A3D7D5933A"
	)

	add_test(NAME dukpt_tool_tdes_test3
		COMMAND dukpt-tool --bdk=0123456789ABCDEFFEDCBA9876543210 --ksn=FFFF9876543210E00001 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_tdes_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^042666B49184CFA368DE9628D0397BC9"
	)

	add_test(NAME dukpt_tool_tdes_test4
		COMMAND dukpt-tool --bdk=0123456789ABCDEFFEDCBA9876543210 --ksn=FFFF9876543210E00002 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_tdes_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^C46551CEF9FD24B0AA9AD834130D3BC7"
	)

	add_test(NAME dukpt_tool_tdes_test5
		COMMAND dukpt-tool --ik=6AC292FAA1315B4D858AB3A3D7D5933A --ksn=FFFF9876543210E00001 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_tdes_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^042666B49184CFA368DE9628D0397BC9"
	)

	add_test(NAME dukpt_tool_tdes_test6
		COMMAND dukpt-tool --ik=6AC292FAA1315B4D858AB3A3D7D5933A --ksn=FFFF9876543210E00002 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_tdes_test6
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^C46551CEF9FD24B0AA9AD834130D3BC7"
	)

	add_test(NAME dukpt_tool_tdes_ksn_test1
		COMMAND dukpt-tool --ksn=FFFF9876543210E00000 --advance-ksn
	)
	set_tests_properties(dukpt_tool_tdes_ksn_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^FFFF9876543210E00001"
	)

	add_test(NAME dukpt_tool_tdes_ksn_test2
		COMMAND dukpt-tool --ksn=FFFF9876543210E00001 --advance-ksn
	)
	set_tests_properties(dukpt_tool_tdes_ksn_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^FFFF9876543210E00002"
	)

	add_test(NAME dukpt_tool_tdes_ksn_test3
		COMMAND dukpt-tool --ksn=FFFF9876543210FFF400 --advance-ksn
	)
	set_tests_properties(dukpt_tool_tdes_ksn_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^FFFF9876543210FFF800"
	)

	add_test(NAME dukpt_tool_tdes_ksn_test4
		COMMAND dukpt-tool --ksn=FFFF9876543210EFFC00 --advance-ksn
	)
	set_tests_properties(dukpt_tool_tdes_ksn_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^FFFF9876543210F00000"
	)

	add_test(NAME dukpt_tool_tdes_ksn_test5
		COMMAND dukpt-tool --ksn=FFFF9876543210FFF800 --advance-ksn
	)
	set_tests_properties(dukpt_tool_tdes_ksn_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^KSN exhausted"
	)

	add_test(NAME dukpt_tool_aes128_test1
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456 --derive-ik
	)
	set_tests_properties(dukpt_tool_aes128_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^1273671EA26AC29AFA4D1084127652A1"
	)

	add_test(NAME dukpt_tool_aes128_test2
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000003 --derive-ik
	)
	set_tests_properties(dukpt_tool_aes128_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^1273671EA26AC29AFA4D1084127652A1"
	)

	add_test(NAME dukpt_tool_aes128_test3
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000001 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_aes128_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^4F21B565BAD9835E112B6465635EAE44"
	)

	add_test(NAME dukpt_tool_aes128_test4
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000002 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_aes128_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^2F34D68DE10F68D38091A73B9E7C437C"
	)

	add_test(NAME dukpt_tool_aes128_test5
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000001 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_aes128_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^4F21B565BAD9835E112B6465635EAE44"
	)

	add_test(NAME dukpt_tool_aes128_test6
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000002 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_aes128_test6
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^2F34D68DE10F68D38091A73B9E7C437C"
	)

	add_test(NAME dukpt_tool_aes256_test1
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456 --derive-ik
	)
	set_tests_properties(dukpt_tool_aes256_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F"
	)

	add_test(NAME dukpt_tool_aes256_test2
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000003 --derive-ik
	)
	set_tests_properties(dukpt_tool_aes256_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F"
	)

	add_test(NAME dukpt_tool_aes256_test3
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000001 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_aes256_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^54AC2B32B145EA4A554CB8BC44B17467063A799856B1CCC2A138D36E8DBF78B3"
	)

	add_test(NAME dukpt_tool_aes256_test4
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000002 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_aes256_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^5DD5A0253842BBBE1D7C0DA27021412C6F1FAB53FB928DEAE56DA06090A9DE97"
	)

	add_test(NAME dukpt_tool_aes256_test5
		COMMAND dukpt-tool --mode AES --ik CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F --ksn 123456789012345600000001 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_aes256_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^54AC2B32B145EA4A554CB8BC44B17467063A799856B1CCC2A138D36E8DBF78B3"
	)

	add_test(NAME dukpt_tool_aes256_test6
		COMMAND dukpt-tool --mode AES --ik CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F --ksn 123456789012345600000002 --derive-txn-key
	)
	set_tests_properties(dukpt_tool_aes256_test6
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^5DD5A0253842BBBE1D7C0DA27021412C6F1FAB53FB928DEAE56DA06090A9DE97"
	)

	add_test(NAME dukpt_tool_aes_ksn_test1
		COMMAND dukpt-tool --mode AES --ksn 123456789012345600000000 --advance-ksn
	)
	set_tests_properties(dukpt_tool_aes_ksn_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^123456789012345600000001"
	)

	add_test(NAME dukpt_tool_aes_ksn_test2
		COMMAND dukpt-tool --mode AES --ksn 123456789012345600000001 --advance-ksn
	)
	set_tests_properties(dukpt_tool_aes_ksn_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^123456789012345600000002"
	)

	add_test(NAME dukpt_tool_aes_ksn_test3
		COMMAND dukpt-tool --mode AES --ksn 12345678901234560001FFFE --advance-ksn
	)
	set_tests_properties(dukpt_tool_aes_ksn_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^123456789012345600020000"
	)

	add_test(NAME dukpt_tool_aes_ksn_test4
		COMMAND dukpt-tool --mode AES --ksn 1234567890123456FFFE8000 --advance-ksn
	)
	set_tests_properties(dukpt_tool_aes_ksn_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^1234567890123456FFFF0000"
	)

	add_test(NAME dukpt_tool_aes_ksn_test5
		COMMAND dukpt-tool --mode AES --ksn 1234567890123456FFFF0000 --advance-ksn
	)
	set_tests_properties(dukpt_tool_aes_ksn_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^KSN exhausted"
	)

	add_test(NAME dukpt_tool_aes128_update_key_test1
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456FFFFFFFF --key-type AES128 --derive-update-key
	)
	set_tests_properties(dukpt_tool_aes128_update_key_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^9A9770AEE1ACD1B13473D0463A1883B9"
	)

	add_test(NAME dukpt_tool_aes128_update_key_test2
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 1234567890123456FFFFFFFF --key-type AES128 --derive-update-key
	)
	set_tests_properties(dukpt_tool_aes128_update_key_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^9A9770AEE1ACD1B13473D0463A1883B9"
	)

	add_test(NAME dukpt_tool_aes128_update_key_test3
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456FFFFFFFF --derive-update-key
	)
	set_tests_properties(dukpt_tool_aes128_update_key_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^9A9770AEE1ACD1B13473D0463A1883B9"
	)

	add_test(NAME dukpt_tool_aes128_update_key_test4
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 1234567890123456FFFFFFFF --derive-update-key
	)
	set_tests_properties(dukpt_tool_aes128_update_key_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^9A9770AEE1ACD1B13473D0463A1883B9"
	)

	add_test(NAME dukpt_tool_aes256_update_key_test1
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456FFFFFFFF --key-type AES128 --derive-update-key
	)
	set_tests_properties(dukpt_tool_aes256_update_key_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^90E54E4A70160C7E085C09D2B241D343"
	)

	add_test(NAME dukpt_tool_aes256_update_key_test2
		COMMAND dukpt-tool --mode AES --ik CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F --ksn 1234567890123456FFFFFFFF --key-type AES128 --derive-update-key
	)
	set_tests_properties(dukpt_tool_aes256_update_key_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^90E54E4A70160C7E085C09D2B241D343"
	)

	add_test(NAME dukpt_tool_aes256_update_key_test3
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456FFFFFFFF --key-type AES256 --derive-update-key
	)
	set_tests_properties(dukpt_tool_aes256_update_key_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^AEFB210C136278A1279F7C8815F446DB8EBE2AA910B157AA4E6484D8DE9C4807"
	)

	add_test(NAME dukpt_tool_aes256_update_key_test4
		COMMAND dukpt-tool --mode AES --ik CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F --ksn 1234567890123456FFFFFFFF --key-type AES256 --derive-update-key
	)
	set_tests_properties(dukpt_tool_aes256_update_key_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^AEFB210C136278A1279F7C8815F446DB8EBE2AA910B157AA4E6484D8DE9C4807"
	)

	add_test(NAME dukpt_tool_aes256_update_key_test5
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456FFFFFFFF --derive-update-key
	)
	set_tests_properties(dukpt_tool_aes256_update_key_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^AEFB210C136278A1279F7C8815F446DB8EBE2AA910B157AA4E6484D8DE9C4807"
	)

	add_test(NAME dukpt_tool_aes256_update_key_test6
		COMMAND dukpt-tool --mode AES --ik CE9CE0C101D1138F97FB6CAD4DF045A7083D4EAE2D35A31789D01CCF0949550F --ksn 1234567890123456FFFFFFFF --derive-update-key
	)
	set_tests_properties(dukpt_tool_aes256_update_key_test6
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^AEFB210C136278A1279F7C8815F446DB8EBE2AA910B157AA4E6484D8DE9C4807"
	)

	add_test(NAME dukpt_tool_tdes_pinblock_test1
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00001 --encrypt-pinblock 041274EDCBA9876F
	)
	set_tests_properties(dukpt_tool_tdes_pinblock_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^1B9C1845EB993A7A"
	)

	add_test(NAME dukpt_tool_tdes_pinblock_test2
		COMMAND dukpt-tool --ik 6AC292FAA1315B4D858AB3A3D7D5933A --ksn FFFF9876543210E00001 --decrypt-pinblock 1B9C1845EB993A7A
	)
	set_tests_properties(dukpt_tool_tdes_pinblock_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^041274EDCBA9876F"
	)

	add_test(NAME dukpt_tool_tdes_pinblock_test3
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00002 --encrypt-pinblock 041274EDCBA9876F
	)
	set_tests_properties(dukpt_tool_tdes_pinblock_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^10A01C8D02C69107"
	)

	add_test(NAME dukpt_tool_tdes_pinblock_test4
		COMMAND dukpt-tool --ik 6AC292FAA1315B4D858AB3A3D7D5933A --ksn FFFF9876543210E00002 --decrypt-pinblock 10A01C8D02C69107
	)
	set_tests_properties(dukpt_tool_tdes_pinblock_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^041274EDCBA9876F"
	)

	add_test(NAME dukpt_tool_tdes_pinblock_test5
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210F00000 --encrypt-pinblock 041274EDCBA9876F
	)
	set_tests_properties(dukpt_tool_tdes_pinblock_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^73EC88AD0AC5830E"
	)

	add_test(NAME dukpt_tool_tdes_pinblock_test6
		COMMAND dukpt-tool --ik 6AC292FAA1315B4D858AB3A3D7D5933A --ksn FFFF9876543210F00000 --decrypt-pinblock 73EC88AD0AC5830E
	)
	set_tests_properties(dukpt_tool_tdes_pinblock_test6
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^041274EDCBA9876F"
	)

	add_test(NAME dukpt_tool_tdes_pin_test1
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00001 --pan 4012345678909 --pinblock-format 0 --encrypt-pin 1234
	)
	set_tests_properties(dukpt_tool_tdes_pin_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^1B9C1845EB993A7A"
	)

	add_test(NAME dukpt_tool_tdes_pin_test2
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00001 --pan 4012345678909 --decrypt-pin 1B9C1845EB993A7A
	)
	set_tests_properties(dukpt_tool_tdes_pin_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^1234"
	)

	add_test(NAME dukpt_tool_tdes_pin_test3
		COMMAND dukpt-tool --ik 6AC292FAA1315B4D858AB3A3D7D5933A --ksn FFFF9876543210E00002 --pan 4012345678909 --encrypt-pin 1234
	)
	set_tests_properties(dukpt_tool_tdes_pin_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^10A01C8D02C69107"
	)

	add_test(NAME dukpt_tool_tdes_pin_test4
		COMMAND dukpt-tool --ik 6AC292FAA1315B4D858AB3A3D7D5933A --ksn FFFF9876543210E00002 --pan 4012345678909 --decrypt-pin 10A01C8D02C69107
	)
	set_tests_properties(dukpt_tool_tdes_pin_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^1234"
	)

	add_test(NAME dukpt_tool_tdes_pin_test5
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00003 --pan 4012345678909 --pinblock-format 3 --encrypt-pin 1234
		# NOTE: this test only check for pass/fail because PIN block format 3 results in an unpredictable encrypted PIN block
	)

	add_test(NAME dukpt_tool_tdes_pin_test6
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00003 --pan 4012345678909 --pinblock-format 4 --encrypt-pin 1234
		# NOTE: this test will fail because TDES PIN encryption doesn't allow PIN block format 4
	)
	set_tests_properties(dukpt_tool_tdes_pin_test6
		PROPERTIES
			WILL_FAIL True
	)

	add_test(NAME dukpt_tool_aes128_pinblock_test1
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000001 --key-type AES128 --pan 4111111111111111 --encrypt-pinblock 441234AAAAAAAAAA2F69ADDE2E9E7ACE
	)
	set_tests_properties(dukpt_tool_aes128_pinblock_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^A912150391AB65A67E52883D81CE2D15"
	)

	add_test(NAME dukpt_tool_aes128_pinblock_test2
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000001 --pan 4111111111111111 --decrypt-pinblock A912150391AB65A67E52883D81CE2D15
	)
	set_tests_properties(dukpt_tool_aes128_pinblock_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^441234AAAAAAAAAA2F69ADDE2E9E7ACE"
	)

	add_test(NAME dukpt_tool_aes128_pinblock_test3
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000002 --pan 4111111111111111 --encrypt-pinblock 441234AAAAAAAAAA2F69ADDE2E9E7ACE
	)
	set_tests_properties(dukpt_tool_aes128_pinblock_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^52A00503BD34BA1383F6A7EE9FE2547F"
	)

	add_test(NAME dukpt_tool_aes128_pinblock_test4
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000002 --key-type AES128 --pan 4111111111111111 --decrypt-pinblock 52A00503BD34BA1383F6A7EE9FE2547F
	)
	set_tests_properties(dukpt_tool_aes128_pinblock_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^441234AAAAAAAAAA2F69ADDE2E9E7ACE"
	)

	add_test(NAME dukpt_tool_aes128_pinblock_test5
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600845FED --pan 4111111111111111 --encrypt-pinblock 441234AAAAAAAAAA2F69ADDE2E9E7ACE
	)
	set_tests_properties(dukpt_tool_aes128_pinblock_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^3AB5FF370302F73089003AD36CB7E046"
	)

	add_test(NAME dukpt_tool_aes128_pinblock_test6
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600845FED --pan 4111111111111111 --decrypt-pinblock 3AB5FF370302F73089003AD36CB7E046
	)
	set_tests_properties(dukpt_tool_aes128_pinblock_test6
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^441234AAAAAAAAAA2F69ADDE2E9E7ACE"
	)

	add_test(NAME dukpt_tool_aes128_pin_test1
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000001 --key-type AES128 --pan 4111111111111111 --encrypt-pin 1234
		# NOTE: this test only check for pass/fail because PIN block format 4 results in an unpredictable encrypted PIN block
	)

	add_test(NAME dukpt_tool_aes128_pin_test2
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000001 --pan 4111111111111111 --decrypt-pin A912150391AB65A67E52883D81CE2D15
	)
	set_tests_properties(dukpt_tool_aes128_pin_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^1234"
	)

	add_test(NAME dukpt_tool_aes128_pin_test3
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000002 --pan 4111111111111111 --encrypt-pin 1234
		# NOTE: this test only check for pass/fail because PIN block format 4 results in an unpredictable encrypted PIN block
	)

	add_test(NAME dukpt_tool_aes128_pin_test4
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000002 --key-type AES128 --pan 4111111111111111 --decrypt-pin 52A00503BD34BA1383F6A7EE9FE2547F
	)
	set_tests_properties(dukpt_tool_aes128_pin_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^1234"
	)

	add_test(NAME dukpt_tool_aes128_pin_test5
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600845FED --pan 4111111111111111 --pinblock-format 0 --encrypt-pin 1234
		# NOTE: this test will fail because AES PIN encryption must use PIN block format 4
	)
	set_tests_properties(dukpt_tool_aes128_pin_test5
		PROPERTIES
			WILL_FAIL True
	)

	add_test(NAME dukpt_tool_aes128_pin_test6
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600845FED --pan 4111111111111111 --pinblock-format 4 --encrypt-pin 1234
		# NOTE: this test only check for pass/fail because PIN block format 4 results in an unpredictable encrypted PIN block
	)

	add_test(NAME dukpt_tool_tdes_data_test1
		COMMAND dukpt-tool --mode TDES --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00001 --encrypt-request 343031323334353637383930394439383700000000000000
	)
	set_tests_properties(dukpt_tool_tdes_data_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^FC0D53B7EA1FDA9EE68AAF2E70D9B9506229BE2AA993F04F"
	)

	add_test(NAME dukpt_tool_tdes_data_test2
		COMMAND dukpt-tool --mode TDES --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00001 --decrypt-request FC0D53B7EA1FDA9EE68AAF2E70D9B9506229BE2AA993F04F
	)
	set_tests_properties(dukpt_tool_tdes_data_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^343031323334353637383930394439383700000000000000"
	)

	add_test(NAME dukpt_tool_tdes_data_test3
		COMMAND dukpt-tool --mode TDES --ik 6AC292FAA1315B4D858AB3A3D7D5933A --ksn FFFF9876543210E00002 --encrypt-request 343031323334353637383930394439383700000000000000
	)
	set_tests_properties(dukpt_tool_tdes_data_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^A2B4E70F846E63D68775B7215EB4563DFD3037244C61CC13"
	)

	add_test(NAME dukpt_tool_tdes_data_test4
		COMMAND dukpt-tool --mode TDES --ik 6AC292FAA1315B4D858AB3A3D7D5933A --ksn FFFF9876543210E00002 --decrypt-request A2B4E70F846E63D68775B7215EB4563DFD3037244C61CC13
	)
	set_tests_properties(dukpt_tool_tdes_data_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^343031323334353637383930394439383700000000000000"
	)

	add_test(NAME dukpt_tool_tdes_data_test5
		COMMAND dukpt-tool --mode TDES --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00001 --iv DDA6F8C3E9ABB51D --encrypt-request 343031323334353637383930394439383700000000000000
	)
	set_tests_properties(dukpt_tool_tdes_data_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^6B700AEEDD6F04F4B5B9245AA88C22B6D1052A8B4C0207CC"
	)

	add_test(NAME dukpt_tool_tdes_data_test6
		COMMAND dukpt-tool --mode TDES --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00001 --iv DDA6F8C3E9ABB51D --decrypt-request 6B700AEEDD6F04F4B5B9245AA88C22B6D1052A8B4C0207CC
	)
	set_tests_properties(dukpt_tool_tdes_data_test6
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^343031323334353637383930394439383700000000000000"
	)

	add_test(NAME dukpt_tool_tdes_data_test7
		COMMAND dukpt-tool --mode TDES --ik 6AC292FAA1315B4D858AB3A3D7D5933A --ksn FFFF9876543210E00002 --iv 4F4B5B9245AA88C2 --encrypt-request 343031323334353637383930394439383700000000000000
	)
	set_tests_properties(dukpt_tool_tdes_data_test7
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^EB963556921259B22D6487CF5272D66598ABDE3741C56949"
	)

	add_test(NAME dukpt_tool_tdes_data_test8
		COMMAND dukpt-tool --mode TDES --ik 6AC292FAA1315B4D858AB3A3D7D5933A --ksn FFFF9876543210E00002 --iv 4F4B5B9245AA88C2 --decrypt-request EB963556921259B22D6487CF5272D66598ABDE3741C56949
	)
	set_tests_properties(dukpt_tool_tdes_data_test8
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^343031323334353637383930394439383700000000000000"
	)

	add_test(NAME dukpt_tool_aes128_data_test1
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000001 --key-type AES128 --encrypt-request 3430313233343536373839303944393837000000000000000000000000000000
	)
	set_tests_properties(dukpt_tool_aes128_data_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^E5AFA5B408A3310E3D779C8A9A2AE29448BD5B4232582090DB703AF647205A79"
	)

	add_test(NAME dukpt_tool_aes128_data_test2
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000001 --key-type AES128 --decrypt-request E5AFA5B408A3310E3D779C8A9A2AE29448BD5B4232582090DB703AF647205A79
	)
	set_tests_properties(dukpt_tool_aes128_data_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^3430313233343536373839303944393837000000000000000000000000000000"
	)

	add_test(NAME dukpt_tool_aes128_data_test3
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000002 --key-type AES128 --encrypt-request 3430313233343536373839303944393837000000000000000000000000000000
	)
	set_tests_properties(dukpt_tool_aes128_data_test3
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^A17A9658EE0F451D6CA11B65B592EF9C5F90BB175D926F1457B63B3273042476"
	)

	add_test(NAME dukpt_tool_aes128_data_test4
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000002 --key-type AES128 --decrypt-request A17A9658EE0F451D6CA11B65B592EF9C5F90BB175D926F1457B63B3273042476
	)
	set_tests_properties(dukpt_tool_aes128_data_test4
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^3430313233343536373839303944393837000000000000000000000000000000"
	)

	add_test(NAME dukpt_tool_aes128_data_test5
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000001 --key-type AES128 --iv 1244C548FB7FF50A274AD44C146276B7 --encrypt-request 3430313233343536373839303944393837000000000000000000000000000000
	)
	set_tests_properties(dukpt_tool_aes128_data_test5
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^949C779F309920E71A1F6CDDE5B92355A28612F0B0EBE28CEB0BFA4E2DE21414"
	)

	add_test(NAME dukpt_tool_aes128_data_test6
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000001 --key-type AES128 --iv 1244C548FB7FF50A274AD44C146276B7 --decrypt-request 949C779F309920E71A1F6CDDE5B92355A28612F0B0EBE28CEB0BFA4E2DE21414
	)
	set_tests_properties(dukpt_tool_aes128_data_test6
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^3430313233343536373839303944393837000000000000000000000000000000"
	)

	add_test(NAME dukpt_tool_aes128_data_test7
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000002 --key-type AES128 --iv B7D2C339AEAB7E0EB019D467ABCA7E88 --encrypt-request 3430313233343536373839303944393837000000000000000000000000000000
	)
	set_tests_properties(dukpt_tool_aes128_data_test7
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^4F9616BECB1ECA5176FB17BCF0A08AF529072320F4DD849CF9573F50C0509060"
	)

	add_test(NAME dukpt_tool_aes128_data_test8
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000002 --key-type AES128 --iv B7D2C339AEAB7E0EB019D467ABCA7E88 --decrypt-request 4F9616BECB1ECA5176FB17BCF0A08AF529072320F4DD849CF9573F50C0509060
	)
	set_tests_properties(dukpt_tool_aes128_data_test8
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^3430313233343536373839303944393837000000000000000000000000000000"
	)

	add_test(NAME dukpt_tool_aes128_data_test9
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000001 --key-type AES128 --encrypt-response 3430313233343536373839303944393837000000000000000000000000000000
	)
	set_tests_properties(dukpt_tool_aes128_data_test9
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^84904DFC6B5201A4F1FE2EAA49E70B8C01838EF53030790FF785D630AB3916B4"
	)

	add_test(NAME dukpt_tool_aes128_data_test10
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000001 --key-type AES128 --decrypt-response 84904DFC6B5201A4F1FE2EAA49E70B8C01838EF53030790FF785D630AB3916B4
	)
	set_tests_properties(dukpt_tool_aes128_data_test10
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^3430313233343536373839303944393837000000000000000000000000000000"
	)

	add_test(NAME dukpt_tool_aes128_data_test11
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000002 --key-type AES128 --encrypt-response 3430313233343536373839303944393837000000000000000000000000000000
	)
	set_tests_properties(dukpt_tool_aes128_data_test11
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^699ED7BC85994F1C11DE1C40177A629530E85262EA0B02FB80771255DC1F65B6"
	)

	add_test(NAME dukpt_tool_aes128_data_test12
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000002 --key-type AES128 --decrypt-response 699ED7BC85994F1C11DE1C40177A629530E85262EA0B02FB80771255DC1F65B6
	)
	set_tests_properties(dukpt_tool_aes128_data_test12
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^3430313233343536373839303944393837000000000000000000000000000000"
	)

	add_test(NAME dukpt_tool_aes128_data_test13
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000001 --key-type AES128 --iv 1244C548FB7FF50A274AD44C146276B7 --encrypt-response 3430313233343536373839303944393837000000000000000000000000000000
	)
	set_tests_properties(dukpt_tool_aes128_data_test13
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^91C29233243744D590DCDC53FCBDB08065FAD927C37E37502E4833AB058ADDE1"
	)

	add_test(NAME dukpt_tool_aes128_data_test14
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000001 --key-type AES128 --iv 1244C548FB7FF50A274AD44C146276B7 --decrypt-response 91C29233243744D590DCDC53FCBDB08065FAD927C37E37502E4833AB058ADDE1
	)
	set_tests_properties(dukpt_tool_aes128_data_test14
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^3430313233343536373839303944393837000000000000000000000000000000"
	)

	add_test(NAME dukpt_tool_aes128_data_test15
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000002 --key-type AES128 --iv B7D2C339AEAB7E0EB019D467ABCA7E88 --encrypt-response 3430313233343536373839303944393837000000000000000000000000000000
	)
	set_tests_properties(dukpt_tool_aes128_data_test15
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^EB95DDA9EA336CC1091A53953CE5A86DB0FC7588BC01BCF27AA7FCADF87A2C1F"
	)

	add_test(NAME dukpt_tool_aes128_data_test16
		COMMAND dukpt-tool --mode AES --ik 1273671EA26AC29AFA4D1084127652A1 --ksn 123456789012345600000002 --key-type AES128 --iv B7D2C339AEAB7E0EB019D467ABCA7E88 --decrypt-response EB95DDA9EA336CC1091A53953CE5A86DB0FC7588BC01BCF27AA7FCADF87A2C1F
	)
	set_tests_properties(dukpt_tool_aes128_data_test16
		PROPERTIES
			PASS_REGULAR_EXPRESSION "^3430313233343536373839303944393837000000000000000000000000000000"
	)

	if(tr31_FOUND)
		add_test(NAME dukpt_tool_tr31_test1
			COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456 --derive-ik --output-tr31 3235362D62697420414553207772617070696E67202849534F20323030333829 --output-tr31-format-version E --output-tr31-with-ksn
		)
		set_tests_properties(dukpt_tool_tr31_test1
			PROPERTIES
				PASS_REGULAR_EXPRESSION "^E0116B1AX00N0200IK141234567890123456PB0C000000008FAD1464E086FA2538D8FF061AB8AAEB3264852F433F215E3CB7903F7CD393AC6F4C"
		)

		add_test(NAME dukpt_tool_tr31_test2
			COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456 --derive-ik --output-tr31 3235362D62697420414553207772617070696E67202849534F20323030333829 --output-tr31-format-version E --output-tr31-with-ksn --output-tr31-with-kc
		)
		set_tests_properties(dukpt_tool_tr31_test2
			PROPERTIES
				PASS_REGULAR_EXPRESSION "^E0132B1AX00N0300IK141234567890123456KC100105EF4531ECPB0C000000002D1E3CBD08D4C9E3B676277286DC4623D7D5CDC7DD5EBC5FE84A50D22122C02975ED"
		)

		add_test(NAME dukpt_tool_tr31_test3
			COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456 --derive-ik --output-tr31 3235362D62697420414553207772617070696E67202849534F20323030333829 --output-tr31-format-version E --output-tr31-with-ksn --output-tr31-with-kc --output-tr31-with-kp
		)
		set_tests_properties(dukpt_tool_tr31_test3
			PROPERTIES
				PASS_REGULAR_EXPRESSION "^E0148B1AX00N0400IK141234567890123456KC100105EF4531ECKP10019E357FBF09PB0C00000000AB37D3FD2A840B095AAD50173A1B05EFBFD4384D37BCD9EDAB93C7D4EA6127EFEE89"
		)

		add_test(NAME dukpt_tool_tr31_test4
			COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00000 --derive-ik --output-tr31 3235362D62697420414553207772617070696E67202849534F20323030333829 --output-tr31-format-version E --output-tr31-with-ksn --output-tr31-with-kc --output-tr31-with-kp
		)
		set_tests_properties(dukpt_tool_tr31_test4
			PROPERTIES
				PASS_REGULAR_EXPRESSION "^E0148B1TX00N0400KS18FFFF9876543210E00000KC0C00AF8C07KP10019E357FBF09PB0C00000000681A4D763AD3E62943416007DFEE2CA9B0CC94D160882FDFB69182926B0403418001"
		)
	endif()
endif()
