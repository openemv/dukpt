##############################################################################
# Copyright 2021-2024 Leon Lynch
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

# Check for tr31 using TR31_MIN_VERSION provided by the parent scope
find_package(tr31 ${TR31_MIN_VERSION} CONFIG)
if(BUILD_DUKPT_TOOL AND tr31_FOUND)
	# The DUKPT_PACKAGE_DEPENDENCIES variable is set for the parent scope to
	# facilitate the generation of CMake package configuration files.
	list(APPEND DUKPT_PACKAGE_DEPENDENCIES "tr31 ${TR31_MIN_VERSION} CONFIG")
	set(DUKPT_PACKAGE_DEPENDENCIES ${DUKPT_PACKAGE_DEPENDENCIES} PARENT_SCOPE)
endif()

# Check for time.h required by dukpt-tool
include(CheckIncludeFile)
CHECK_INCLUDE_FILE(time.h HAVE_TIME_H)
if(BUILD_DUKPT_TOOL AND NOT HAVE_TIME_H)
	message(FATAL_ERROR "Could NOT find time.h. This is required to build dukpt-tool")
endif()

# Generate config file for internal use only
# This file should NOT be installed or used by an installed header
configure_file(
	dukpt_config.h.in
	dukpt_config.h
)

# TDES DUKPT library
add_library(dukpt_tdes dukpt_tdes.c)
add_library(dukpt::dukpt_tdes ALIAS dukpt_tdes)
set_target_properties(dukpt_tdes
	PROPERTIES
		PUBLIC_HEADER dukpt_tdes.h
		VERSION ${CMAKE_PROJECT_VERSION}
		SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_include_directories(dukpt_tdes PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # For generated config file
target_include_directories(dukpt_tdes INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)
target_link_libraries(dukpt_tdes PRIVATE crypto_tdes crypto_mem crypto_rand pinblock)

# AES DUKPT library
add_library(dukpt_aes dukpt_aes.c)
add_library(dukpt::dukpt_aes ALIAS dukpt_aes)
set_target_properties(dukpt_aes
	PROPERTIES
		PUBLIC_HEADER dukpt_aes.h
		VERSION ${CMAKE_PROJECT_VERSION}
		SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
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

	if(WIN32 AND tr31_FOUND)
		# Copy tr31 DLL to build tree for dukpt-tool and tests on Windows
		# NOTE: This does NOT install the tr31 DLL
		get_target_property(tr31_TYPE tr31::tr31 TYPE)
		if(tr31_TYPE STREQUAL "SHARED_LIBRARY") # If tr31 library is a DLL
			add_custom_command(TARGET dukpt-tool POST_BUILD
				COMMAND ${CMAKE_COMMAND} -E copy_if_different
					$<TARGET_FILE:tr31::tr31>
					$<TARGET_FILE_DIR:dukpt-tool>
				COMMENT "Copying tr31 DLL..."
			)
		endif()
	endif()
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

	add_test(NAME dukpt_tool_tdes_pin_test7
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00001 --pan 4022345678909 --decrypt-pin 1B9C1845EB993A7A
		# NOTE: this test will fail because the PAN is incorrect
	)
	set_tests_properties(dukpt_tool_tdes_pin_test7
		PROPERTIES
			WILL_FAIL True
	)

	add_test(NAME dukpt_tool_tdes_pin_test8
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00001 --pan 4022345678909 --decrypt-pin 1B9C1845EB993A7A
		# NOTE: this test will fail because the PAN is incorrect
	)
	set_tests_properties(dukpt_tool_tdes_pin_test8
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

	add_test(NAME dukpt_tool_aes128_pin_test7
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000001 --pan 4111111111111112 --decrypt-pin A912150391AB65A67E52883D81CE2D15
		# NOTE: this test will fail because the PAN is incorrect
	)
	set_tests_properties(dukpt_tool_aes128_pin_test7
		PROPERTIES
			WILL_FAIL True
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

	add_test(NAME dukpt_tool_tdes_state_test1
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00001 --dump-state
	)
	string(CONCAT dukpt_tool_tdes_state_test1_regex
		"^ 1: 042666B49184CFA368DE9628D0397BC9[\r\n]"
		" 2: C46551CEF9FD24B0AA9AD834130D3BC7[\r\n]"
		" 3: 279C0F6AEED0BE652B2C733E1383AE91[\r\n]"
		" 4: 27F66D5244FF62E1AA6F6120EDEB4280[\r\n]"
		" 5: 59598DCBD9BD94C094165CE453585F57[\r\n]"
		" 6: A928334AB384B4CAF30C9F8F71A4693C[\r\n]"
		" 7: 8AB30B5CABED51324C8733F1F0CF2DB5[\r\n]"
		" 8: 6151CE9C70468712BBA9B06FD7220311[\r\n]"
		" 9: A6ECEC4019F8BB2C1D0E1EA90E4F71AE[\r\n]"
		"10: B6E1F9986650D37A8CAAEF7E600FD102[\r\n]"
		"11: 03674910286A78FF1E736AAA82B8260D[\r\n]"
		"12: 7E4AB005422BCADC5F65363964EF6504[\r\n]"
		"13: 014BDAE9DBDC07531517FB438835E3CF[\r\n]"
		"14: 92F14EB165BB58ED5E0C674D2A135EB8[\r\n]"
		"15: 67DE2B0E87E08041243A234728828404[\r\n]"
		"16: 1A62D89919CA2FEAECF26361957215F6[\r\n]"
		"17: 2F9A0C0B46ECCB5EF8287A7A071AF5B4[\r\n]"
		"18: DEFDE0EA1043B5722FA013DE6C4B8FFB[\r\n]"
		"19: 9F59E8536BDB059A13C856FCCF9A097E[\r\n]"
		"20: 87B9983D9D2304858D199F5CA0C3DE13[\r\n]"
		"21: AA4D58DB653EC74A48C75F2F047DD2B5[\r\n]$"
	)
	set_tests_properties(dukpt_tool_tdes_state_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION ${dukpt_tool_tdes_state_test1_regex}
	)

	add_test(NAME dukpt_tool_tdes_state_test2
		COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E0F000 --dump-state
	)
	string(CONCAT dukpt_tool_tdes_state_test2_regex
		"^ 1: 280921848B3488942FB2C1A8F6724FB2[\r\n]"
		" 2: BF91D85470C89042A6D5AC2BA60E3E8D[\r\n]"
		" 3: 0ECCB67323CD960C000EE3C9AEFD0186[\r\n]"
		" 4: EB28F15AC06C232541C50D2945B63AEF[\r\n]"
		" 5: D951EA1EAB97310123DA387757D944E4[\r\n]"
		" 6: -[\r\n]"
		" 7: -[\r\n]"
		" 8: -[\r\n]"
		" 9: -[\r\n]"
		"10: -[\r\n]"
		"11: -[\r\n]"
		"12: -[\r\n]"
		"13: E2B1C8103FA5C3C7DC719228E2C945C8[\r\n]"
		"14: -[\r\n]"
		"15: -[\r\n]"
		"16: -[\r\n]"
		"17: 2F9A0C0B46ECCB5EF8287A7A071AF5B4[\r\n]"
		"18: DEFDE0EA1043B5722FA013DE6C4B8FFB[\r\n]"
		"19: 9F59E8536BDB059A13C856FCCF9A097E[\r\n]"
		"20: 87B9983D9D2304858D199F5CA0C3DE13[\r\n]"
		"21: AA4D58DB653EC74A48C75F2F047DD2B5[\r\n]$"
	)
	set_tests_properties(dukpt_tool_tdes_state_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION ${dukpt_tool_tdes_state_test2_regex}
	)

	add_test(NAME dukpt_tool_aes_state_test1
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 123456789012345600000001 --dump-state
	)
	string(CONCAT dukpt_tool_aes_state_test1_regex
		"^ 1: 4F21B565BAD9835E112B6465635EAE44[\r\n]"
		" 2: 2F34D68DE10F68D38091A73B9E7C437C[\r\n]"
		" 3: 0EEFC7ADA628BA68878DA9165A8A1887[\r\n]"
		" 4: 718EE6CF0B27E53D5F7AF99C4D8146A2[\r\n]"
		" 5: 7459762EED7F51D08567ED6598DFBEA2[\r\n]"
		" 6: 1ED39390B4448C69819EB55F4C616564[\r\n]"
		" 7: C13BDA0A56D6998E544E0A10A3D979DA[\r\n]"
		" 8: 089F6B989CA13D49A6A0317F85460CE5[\r\n]"
		" 9: 065355A6A3DD4C2260BDDDFA0C16704E[\r\n]"
		"10: CF16FEBC5CFD1A741A3280564A9681F2[\r\n]"
		"11: 4BF8EB1DAF9F4244332ED01663EB654E[\r\n]"
		"12: 492248FEE0FE87E8B5DB7BB2AC7BC955[\r\n]"
		"13: 18690547EB19D28EFAF5EF6D22C271AA[\r\n]"
		"14: 84F4CCA45C4F1D4E063F1CE5B95B6C7F[\r\n]"
		"15: 4EC5FC0C3CD62AFF174A37B6FDC2B0D9[\r\n]"
		"16: 9EF99A4D5FD548A23D299074047F7F6B[\r\n]"
		"17: F4C6237DB49E28BF96E6A18CD8CDDA00[\r\n]"
		"18: F7AE9025468A25D37B7249CFFED224C8[\r\n]"
		"19: 579594A986E87917382A181576FA7A9A[\r\n]"
		"20: 5AAF46AAD7593E0D224E05E13629ED1E[\r\n]"
		"21: 5787EB837B6FFB3AF24759F8625CEC19[\r\n]"
		"22: 988A3AB89B9332A15D0BE2C54C279923[\r\n]"
		"23: E55171636976BDC5758A6FA4C25F0008[\r\n]"
		"24: DF16D5BAC52FFA7564D7DBD2DE7C6CCF[\r\n]"
		"25: 145E8C933FC0D61900592035CF18A5AF[\r\n]"
		"26: FBDF917E209B42F9DB8843D18BEE8033[\r\n]"
		"27: 61C70779F920BBD37815C21B5A1A7B75[\r\n]"
		"28: 97D7BB3FC342B9E961308BB8B801775B[\r\n]"
		"29: 69B453118411404DB54AE2B751F02F43[\r\n]"
		"30: 7CCE4E679F4FC3478E3CD4509D64A7F3[\r\n]"
		"31: 36AF4AA9FC1100B2AE7742101540340A[\r\n]"
		"32: 9DC56486499A2E857FDEFC4740641EA8[\r\n]$"
	)
	set_tests_properties(dukpt_tool_aes_state_test1
		PROPERTIES
			PASS_REGULAR_EXPRESSION ${dukpt_tool_aes_state_test1_regex}
	)

	add_test(NAME dukpt_tool_aes_state_test2
		COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 12345678901234560000AA00 --dump-state
	)
	string(CONCAT dukpt_tool_aes_state_test2_regex
		"^ 1: -[\r\n]"
		" 2: -[\r\n]"
		" 3: -[\r\n]"
		" 4: -[\r\n]"
		" 5: -[\r\n]"
		" 6: -[\r\n]"
		" 7: -[\r\n]"
		" 8: -[\r\n]"
		" 9: -[\r\n]"
		"10: 0C799DFA4ED4EC1BB144ABED959CD619[\r\n]"
		"11: 5E1BE95796FF6C6E5BCFD92B24871E8D[\r\n]"
		"12: -[\r\n]"
		"13: 6B8F63A1BD66F1F641E41FC0656A7E2F[\r\n]"
		"14: -[\r\n]"
		"15: A1BCBDBF21BE80A20C0B124C73315EA7[\r\n]"
		"16: -[\r\n]"
		"17: F4C6237DB49E28BF96E6A18CD8CDDA00[\r\n]"
		"18: F7AE9025468A25D37B7249CFFED224C8[\r\n]"
		"19: 579594A986E87917382A181576FA7A9A[\r\n]"
		"20: 5AAF46AAD7593E0D224E05E13629ED1E[\r\n]"
		"21: 5787EB837B6FFB3AF24759F8625CEC19[\r\n]"
		"22: 988A3AB89B9332A15D0BE2C54C279923[\r\n]"
		"23: E55171636976BDC5758A6FA4C25F0008[\r\n]"
		"24: DF16D5BAC52FFA7564D7DBD2DE7C6CCF[\r\n]"
		"25: 145E8C933FC0D61900592035CF18A5AF[\r\n]"
		"26: FBDF917E209B42F9DB8843D18BEE8033[\r\n]"
		"27: 61C70779F920BBD37815C21B5A1A7B75[\r\n]"
		"28: 97D7BB3FC342B9E961308BB8B801775B[\r\n]"
		"29: 69B453118411404DB54AE2B751F02F43[\r\n]"
		"30: 7CCE4E679F4FC3478E3CD4509D64A7F3[\r\n]"
		"31: 36AF4AA9FC1100B2AE7742101540340A[\r\n]"
		"32: 9DC56486499A2E857FDEFC4740641EA8[\r\n]$"
	)
	set_tests_properties(dukpt_tool_aes_state_test2
		PROPERTIES
			PASS_REGULAR_EXPRESSION ${dukpt_tool_aes_state_test2_regex}
	)

	if(tr31_FOUND)
		add_test(NAME dukpt_tool_tr31_test1
			COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456 --derive-ik --output-tr31 3235362D62697420414553207772617070696E67202849534F20323030333829 --output-tr31-format-version E --output-tr31-with-ksn
		)
		set_tests_properties(dukpt_tool_tr31_test1
			PROPERTIES
				# tr31-tool --kbpk 3235362D62697420414553207772617070696E67202849534F20323030333829 --export 1273671EA26AC29AFA4D1084127652A1 --export-template IK --export-format-version E --export-key-algorithm AES --export-opt-block-IK 1234567890123456 --export-no-key-length-obfuscation --export-zero-opt-block-PB
				PASS_REGULAR_EXPRESSION "^E0116B1AX00N0200IK141234567890123456PB0C000000008FAD1464E086FA2538D8FF061AB8AAEB3264852F433F215E3CB7903F7CD393AC6F4C"
		)

		add_test(NAME dukpt_tool_tr31_test2
			COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456 --derive-ik --output-tr31 3235362D62697420414553207772617070696E67202849534F20323030333829 --output-tr31-format-version E --output-tr31-with-ksn --output-tr31-with-kc
		)
		set_tests_properties(dukpt_tool_tr31_test2
			PROPERTIES
				# tr31-tool --kbpk 3235362D62697420414553207772617070696E67202849534F20323030333829 --export 1273671EA26AC29AFA4D1084127652A1 --export-template IK --export-format-version E --export-key-algorithm AES --export-opt-block-IK 1234567890123456 --export-opt-block-KC --export-no-key-length-obfuscation --export-zero-opt-block-PB
				PASS_REGULAR_EXPRESSION "^E0132B1AX00N0300IK141234567890123456KC100105EF4531ECPB0C000000002D1E3CBD08D4C9E3B676277286DC4623D7D5CDC7DD5EBC5FE84A50D22122C02975ED"
		)

		add_test(NAME dukpt_tool_tr31_test3
			COMMAND dukpt-tool --mode AES --bdk FEDCBA9876543210F1F1F1F1F1F1F1F1 --ksn 1234567890123456 --derive-ik --output-tr31 3235362D62697420414553207772617070696E67202849534F20323030333829 --output-tr31-format-version E --output-tr31-with-ksn --output-tr31-with-kc --output-tr31-with-kp
		)
		set_tests_properties(dukpt_tool_tr31_test3
			PROPERTIES
				# tr31-tool --kbpk 3235362D62697420414553207772617070696E67202849534F20323030333829 --export 1273671EA26AC29AFA4D1084127652A1 --export-template IK --export-format-version E --export-key-algorithm AES --export-opt-block-IK 1234567890123456 --export-opt-block-KC --export-opt-block-KP --export-no-key-length-obfuscation --export-zero-opt-block-PB
				PASS_REGULAR_EXPRESSION "^E0148B1AX00N0400IK141234567890123456KC100105EF4531ECKP10019E357FBF09PB0C00000000AB37D3FD2A840B095AAD50173A1B05EFBFD4384D37BCD9EDAB93C7D4EA6127EFEE89"
		)

		add_test(NAME dukpt_tool_tr31_test4
			COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00000 --derive-ik --output-tr31 3235362D62697420414553207772617070696E67202849534F20323030333829 --output-tr31-format-version E --output-tr31-with-ksn --output-tr31-with-kc --output-tr31-with-kp
		)
		set_tests_properties(dukpt_tool_tr31_test4
			PROPERTIES
				# tr31-tool --kbpk 3235362D62697420414553207772617070696E67202849534F20323030333829 --export 6AC292FAA1315B4D858AB3A3D7D5933A --export-template IK --export-format-version E --export-key-algorithm TDES --export-opt-block-KS FFFF9876543210E00000 --export-opt-block-KC --export-opt-block-KP --export-no-key-length-obfuscation --export-zero-opt-block-PB
				PASS_REGULAR_EXPRESSION "^E0148B1TX00N0400KC0C00AF8C07KP10019E357FBF09KS18FFFF9876543210E00000PB0C000000006335F66CA18FB2439585B40D854907AEFDC534FEE2C4EAE1966F24E04EEE8D5D398C"
		)

		add_test(NAME dukpt_tool_tr31_test5
			COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00000 --derive-ik --output-tr31 3235362D62697420414553207772617070696E67202849534F20323030333829 --output-tr31-format-version E --output-tr31-with-ksn --output-tr31-with-kc --output-tr31-with-kp --output-tr31-with-lb "My Amazing BDK"
		)
		set_tests_properties(dukpt_tool_tr31_test5
			PROPERTIES
				# tr31-tool --kbpk 3235362D62697420414553207772617070696E67202849534F20323030333829 --export 6AC292FAA1315B4D858AB3A3D7D5933A --export-template IK --export-format-version E --export-key-algorithm TDES --export-opt-block-KS FFFF9876543210E00000 --export-opt-block-KC --export-opt-block-KP --export-opt-block-LB "My Amazing BDK" --export-no-key-length-obfuscation --export-zero-opt-block-PB
				PASS_REGULAR_EXPRESSION "^E0164B1TX00N0500KC0C00AF8C07KP10019E357FBF09KS18FFFF9876543210E00000LB12My Amazing BDKPB0A000000D6F9D74BAB9526E111E5E74BB34FB77305DF6C2B7AFF96D8FA36916B32C24318F108"
		)

		add_test(NAME dukpt_tool_tr31_test6
			COMMAND dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00000 --derive-ik --output-tr31 3235362D62697420414553207772617070696E67202849534F20323030333829 --output-tr31-format-version E --output-tr31-with-ksn --output-tr31-with-kc --output-tr31-with-kp --output-tr31-with-lb "My Amazing BDK" --output-tr31-with-ts
		)
		set_tests_properties(dukpt_tool_tr31_test6
			PROPERTIES
				# tr31-tool --kbpk 3235362D62697420414553207772617070696E67202849534F20323030333829 --export 6AC292FAA1315B4D858AB3A3D7D5933A --export-template IK --export-format-version E --export-key-algorithm TDES --export-opt-block-KS FFFF9876543210E00000 --export-opt-block-KC --export-opt-block-KP --export-opt-block-LB My\ Amazing\ BDK --export-opt-block-TS now --export-no-key-length-obfuscation --export-zero-opt-block-PB
				PASS_REGULAR_EXPRESSION "^E0180B1TX00N0600KC0C00AF8C07KP10019E357FBF09KS18FFFF9876543210E00000LB12My Amazing BDKTS13..............ZPB07000" # Only match header due to time stamp
		)
	endif()
endif()
