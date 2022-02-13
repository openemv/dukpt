##############################################################################
# Copyright (c) 2021, 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
find_package(MbedTLS 2.16 REQUIRED) # Latest version available on Ubuntu 20.04 and Fedora 34

# Check whether compiler supports __builtin_popcount()
include(CheckCSourceCompiles)
check_c_source_compiles("int main(void) { return __builtin_popcount(42); }" HAS_BUILTIN_POPCOUNT)

include(GNUInstallDirs) # Provides CMAKE_INSTALL_* variables and good defaults for install()

# Generate config file for internal use only
# This file should NOT be installed or used by an installed header
configure_file(
	dukpt_config.h.in
	dukpt_config.h
)

# Internal TDES crypto library
add_library(dukpt_tdes_crypto OBJECT dukpt_tdes_crypto.c dukpt_mem.c)
set_target_properties(dukpt_tdes_crypto
	PROPERTIES
		C_VISIBILITY_PRESET hidden
)
target_include_directories(dukpt_tdes_crypto PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # for generated config file
target_include_directories(dukpt_tdes_crypto INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
target_link_libraries(dukpt_tdes_crypto PUBLIC MbedTLS::mbedcrypto)

# TDES DUKPT library
add_library(dukpt_tdes dukpt_tdes.c)
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
target_link_libraries(dukpt_tdes PRIVATE dukpt_tdes_crypto)

# Internal AES crypto library
add_library(dukpt_aes_crypto OBJECT dukpt_aes_crypto.c dukpt_mem.c)
set_target_properties(dukpt_aes_crypto
	PROPERTIES
		C_VISIBILITY_PRESET hidden
)
target_include_directories(dukpt_aes_crypto PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # for generated config file
target_include_directories(dukpt_aes_crypto INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
)
target_link_libraries(dukpt_aes_crypto PUBLIC MbedTLS::mbedcrypto)

# AES DUKPT library
add_library(dukpt_aes dukpt_aes.c)
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
target_link_libraries(dukpt_aes PRIVATE dukpt_aes_crypto)

# DUKPT command line tool
add_executable(dukpt-tool dukpt-tool.c)
target_link_libraries(dukpt-tool dukpt_tdes dukpt_aes)

install(
	TARGETS
		dukpt_tdes
		dukpt_tdes_crypto
		dukpt_aes
		dukpt_aes_crypto
		dukpt-tool
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

if(BUILD_TESTING)
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
endif()
