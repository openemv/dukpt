##############################################################################
# Copyright (c) 2021 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
find_package(MbedTLS 2.16 REQUIRED) # Latest version available on Ubuntu 20.04 and Fedora 34

include(GNUInstallDirs) # Provides CMAKE_INSTALL_* variables and good defaults for install()

# Generate config file for internal use only
# This file should NOT be installed or used by an installed header
configure_file(
	dukpt_config.h.in
	dukpt_config.h
)

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
target_link_libraries(dukpt_tdes MbedTLS::mbedcrypto)

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

add_executable(dukpt-tool dukpt-tool.c)
target_link_libraries(dukpt-tool dukpt_tdes dukpt_aes)

install(TARGETS dukpt_tdes dukpt_aes dukpt-tool
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
endif()
