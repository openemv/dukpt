##############################################################################
# Copyright (c) 2021 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

include(GNUInstallDirs) # Provides CMAKE_INSTALL_* variables and good defaults for install()

add_library(dukpt_tdes dukpt_tdes.c)
set_target_properties(dukpt_tdes
	PROPERTIES
		PUBLIC_HEADER dukpt_tdes.h
		VERSION ${CMAKE_PROJECT_VERSION}
		SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
target_include_directories(dukpt_tdes INTERFACE
	$<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
	$<INSTALL_INTERFACE:include/${PROJECT_NAME}>
)

add_library(dukpt_aes dukpt_aes.c)
set_target_properties(dukpt_aes
	PROPERTIES
		PUBLIC_HEADER dukpt_aes.h
		VERSION ${CMAKE_PROJECT_VERSION}
		SOVERSION ${CMAKE_PROJECT_VERSION_MAJOR}
)
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
