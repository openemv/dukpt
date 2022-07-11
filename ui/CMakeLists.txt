##############################################################################
# Copyright (c) 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

project(dukpt-ui
	VERSION 0.2.0
	DESCRIPTION "DUKPT User Interface using Qt"
	HOMEPAGE_URL "https://github.com/openemv/dukpt"
	LANGUAGES C CXX
)

# Determine whether this project is the top-level project
if(${CMAKE_VERSION} VERSION_LESS "3.21")
	get_directory_property(DUKPT_UI_HAS_PARENT PARENT_DIRECTORY)
	if(NOT DUKPT_UI_HAS_PARENT)
		set(DUKPT_UI_IS_TOP_LEVEL True)
	endif()
else()
	# CMake >=3.21 provides <PROJECT-NAME>_IS_TOP_LEVEL
	set(DUKPT_UI_IS_TOP_LEVEL ${dukpt-ui_IS_TOP_LEVEL})
endif()

# Configure compiler
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_EXTENSIONS OFF)
if(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
	add_compile_options(-Wall)
	add_compile_options($<$<CONFIG:Debug>:-ggdb>)
	add_compile_options($<$<CONFIG:RelWithDebInfo>:-ggdb>)
endif()

find_package(Qt5 5.15 COMPONENTS Widgets REQUIRED)
add_executable(dukpt-ui dukpt-ui.cpp)
target_link_libraries(dukpt-ui Qt::Widgets)

install(
	TARGETS
		dukpt-ui
	EXPORT dukptTargets # For use by install(EXPORT) command
	RUNTIME
		COMPONENT dukpt_ui_runtime
)