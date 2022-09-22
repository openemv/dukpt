##############################################################################
# Copyright (c) 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

project(dukpt-ui
	VERSION 0.2.2
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

if(DUKPT_UI_IS_TOP_LEVEL)
	# If this is the top-level project, it will need CMake modules provided by
	# the crypto sub-module
	set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/../crypto/cmake/Modules/")

	# If this is the top-level project, look for the platform dukpt libraries
	find_package(dukpt 0.2.0 REQUIRED)
else()
	# Otherwise the parent project must provide the dukpt targets
	if(NOT TARGET dukpt::dukpt_tdes OR NOT TARGET dukpt::dukpt_aes)
		message(FATAL_ERROR "Parent project must provide dukpt libraries")
	endif()
endif()

include(GNUInstallDirs) # Provides CMAKE_INSTALL_* variables and good defaults for install()

find_package(Qt5 5.12 COMPONENTS Widgets REQUIRED)
find_package(tr31 0.4.3 REQUIRED)

if(Qt5_VERSION VERSION_LESS 5.15)
	# Qt-5.12 provides these versioned commands
	qt5_wrap_ui(UI_SRCS mainwindow.ui)
	qt5_wrap_cpp(MOC_SRCS mainwindow.h validators.h)
	add_library(Qt::Widgets ALIAS Qt5::Widgets)
else()
	# Qt-5.15 and Qt-6 provide these version-less commands
	qt_wrap_ui(UI_SRCS mainwindow.ui)
	qt_wrap_cpp(MOC_SRCS mainwindow.h validators.h)
endif()

add_executable(dukpt-ui dukpt-ui.cpp mainwindow.cpp validators.cpp ${UI_SRCS} ${MOC_SRCS})
target_include_directories(dukpt-ui PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # For generated files
target_link_libraries(dukpt-ui Qt::Widgets dukpt::dukpt_tdes dukpt::dukpt_aes tr31::tr31)

option(BUILD_MACOSX_BUNDLE "Build MacOS bundle containing dukpt-ui")
if(APPLE AND BUILD_MACOSX_BUNDLE)
	# Set properties needed for bundle applications on MacOS
	set_target_properties(
		dukpt-ui
		PROPERTIES
			MACOSX_BUNDLE TRUE
			MACOSX_BUNDLE_BUNDLE_NAME ${CMAKE_PROJECT_NAME}
			MACOSX_BUNDLE_BUNDLE_VERSION ${CMAKE_PROJECT_VERSION}
			MACOSX_BUNDLE_SHORT_VERSION_STRING ${CMAKE_PROJECT_VERSION}
			MACOSX_BUNDLE_COPYRIGHT "Copyright (c) 2021, 2022 Leon Lynch"
			MACOSX_BUNDLE_GUI_IDENTIFIER org.openemv.${CMAKE_PROJECT_NAME}
	)

	# Install README and LICENSE into bundle for MacOS
	if(EXISTS ${CMAKE_SOURCE_DIR}/README.md AND EXISTS ${CMAKE_SOURCE_DIR}/LICENSE)
		install(FILES
			${CMAKE_SOURCE_DIR}/README.md
			${CMAKE_SOURCE_DIR}/LICENSE
			COMPONENT dukpt_ui_bundle
			DESTINATION $<TARGET_BUNDLE_CONTENT_DIR:dukpt-ui>/doc/
		)
	endif()
endif()

if(WIN32)
	# Set properties needed for GUI applications on Windows
	set_target_properties(
		dukpt-ui
		PROPERTIES
			WIN32_EXECUTABLE TRUE
	)

	# Deploy Qt for Windows
	include(DeployQt)
	windeployqt(dukpt-ui dukpt_ui_runtime)

	# Deploy runtime libraries for Windows
	set(CMAKE_INSTALL_SYSTEM_RUNTIME_COMPONENT dukpt_ui_runtime)
	include(InstallRequiredSystemLibraries)
	if(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS)
		message(STATUS "Required system libraries: ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS}")
	endif()
endif()

install(
	TARGETS
		dukpt-ui
	EXPORT dukptTargets # For use by install(EXPORT) command
	RUNTIME
		COMPONENT dukpt_ui_runtime
	BUNDLE
		COMPONENT dukpt_ui_bundle
		DESTINATION . # Install to root of MacOS bundle
)
