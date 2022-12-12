##############################################################################
# Copyright (c) 2022 Leon Lynch
#
# This file is licensed under the terms of the GPL v3 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

project(dukpt-ui
	VERSION 0.2.3
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

# Generate config file for internal use only
# This file should NOT be installed or used by an installed header
if(NOT DUKPT_VERSION_STRING)
	set(DUKPT_VERSION_STRING ${dukpt-ui_VERSION})
endif()
configure_file(
	dukpt_ui_config.h.in
	dukpt_ui_config.h
)

find_package(Qt5 5.12 COMPONENTS Widgets REQUIRED)
find_package(tr31 0.4.5 REQUIRED)

if(Qt5_VERSION VERSION_LESS 5.15)
	# Qt-5.12 provides these versioned commands
	qt5_wrap_ui(UI_SRCS mainwindow.ui)
	qt5_wrap_cpp(MOC_SRCS mainwindow.h validators.h)
	qt5_add_resources(QRC_SRCS icons.qrc)
	add_library(Qt::Widgets ALIAS Qt5::Widgets)
else()
	# Qt-5.15 and Qt-6 provide these version-less commands
	qt_wrap_ui(UI_SRCS mainwindow.ui)
	qt_wrap_cpp(MOC_SRCS mainwindow.h validators.h)
	qt_add_resources(QRC_SRCS icons.qrc)
endif()

add_executable(dukpt-ui dukpt-ui.cpp mainwindow.cpp validators.cpp ${UI_SRCS} ${MOC_SRCS} ${QRC_SRCS})
target_include_directories(dukpt-ui PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # For generated files
target_link_libraries(dukpt-ui Qt::Widgets dukpt::dukpt_tdes dukpt::dukpt_aes tr31::tr31)

option(BUILD_MACOSX_BUNDLE "Build MacOS bundle containing dukpt-ui and dukpt-tool")
if(APPLE AND BUILD_MACOSX_BUNDLE)
	# Set properties needed for bundle applications on MacOS
	set_target_properties(
		dukpt-ui
		PROPERTIES
			MACOSX_BUNDLE TRUE
			MACOSX_BUNDLE_BUNDLE_NAME Dukpt
			MACOSX_BUNDLE_BUNDLE_VERSION ${CMAKE_PROJECT_VERSION}
			MACOSX_BUNDLE_SHORT_VERSION_STRING ${CMAKE_PROJECT_VERSION}
			MACOSX_BUNDLE_COPYRIGHT "Copyright (c) 2021, 2022 Leon Lynch"
			MACOSX_BUNDLE_GUI_IDENTIFIER org.openemv.${CMAKE_PROJECT_NAME}
			MACOSX_BUNDLE_ICON_FILE "openemv_dukpt.icns"
			RESOURCE icons/openemv_dukpt.icns
			OUTPUT_NAME Dukpt
	)

	# Add application icon for MacOS
	target_sources(dukpt-ui PRIVATE icons/openemv_dukpt.icns)

	# Install dukpt-ui symlink into bundle for MacOS
	install(CODE
		"execute_process(COMMAND \"${CMAKE_COMMAND}\" -E make_directory \"$<TARGET_BUNDLE_CONTENT_DIR:dukpt-ui>/bin/\")"
		COMPONENT dukpt_ui_bundle
	)
	install(CODE
		"execute_process(COMMAND \"${CMAKE_COMMAND}\" -E create_symlink \"../MacOS/$<TARGET_FILE_NAME:dukpt-ui>\" \"$<TARGET_BUNDLE_CONTENT_DIR:dukpt-ui>/bin/dukpt-ui\")"
		COMPONENT dukpt_ui_bundle
	)

	# Install README and LICENSE.gpl into bundle for MacOS
	if(EXISTS ${CMAKE_SOURCE_DIR}/README.md)
		install(FILES
			${CMAKE_SOURCE_DIR}/README.md
			COMPONENT dukpt_ui_bundle
			DESTINATION $<TARGET_BUNDLE_CONTENT_DIR:dukpt-ui>/doc/
		)
	endif()
	install(FILES
		${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.gpl
		COMPONENT dukpt_ui_bundle
		DESTINATION $<TARGET_BUNDLE_CONTENT_DIR:dukpt-ui>/doc/
	)

	# Install dukpt-tool into bundle for MacOS
	if(TARGET dukpt-tool)
		install(PROGRAMS
			$<TARGET_FILE:dukpt-tool>
			COMPONENT dukpt_ui_bundle
			DESTINATION $<TARGET_BUNDLE_CONTENT_DIR:dukpt-ui>/bin/
		)
	endif()

	# Deploy Qt into bundle for MacOS
	include(DeployQt)
	macdeployqt(dukpt-ui dukpt_ui_bundle)
endif()

if(WIN32)
	# Set properties needed for GUI applications on Windows
	set_target_properties(
		dukpt-ui
		PROPERTIES
			WIN32_EXECUTABLE TRUE
	)

	# Add application icon for Windows
	target_sources(dukpt-ui PRIVATE icon.rc)

	# Deploy Qt for Windows
	include(DeployQt)
	windeployqt(dukpt-ui dukpt_ui_runtime)

	# Install tr31 DLL library to DUKPT runtime, if necessary
	# NOTE: The tr31 DLL is installed to the DUKPT runtime, not the DUKPT UI
	# runtime, because the latter depends on the former and it should be
	# possible to install the former without the latter. It is implemented here
	# because when the GUI is not being built, it is assumed that tr31 will be
	# available in the PATH of the shell environment.
	get_target_property(tr31_TYPE tr31::tr31 TYPE)
	if(tr31_TYPE STREQUAL "SHARED_LIBRARY")
		if(${CMAKE_VERSION} VERSION_LESS "3.21")
			message(FATAL_ERROR "CMake >=3.21 is required to install on Windows when tr31 library is a DLL")
		endif()

		install(
			IMPORTED_RUNTIME_ARTIFACTS # NOTE: requires CMake >=3.21
				tr31::tr31
			RUNTIME
				COMPONENT dukpt_runtime
		)
	endif()

	# Deploy runtime libraries for Windows
	set(CMAKE_INSTALL_SYSTEM_RUNTIME_COMPONENT dukpt_ui_runtime)
	include(InstallRequiredSystemLibraries)
	if(CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS)
		message(STATUS "Required system libraries: ${CMAKE_INSTALL_SYSTEM_RUNTIME_LIBS}")
	endif()
endif()

# Install LICENSE.gpl file to UI runtime component
install(FILES
	${CMAKE_CURRENT_SOURCE_DIR}/LICENSE.gpl
	TYPE DOC
	COMPONENT dukpt_ui_runtime
)

if(NOT APPLE AND NOT WIN32)
	# Install icon file to UI runtime component for Linux
	set(DUKPT_INSTALL_ICONSDIR ${CMAKE_INSTALL_DATADIR}/icons/hicolor/512x512/apps CACHE STRING "Installation location for dukpt-ui icon files")
	install(FILES
		${CMAKE_CURRENT_SOURCE_DIR}/icons/openemv_dukpt_512x512.png
		DESTINATION ${DUKPT_INSTALL_ICONSDIR}
		COMPONENT dukpt_ui_runtime
		RENAME dukpt-ui.png
	)

	# Install desktop entry file to UI runtime component for Linux
	set(DUKPT_INSTALL_DESKTOPENTRYDIR ${CMAKE_INSTALL_DATADIR}/applications CACHE STRING "Installation location for dukpt-ui desktop entry files")
	install(FILES
		${CMAKE_CURRENT_SOURCE_DIR}/dukpt-ui.desktop
		DESTINATION ${DUKPT_INSTALL_DESKTOPENTRYDIR}
		COMPONENT dukpt_ui_runtime
	)

	# Install appstream file to UI runtime component for Linux
	set(DUKPT_INSTALL_APPSTREAMDIR ${CMAKE_INSTALL_DATADIR}/metainfo CACHE STRING "Installation location for dukpt-ui appstream files")
	install(FILES
		${CMAKE_CURRENT_SOURCE_DIR}/dukpt-ui.appdata.xml
		DESTINATION ${DUKPT_INSTALL_APPSTREAMDIR}
		COMPONENT dukpt_ui_runtime
	)
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

# Sign bundle using the specified identity
option(SIGN_MACOSX_BUNDLE "Sign MacOS bundle using the specified identity (use - for ad-hoc signing)")
if(APPLE AND BUILD_MACOSX_BUNDLE AND SIGN_MACOSX_BUNDLE)
	find_program(CODESIGN_EXECUTABLE codesign)
	if(NOT CODESIGN_EXECUTABLE)
		message(FATAL_ERROR "codesign not found")
	endif()

	# When using install(CODE) instead of CPACK_PRE_BUILD_SCRIPTS to sign
	# the bundle, it must always be the last install() command to ensure
	# that all of the bundle files are already present
	install(CODE
		"
		if(TARGET dukpt-tool)
			message(STATUS \"Using identity '${SIGN_MACOSX_BUNDLE}' to sign binary at \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\$<TARGET_BUNDLE_DIR_NAME:dukpt-ui>/Contents/dukpt-tool\")
			execute_process(COMMAND ${CODESIGN_EXECUTABLE} --sign \"${SIGN_MACOSX_BUNDLE}\" --deep \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\$<TARGET_BUNDLE_DIR_NAME:dukpt-ui>/Contents/dukpt-tool\")
			execute_process(COMMAND ${CODESIGN_EXECUTABLE} --display --verbose --verbose=4 \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\$<TARGET_BUNDLE_DIR_NAME:dukpt-ui>/Contents/dukpt-tool\")
			execute_process(COMMAND ${CODESIGN_EXECUTABLE} --verify --verbose --deep \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\$<TARGET_BUNDLE_DIR_NAME:dukpt-ui>/Contents/dukpt-tool\")
		endif()
		message(STATUS \"Using identity '${SIGN_MACOSX_BUNDLE}' to sign bundle at \$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\$<TARGET_BUNDLE_DIR_NAME:dukpt-ui>\")
		execute_process(COMMAND ${CODESIGN_EXECUTABLE} --sign \"${SIGN_MACOSX_BUNDLE}\" --deep \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\$<TARGET_BUNDLE_DIR_NAME:dukpt-ui>\")
		execute_process(COMMAND ${CODESIGN_EXECUTABLE} --display --verbose --verbose=4 \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\$<TARGET_BUNDLE_DIR_NAME:dukpt-ui>\")
		execute_process(COMMAND ${CODESIGN_EXECUTABLE} --verify --verbose --deep \"\$ENV{DESTDIR}\${CMAKE_INSTALL_PREFIX}/\$<TARGET_BUNDLE_DIR_NAME:dukpt-ui>\")
		"
		COMPONENT dukpt_ui_bundle
	)
endif()
