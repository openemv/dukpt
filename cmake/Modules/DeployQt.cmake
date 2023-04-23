##############################################################################
# Copyright (c) 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
#
# This file was inspired by:
# * https://github.com/nitroshare/nitroshare-desktop/blob/master/cmake/DeployQt.cmake
# * https://github.com/miurahr/cmake-qt-packaging-example/blob/master/Packaging.cmake
#
##############################################################################

find_package(Qt5Core REQUIRED)

# Find Qt installation
get_target_property(_qmake_executable Qt5::qmake IMPORTED_LOCATION)
get_filename_component(_qt_bin_dir "${_qmake_executable}" DIRECTORY)

find_program(MACDEPLOYQT_EXECUTABLE macdeployqt HINTS "${_qt_bin_dir}")
if(APPLE AND NOT MACDEPLOYQT_EXECUTABLE)
	message(FATAL_ERROR "macdeployqt not found")
endif()

find_program(WINDEPLOYQT_EXECUTABLE windeployqt HINTS "${_qt_bin_dir}")
if(WIN32 AND NOT WINDEPLOYQT_EXECUTABLE)
	message(FATAL_ERROR "windeployqt not found")
endif()

function(macdeployqt target component)
	add_custom_command(TARGET ${target} POST_BUILD
		COMMAND "${MACDEPLOYQT_EXECUTABLE}"
			\"$<TARGET_BUNDLE_DIR:${target}>\"
			-verbose=1
			-always-overwrite
		COMMENT "Deploying Qt..."
	)
endfunction()

function(windeployqt target component)
	# Deploy Qt to output directory from where it can be installed to a component
	add_custom_command(TARGET ${target} POST_BUILD
		COMMAND "${CMAKE_COMMAND}" -E remove_directory "${CMAKE_CURRENT_BINARY_DIR}/qt-bin/"
		COMMAND "${CMAKE_COMMAND}" -E
			env PATH="${_qt_bin_dir}$<SEMICOLON>%PATH%" "${WINDEPLOYQT_EXECUTABLE}"
			--verbose 3
			--compiler-runtime
			--no-translations
			--no-webkit2
			--no-angle
			--no-opengl-sw
			--dir "${CMAKE_CURRENT_BINARY_DIR}/qt-bin/"
			$<TARGET_FILE:${target}>
		COMMENT "Deploying Qt..."
	)

	# Install Qt to the appropriate CMake component
	install(
		DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/qt-bin/"
		TYPE BIN
		COMPONENT ${component}
	)
endfunction()

mark_as_advanced(MACDEPLOYQT_EXECUTABLE WINDEPLOYQT_EXECUTABLE)
