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
			env PATH="${_qt_bin_dir}" "${WINDEPLOYQT_EXECUTABLE}"
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

	# Install additional Qt dependencies
	if(MINGW)
		# NOTE: These libraries are required by MSYS2's build of Qt for MinGW
		# and are in the PATH where windeployqt expects to find them, but it's
		# unclear why windeployqt refuses to copy them. If these dependencies
		# or their versions ever change, this must be updated accordingly.
		# NOTE: Use find_file() instead of find_library() because the latter is
		# intended to find linkable libraries, not DLLs.
		find_file(DOUBLE_CONVERSION_LIBRARY NAMES libdouble-conversion.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBICUIN_LIBRARY NAMES libicuin71.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBICUUC_LIBRARY NAMES libicuuc71.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBICUDT_LIBRARY NAMES libicudt71.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBPCRE2_16_LIBRARY NAMES libpcre2-16-0.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBPCRE2_8_LIBRARY NAMES libpcre2-8-0.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(ZLIB_LIBRARY NAMES zlib1.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBZSTD_LIBRARY NAMES libzstd.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBHARFBUZZ_LIBRARY NAMES libharfbuzz-0.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBMD4C_LIBRARY NAMES libmd4c.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBPNG_LIBRARY NAMES libpng16-16.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBFREETYPE_LIBRARY NAMES libfreetype-6.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBGLIB_LIBRARY NAMES libglib-2.0-0.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBGRAPHITE_LIBRARY NAMES libgraphite2.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBINTL_LIBRARY NAMES libintl-8.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBBZ2_LIBRARY NAMES libbz2-1.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBICONV_LIBRARY NAMES libiconv-2.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBBROTLIDEC_LIBRARY NAMES libbrotlidec.dll PATHS "${_qt_bin_dir}" REQUIRED)
		find_file(LIBBROTLICOMMON_LIBRARY NAMES libbrotlicommon.dll PATHS "${_qt_bin_dir}" REQUIRED)
		install(FILES
			${DOUBLE_CONVERSION_LIBRARY}
			${LIBICUIN_LIBRARY}
			${LIBICUUC_LIBRARY}
			${LIBICUDT_LIBRARY}
			${LIBPCRE2_16_LIBRARY}
			${LIBPCRE2_8_LIBRARY}
			${ZLIB_LIBRARY}
			${LIBZSTD_LIBRARY}
			${LIBHARFBUZZ_LIBRARY}
			${LIBMD4C_LIBRARY}
			${LIBPNG_LIBRARY}
			${LIBFREETYPE_LIBRARY}
			${LIBGLIB_LIBRARY}
			${LIBGRAPHITE_LIBRARY}
			${LIBINTL_LIBRARY}
			${LIBBZ2_LIBRARY}
			${LIBICONV_LIBRARY}
			${LIBBROTLIDEC_LIBRARY}
			${LIBBROTLICOMMON_LIBRARY}
			TYPE BIN
			COMPONENT ${component}
		)
	endif()
endfunction()

mark_as_advanced(MACDEPLOYQT_EXECUTABLE WINDEPLOYQT_EXECUTABLE)
