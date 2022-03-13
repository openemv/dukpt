##############################################################################
# Copyright (c) 2021, 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

project(dukpt
	VERSION 0.0.1
	DESCRIPTION "DUKPT library and tools"
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
if (CMAKE_COMPILER_IS_GNUCC OR CMAKE_COMPILER_IS_GNUCXX)
	add_compile_options(-Wall -Werror)
	set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -ggdb")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -ggdb")
endif()

include(CTest)

add_subdirectory(src)
add_subdirectory(test)

include(GNUInstallDirs) # Provides CMAKE_INSTALL_* variables and good defaults for install()

# Generate and install basic CMake config files
include(CMakePackageConfigHelpers) # Provides CMake config generator macros
foreach(pkg IN LISTS DUKPT_PACKAGE_DEPENDENCIES)
	# Build dependency string for use in CMake config file
	string(APPEND DUKPT_CONFIG_PACKAGE_DEPENDENCIES "find_dependency(${pkg})\n")
endforeach()
set(DUKPT_INSTALL_CMAKEDIR ${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME} CACHE STRING "Installation location for dukpt CMake config files")
message(STATUS "Using CMake config install location \"${DUKPT_INSTALL_CMAKEDIR}\"")
configure_package_config_file(cmake/dukptConfig.cmake.in
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/dukptConfig.cmake"
	INSTALL_DESTINATION "${DUKPT_INSTALL_CMAKEDIR}"
)
write_basic_package_version_file(
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/dukptConfigVersion.cmake"
	COMPATIBILITY AnyNewerVersion
)
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/dukptConfig.cmake"
	"${CMAKE_CURRENT_BINARY_DIR}/cmake/dukptConfigVersion.cmake"
	DESTINATION "${DUKPT_INSTALL_CMAKEDIR}"
	COMPONENT dukpt_development
)
install(EXPORT dukptTargets
	FILE dukptTargets.cmake
	DESTINATION "${DUKPT_INSTALL_CMAKEDIR}"
	NAMESPACE dukpt::
	COMPONENT dukpt_development
)
export(EXPORT dukptTargets
	FILE "${CMAKE_CURRENT_BINARY_DIR}/cmake/dukptTargets.cmake"
	NAMESPACE dukpt::
)

# Generate and install pkgconfig files
set(DUKPT_INSTALL_PKGCONFIG_DIR ${CMAKE_INSTALL_LIBDIR}/pkgconfig CACHE STRING "Installation location for dukpt pkgconfig files")
message(STATUS "Using pkgconfig install location \"${DUKPT_INSTALL_PKGCONFIG_DIR}\"")
# NOTE: Subdirectories will provide DUKPT_PKGCONFIG_REQ_PRIV and DUKPT_PKGCONFIG_LIBS_PRIV
set(DUKPT_PKGCONFIG_LIB_NAME dukpt_tdes)
configure_file(pkgconfig/libdukpt_tdes.pc.in
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libdukpt_tdes.pc"
	@ONLY
)
set(DUKPT_PKGCONFIG_LIB_NAME dukpt_aes)
configure_file(pkgconfig/libdukpt_aes.pc.in
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libdukpt_aes.pc"
	@ONLY
)
install(FILES
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libdukpt_tdes.pc"
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libdukpt_aes.pc"
	DESTINATION "${DUKPT_INSTALL_PKGCONFIG_DIR}"
	COMPONENT dukpt_development
)

# Install bash-completion file
find_package(bash-completion) # Optional for providing bash-completion files
if(BASH_COMPLETION_FOUND)
	set(DUKPT_INSTALL_BASH_COMPLETION_DIR ${CMAKE_INSTALL_DATADIR}/bash-completion/completions CACHE STRING "Installation location for dukpt bash-completion files")
	message(STATUS "Using bash-completion install location \"${DUKPT_INSTALL_BASH_COMPLETION_DIR}\"")

	# Install bash completion file
	install(FILES
		"${CMAKE_CURRENT_SOURCE_DIR}/bash-completion/dukpt-tool"
		DESTINATION "${DUKPT_INSTALL_BASH_COMPLETION_DIR}"
		COMPONENT dukpt_runtime
	)
endif()

# Build and install doxygen documentation
option(BUILD_DOCS "Build documentation")
find_package(Doxygen) # Optional for generating doxygen files
if(Doxygen_FOUND)
	# Use doxygen to generate HTML
	set(DOXYGEN_GENERATE_HTML YES)

	# Generate docs for public headers
	if(BUILD_DOCS)
		doxygen_add_docs(docs
			dukpt_tdes.h
			dukpt_aes.h
			ALL # Build by default
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src"
		)

		# Install generated docs by default
		install(
			DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/html
			TYPE DOC
			COMPONENT dukpt_docs
		)
	else()
		doxygen_add_docs(docs
			dukpt_tdes.h
			dukpt_aes.h
			WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}/src"
		)
	endif()
endif()
