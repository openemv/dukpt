##############################################################################
# Copyright (c) 2021, 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

project(dukpt
	VERSION 0.2.0
	DESCRIPTION "DUKPT libraries and tools"
	HOMEPAGE_URL "https://github.com/openemv/dukpt"
	LANGUAGES C
)

# Determine whether this project is the top-level project
if(${CMAKE_VERSION} VERSION_LESS "3.21")
	get_directory_property(DUKPT_HAS_PARENT PARENT_DIRECTORY)
	if(NOT DUKPT_HAS_PARENT)
		set(DUKPT_IS_TOP_LEVEL True)
	endif()
else()
	# CMake >=3.21 provides <PROJECT-NAME>_IS_TOP_LEVEL
	set(DUKPT_IS_TOP_LEVEL ${dukpt_IS_TOP_LEVEL})
endif()

# Configure compiler
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_EXTENSIONS OFF)
if(CMAKE_C_COMPILER_ID STREQUAL "GNU")
	add_compile_options(-Wall)
	add_compile_options($<$<CONFIG:Debug>:-ggdb>)
	add_compile_options($<$<CONFIG:RelWithDebInfo>:-ggdb>)
endif()

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake/Modules/")

# Configure testing before adding subdirectories
if(DUKPT_IS_TOP_LEVEL)
	# Configure Valgrind before including CTest module
	find_program(VALGRIND_COMMAND valgrind)
	set(MEMORYCHECK_TYPE Valgrind)
	set(VALGRIND_COMMAND_OPTIONS "--leak-check=full --show-reachable=yes --track-origins=yes --num-callers=100 --show-error-list=yes")

	# Only top-level project should include CTest module
	include(CTest)
endif()

# Allow parent scope to provide crypto targets when not building shared libs
if(DUKPT_IS_TOP_LEVEL OR BUILD_SHARED_LIBS)
	add_subdirectory(crypto)
	add_subdirectory(crypto/test)
	set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/crypto/cmake/Modules/")
elseif (NOT TARGET crypto_tdes OR
	NOT TARGET crypto_aes OR
	NOT TARGET crypto_hmac OR
	NOT TARGET crypto_mem OR
	NOT TARGET crypto_rand)
	message(FATAL_ERROR "Parent project must provide crypto libraries for static builds")
endif()

# Allow parent scope to provide pinblock target when not building shared libs
if(DUKPT_IS_TOP_LEVEL OR BUILD_SHARED_LIBS)
	add_subdirectory(pinblock)
	add_subdirectory(pinblock/test)
elseif (NOT TARGET pinblock)
	message(FATAL_ERROR "Parent project must provide pinblock library for static builds")
endif()

add_subdirectory(src)
add_subdirectory(test)

# If Qt::Widgets and tr31 are available, build dukpt-ui
find_package(Qt5 5.15 COMPONENTS Widgets QUIET)
if(Qt5Widgets_FOUND)
	message(STATUS "Found Qt5 Widgets: found suitable version \"${Qt5_VERSION}\"")
else()
	message(STATUS "Could NOT find Qt5 Widgets: skipping dukpt-ui build")
endif()
find_package(tr31 0.4.2 QUIET)
if(NOT tr31_FOUND)
	message(STATUS "Could NOT find tr31: skipping dukpt-ui build")
endif()
if(Qt5Widgets_FOUND AND tr31_FOUND)
	add_subdirectory(ui)
endif()

include(GNUInstallDirs) # Provides CMAKE_INSTALL_* variables and good defaults for install()

# Install README and LICENSE files to runtime component
install(FILES
	"${CMAKE_CURRENT_SOURCE_DIR}/README.md"
	"${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
	TYPE DOC
	COMPONENT dukpt_runtime
)

# Generate and install basic CMake config files
include(CMakePackageConfigHelpers) # Provides CMake config generator macros
# NOTE: crypto subdirectory provides CRYPTO_PACKAGE_DEPENDENCIES
foreach(pkg IN LISTS CRYPTO_PACKAGE_DEPENDENCIES)
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
set(DUKPT_PKGCONFIG_LIB_NAME dukpt_tdes)
# NOTE: crypto subdirectory provides CRYPTO_PKGCONFIG_REQ_PRIV and CRYPTO_PKGCONFIG_LIBS_PRIV
set(DUKPT_PKGCONFIG_REQ_PRIV ${CRYPTO_PKGCONFIG_REQ_PRIV})
set(DUKPT_PKGCONFIG_LIBS_PRIV ${CRYPTO_PKGCONFIG_LIBS_PRIV})
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

# Configure CPack to generate .tgz package
set(CPACK_GENERATOR "TGZ")
set(CPACK_PACKAGE_VENDOR "OpenEMV")
set(CPACK_PACKAGE_CONTACT "lynch.leon@gmail.com")
set(CPACK_PACKAGE_DESCRIPTION_FILE "${CMAKE_CURRENT_SOURCE_DIR}/README.md")
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE")
set(CPACK_RESOURCE_FILE_README "${CMAKE_CURRENT_SOURCE_DIR}/README.md")

# Configure generic component packaging attributes
set(CPACK_COMPONENT_DUKPT_DEVELOPMENT_DESCRIPTION "Development files for DUKPT libraries")
set(CPACK_COMPONENT_DUKPT_DOCS_DESCRIPTION "Documentation for DUKPT libraries")
set(CPACK_COMPONENT_DUKPT_DEVELOPMENT_DEPENDS dukpt_runtime)

# NOTE: for monolithic packages, uncomment the line below or specify it when
# invoking CMake
#set(CPACK_COMPONENTS_GROUPING ALL_COMPONENTS_IN_ONE)

find_package(dpkg) # Optional for building Debian/Ubuntu packages
if(dpkg_FOUND)
	# Configure CPack to generate .deb package
	list(APPEND CPACK_GENERATOR "DEB")
	# Generate component packages
	# NOTE: This is overridden by CPACK_COMPONENTS_GROUPING above
	set(CPACK_DEB_COMPONENT_INSTALL ON)
	set(CPACK_DEBIAN_ENABLE_COMPONENT_DEPENDS ON)
	# Use default debian package naming
	set(CPACK_DEBIAN_FILE_NAME "DEB-DEFAULT")
	# Assign package names to components
	set(CPACK_DEBIAN_DUKPT_RUNTIME_PACKAGE_NAME "dukpt-runtime")
	set(CPACK_DEBIAN_DUKPT_DEVELOPMENT_PACKAGE_NAME "dukpt-dev")
	set(CPACK_DEBIAN_DUKPT_DOCS_PACKAGE_NAME "dukpt-doc")
	# Assign package architecture to documentation component
	set(CPACK_DEBIAN_DUKPT_DOCS_PACKAGE_ARCHITECTURE "all")
	# Assign package sections to components
	set(CPACK_DEBIAN_DUKPT_RUNTIME_PACKAGE_SECTION "utils")
	set(CPACK_DEBIAN_DUKPT_DEVELOPMENT_PACKAGE_SECTION "devel")
	set(CPACK_DEBIAN_DUKPT_DOCS_PACKAGE_SECTION "doc")
	# Assign package suggestions
	set(CPACK_DEBIAN_DUKPT_DOCS_PACKAGE_SUGGESTS "dukpt-dev")
	# Generate package dependency list
	set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
endif()

find_package(rpmbuild) # Optional for building RedHat/Fedora packages
if(rpmbuild_FOUND)
	list(APPEND CPACK_GENERATOR "RPM")
	# Generate component packages
	# NOTE: This is overridden by CPACK_COMPONENTS_GROUPING above
	set(CPACK_RPM_COMPONENT_INSTALL ON)
	# Use default rpm package naming
	set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
	# Configure license and changelog
	set(CPACK_RPM_PACKAGE_LICENSE "LGPLv2+")
	set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/rpm_changelog.txt")
	# Assign package names to components
	set(CPACK_RPM_DUKPT_RUNTIME_PACKAGE_NAME "dukpt-runtime")
	set(CPACK_RPM_DUKPT_DEVELOPMENT_PACKAGE_NAME "dukpt-devel")
	set(CPACK_RPM_DUKPT_DOCS_PACKAGE_NAME "dukpt-doc")
	# Assign package architecture to documentation component
	set(CPACK_RPM_DUKPT_DOCS_PACKAGE_ARCHITECTURE "noarch")
	# Assign package suggestions
	set(CPACK_RPM_DUKPT_DOCS_PACKAGE_SUGGESTS "dukpt-devel")
	# NOTE: RPM generator automatically detects dependencies
endif()

include(CPack)
