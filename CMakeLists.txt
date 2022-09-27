##############################################################################
# Copyright (c) 2021, 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

project(dukpt
	VERSION 0.2.2
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
option(BUILD_DUKPT_UI "Build dukpt-ui")
find_package(Qt5 5.12 COMPONENTS Widgets QUIET)
if(Qt5Widgets_FOUND)
	message(STATUS "Found Qt5 Widgets: found suitable version \"${Qt5_VERSION}\"")
else()
	if(BUILD_DUKPT_UI)
		message(FATAL_ERROR "Could NOT find Qt5 Widgets; required to build dukpt-ui")
	else()
		message(STATUS "Could NOT find Qt5 Widgets: skipping dukpt-ui build")
	endif()
endif()
find_package(tr31 0.4.3 QUIET)
if(NOT tr31_FOUND)
	if(BUILD_DUKPT_UI)
		message(FATAL_ERROR "Could NOT find tr31; required to build dukpt-ui")
	else()
		message(STATUS "Could NOT find tr31: skipping dukpt-ui build")
	endif()
endif()
if(Qt5Widgets_FOUND AND tr31_FOUND)
	message(STATUS "Adding dukpt-ui to build")
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
# NOTE: src subdirectory may provide DUKPT_PKGCONFIG_REQ_PRIV and DUKPT_PKGCONFIG_LIBS_PRIV
# NOTE: crypto subdirectory provides CRYPTO_PKGCONFIG_REQ_PRIV and CRYPTO_PKGCONFIG_LIBS_PRIV
string(APPEND DUKPT_PKGCONFIG_REQ_PRIV ${CRYPTO_PKGCONFIG_REQ_PRIV})
string(APPEND DUKPT_PKGCONFIG_LIBS_PRIV ${CRYPTO_PKGCONFIG_LIBS_PRIV})
# Generate pkgconfig for dukpt_tdes
set(DUKPT_PKGCONFIG_LIB_NAME dukpt_tdes)
configure_file(pkgconfig/libdukpt_tdes.pc.in
	"${CMAKE_CURRENT_BINARY_DIR}/pkgconfig/libdukpt_tdes.pc"
	@ONLY
)
# Generate pkgconfig for dukpt_aes
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
set(CPACK_COMPONENT_DUKPT_RUNTIME_DISPLAY_NAME "DUKPT tool and libraries")
set(CPACK_COMPONENT_DUKPT_RUNTIME_DESCRIPTION "DUKPT command line tool (dukpt-tool) and runtime libraries (dukpt_tdes and dukpt_aes)")
set(CPACK_COMPONENT_DUKPT_DEVELOPMENT_DISPLAY_NAME "DUKPT development files")
set(CPACK_COMPONENT_DUKPT_DEVELOPMENT_DESCRIPTION "Development files (headers, pkgconfig files, CMake config files, etc) for DUKPT libraries")
set(CPACK_COMPONENT_DUKPT_DOCS_DISPLAY_NAME "Documentation for DUKPT libraries")
set(CPACK_COMPONENT_DUKPT_DOCS_DESCRIPTION ${CPACK_COMPONENT_DUKPT_DOCS_DISPLAY_NAME})
set(CPACK_COMPONENT_DUKPT_UI_RUNTIME_DISPLAY_NAME "DUKPT UI")
set(CPACK_COMPONENT_DUKPT_UI_RUNTIME_DESCRIPTION "DUKPT graphical user interface (dukpt-ui)")
if(BUILD_SHARED_LIBS)
	set(CPACK_COMPONENT_DUKPT_DEVELOPMENT_DEPENDS dukpt_runtime)
	set(CPACK_COMPONENT_DUKPT_UI_RUNTIME_DEPENDS dukpt_runtime)
endif()

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
	set(CPACK_DEBIAN_DUKPT_UI_RUNTIME_PACKAGE_NAME "dukpt-ui")
	# Assign package architecture to documentation component
	set(CPACK_DEBIAN_DUKPT_DOCS_PACKAGE_ARCHITECTURE "all")
	# Assign package sections to components
	set(CPACK_DEBIAN_DUKPT_RUNTIME_PACKAGE_SECTION "utils")
	set(CPACK_DEBIAN_DUKPT_DEVELOPMENT_PACKAGE_SECTION "devel")
	set(CPACK_DEBIAN_DUKPT_DOCS_PACKAGE_SECTION "doc")
	set(CPACK_DEBIAN_DUKPT_UI_RUNTIME_PACKAGE_SECTION "x11")
	# Assign package suggestions
	set(CPACK_DEBIAN_DUKPT_DOCS_PACKAGE_SUGGESTS "dukpt-dev")
	# Generate package dependency list
	set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS ON)
	set(CPACK_DEBIAN_PACKAGE_SHLIBDEPS_PRIVATE_DIRS ${CMAKE_CURRENT_BINARY_DIR}/src/) # dpkg-shlibdeps cannot find dependencies that aren't installed, so it needs some help
endif()

find_package(rpmbuild) # Optional for building RedHat/Fedora packages
if(rpmbuild_FOUND)
	list(APPEND CPACK_GENERATOR "RPM")
	# Generate component packages
	# NOTE: This is overridden by CPACK_COMPONENTS_GROUPING above
	set(CPACK_RPM_COMPONENT_INSTALL ON)
	# Use default rpm package naming
	set(CPACK_RPM_FILE_NAME "RPM-DEFAULT")
	set(CPACK_RPM_PACKAGE_RELEASE_DIST ON)
	# Configure license and changelog
	set(CPACK_RPM_PACKAGE_LICENSE "LGPLv2+")
	set(CPACK_RPM_CHANGELOG_FILE "${CMAKE_CURRENT_SOURCE_DIR}/rpm_changelog.txt")
	# Assign package names to components
	set(CPACK_RPM_DUKPT_RUNTIME_PACKAGE_NAME "dukpt-runtime")
	set(CPACK_RPM_DUKPT_DEVELOPMENT_PACKAGE_NAME "dukpt-devel")
	set(CPACK_RPM_DUKPT_DOCS_PACKAGE_NAME "dukpt-doc")
	set(CPACK_RPM_DUKPT_UI_RUNTIME_PACKAGE_NAME "dukpt-ui")
	# Assign package architecture to documentation component
	set(CPACK_RPM_DUKPT_DOCS_PACKAGE_ARCHITECTURE "noarch")
	# Assign package suggestions
	set(CPACK_RPM_DUKPT_DOCS_PACKAGE_SUGGESTS "dukpt-devel")
	# NOTE: RPM generator automatically detects dependencies
endif()

# Generate DragNDrop package for MacOS if dukpt-ui is available
if(APPLE AND TARGET dukpt-ui AND BUILD_MACOSX_BUNDLE)
	set(CPACK_GENERATOR "DragNDrop") # Skip TGZ generator when building MacOS bundle
	set(CPACK_COMPONENTS_ALL dukpt_ui_bundle)
	set(CPACK_DMG_SLA_USE_RESOURCE_FILE_LICENSE ON)
	set(CPACK_DMG_DS_STORE_SETUP_SCRIPT "${CMAKE_CURRENT_SOURCE_DIR}/macos/dukpt_dmg_setup.scpt")
	set(CPACK_DMG_BACKGROUND_IMAGE "${CMAKE_CURRENT_SOURCE_DIR}/macos/openemv_dmg_bg.tif")
endif()

# Generate NSIS package for Windows if dukpt-ui is available
if(WIN32 AND TARGET dukpt-ui)
	list(APPEND CPACK_GENERATOR "NSIS")
	# Only package runtime components
	set(CPACK_COMPONENTS_ALL dukpt_runtime dukpt_ui_runtime dukpt_development)
	# Set display name used by Control Panel
	set(CPACK_NSIS_DISPLAY_NAME "${CPACK_PACKAGE_VENDOR} ${CMAKE_PROJECT_NAME} ${CMAKE_PROJECT_VERSION}")
	# Set name used by installer application
	set(CPACK_NSIS_PACKAGE_NAME "${CPACK_PACKAGE_VENDOR} ${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}")
	# Set project URL
	set(CPACK_NSIS_URL_INFO_ABOUT "${CMAKE_PROJECT_HOMEPAGE_URL}")
	# Install into vendor/package-version directory
	set(CPACK_NSIS_INSTALL_ROOT "C:\\${CPACK_PACKAGE_VENDOR}")
	set(CPACK_PACKAGE_INSTALL_DIRECTORY "${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}")
	# Set display name used by Start Menu
	set(CPACK_PACKAGE_EXECUTABLES "dukpt-ui" "Dukpt UI")
	# Set desktop link to dukpt-ui
	set(CPACK_CREATE_DESKTOP_LINKS dukpt-ui)
	# Set package file name based on architecture
	if(CMAKE_SIZEOF_VOID_P EQUAL 8)
		set(CPACK_PACKAGE_FILE_NAME ${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}-win64-setup)
	elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
		set(CPACK_PACKAGE_FILE_NAME ${CMAKE_PROJECT_NAME}-${CMAKE_PROJECT_VERSION}-win32-setup)
	endif()
endif()

include(CPack)
