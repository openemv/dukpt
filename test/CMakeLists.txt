##############################################################################
# Copyright (c) 2021, 2022 Leon Lynch
#
# This file is licensed under the terms of the LGPL v2.1 license.
# See LICENSE file.
##############################################################################

cmake_minimum_required(VERSION 3.16)

if(BUILD_TESTING)
	add_executable(dukpt_tdes_test dukpt_tdes_test.c)
	target_link_libraries(dukpt_tdes_test dukpt_tdes)
	add_test(dukpt_tdes_test dukpt_tdes_test)

	add_executable(dukpt_tdes_ksn_test dukpt_tdes_ksn_test.c)
	target_link_libraries(dukpt_tdes_ksn_test dukpt_tdes)
	add_test(dukpt_tdes_ksn_test dukpt_tdes_ksn_test)

	add_executable(dukpt_aes128_test dukpt_aes128_test.c)
	target_link_libraries(dukpt_aes128_test dukpt_aes crypto_aes crypto_mem)
	add_test(dukpt_aes128_test dukpt_aes128_test)

	add_executable(dukpt_aes128_update_key_test dukpt_aes128_update_key_test.c)
	target_link_libraries(dukpt_aes128_update_key_test dukpt_aes)
	add_test(dukpt_aes128_update_key_test dukpt_aes128_update_key_test)

	add_executable(dukpt_aes256_test dukpt_aes256_test.c)
	target_link_libraries(dukpt_aes256_test dukpt_aes crypto_aes crypto_mem)
	add_test(dukpt_aes256_test dukpt_aes256_test)

	add_executable(dukpt_aes256_update_key_test dukpt_aes256_update_key_test.c)
	target_link_libraries(dukpt_aes256_update_key_test dukpt_aes)
	add_test(dukpt_aes256_update_key_test dukpt_aes256_update_key_test)

	add_executable(dukpt_aes_ksn_test dukpt_aes_ksn_test.c)
	target_link_libraries(dukpt_aes_ksn_test dukpt_aes)
	add_test(dukpt_aes_ksn_test dukpt_aes_ksn_test)

	add_executable(dukpt_tdes_state_test dukpt_tdes_state_test.c)
	target_link_libraries(dukpt_tdes_state_test dukpt_tdes)
	add_test(dukpt_tdes_state_test dukpt_tdes_state_test)

	add_executable(dukpt_aes128_state_test dukpt_aes128_state_test.c)
	target_link_libraries(dukpt_aes128_state_test dukpt_aes)
	add_test(dukpt_aes128_state_test dukpt_aes128_state_test)

	add_executable(dukpt_aes256_state_test dukpt_aes256_state_test.c)
	target_link_libraries(dukpt_aes256_state_test dukpt_aes)
	add_test(dukpt_aes256_state_test dukpt_aes256_state_test)

	if(WIN32)
		# Ensure that tests can find required DLLs (if any)
		# Assume that the PATH already contains the compiler runtime DLLs
		set(DUKPT_TEST_PATH "${CMAKE_CURRENT_BINARY_DIR}/../src/;$ENV{PATH}")
		cmake_path(NATIVE_PATH DUKPT_TEST_PATH NORMALIZE DUKPT_TEST_PATH)
		get_property(DUKPT_TEST_TARGETS DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY TESTS)
		set_property(TEST ${DUKPT_TEST_TARGETS}
			PROPERTY
				ENVIRONMENT "PATH=${DUKPT_TEST_PATH}"
		)
	endif()
endif()
