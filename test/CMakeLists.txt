##############################################################################
# Copyright (c) 2021 Leon Lynch
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
	target_link_libraries(dukpt_aes128_test dukpt_aes)
	add_test(dukpt_aes128_test dukpt_aes128_test)

	add_executable(dukpt_aes128_update_key_test dukpt_aes128_update_key_test.c)
	target_link_libraries(dukpt_aes128_update_key_test dukpt_aes)
	add_test(dukpt_aes128_update_key_test dukpt_aes128_update_key_test)

	add_executable(dukpt_aes256_test dukpt_aes256_test.c)
	target_include_directories(dukpt_aes256_test PRIVATE ${CMAKE_CURRENT_BINARY_DIR}/../src/) # For generated config file
	target_link_libraries(dukpt_aes256_test dukpt_aes)
	add_test(dukpt_aes256_test dukpt_aes256_test)

	add_executable(dukpt_aes256_update_key_test dukpt_aes256_update_key_test.c)
	target_link_libraries(dukpt_aes256_update_key_test dukpt_aes)
	add_test(dukpt_aes256_update_key_test dukpt_aes256_update_key_test)

	add_executable(dukpt_aes_ksn_test dukpt_aes_ksn_test.c)
	target_link_libraries(dukpt_aes_ksn_test dukpt_aes)
	add_test(dukpt_aes_ksn_test dukpt_aes_ksn_test)
endif()
