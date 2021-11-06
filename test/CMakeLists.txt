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

	add_executable(dukpt_aes_test dukpt_aes_test.c)
	target_link_libraries(dukpt_aes_test dukpt_aes)
	add_test(dukpt_aes_test dukpt_aes_test)
endif()
