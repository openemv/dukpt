/**
 * @file dukpt_aes128_update_key_test.c
 *
 * Copyright 2021-2022 Leon Lynch
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "dukpt_aes.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK
static const uint8_t ik[] = { 0x12, 0x73, 0x67, 0x1E, 0xA2, 0x6A, 0xC2, 0x9A, 0xFA, 0x4D, 0x10, 0x84, 0x12, 0x76, 0x52, 0xA1 };
static const uint8_t ikid[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 };

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK (update key for AES-128; bottom of page 7)
static const uint8_t update_key_aes128_verify[] = { 0x9A, 0x97, 0x70, 0xAE, 0xE1, 0xAC, 0xD1, 0xB1, 0x34, 0x73, 0xD0, 0x46, 0x3A, 0x18, 0x83, 0xB9 };

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK (update key for TDES2; middle of page 24)
//static const uint8_t update_key_tdes2_verify[] = { 0x47, 0x44, 0xA5, 0xEC, 0xBC, 0x62, 0xB5, 0xC4, 0xBB, 0x76, 0xFB, 0xEA, 0xE1, 0xE2, 0x44, 0xA3 };

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK (update key for TDES3; top of page 30)
//static const uint8_t update_key_tdes3_verify[] = { 0xAF, 0x82, 0xBE, 0x85, 0x33, 0xCF, 0xCA, 0x52, 0x6D, 0xA7, 0x17, 0x08, 0x66, 0x7A, 0xD0, 0xBB, 0xC7, 0xA7, 0x51, 0x75, 0x04, 0xC7, 0x8C, 0x8A };

static void print_buf(const char* buf_name, const void* buf, size_t length)
{
	const uint8_t* ptr = buf;
	printf("%s: ", buf_name);
	for (size_t i = 0; i < length; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}

int main(void)
{
	int r;
	uint8_t update_key_aes128[DUKPT_AES_KEY_LEN(AES128)];
	//uint8_t update_key_tdes2[DUKPT_AES_KEY_LEN(TDES2)];
	//uint8_t update_key_tdes3[DUKPT_AES_KEY_LEN(TDES3)];

	// Test AES-128 update key
	r = dukpt_aes_derive_update_key(ik, sizeof(ik), ikid, DUKPT_AES_KEY_TYPE_AES128, update_key_aes128);
	if (r) {
		fprintf(stderr, "dukpt_aes_derive_update_key() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(update_key_aes128, update_key_aes128_verify, sizeof(update_key_aes128_verify)) != 0) {
		fprintf(stderr, "Update key (AES128) derivation is incorrect\n");
		print_buf("update_key_aes128", update_key_aes128, sizeof(update_key_aes128));
		print_buf("update_key_aes128_verify", update_key_aes128_verify,sizeof(update_key_aes128_verify));
		r = 1;
		goto exit;
	}

	/*
	// Test TDES2 update key
	r = dukpt_aes_derive_update_key(ik, sizeof(ik), ikid, DUKPT_AES_KEY_TYPE_TDES2, update_key_tdes2);
	if (r) {
		fprintf(stderr, "dukpt_aes_derive_update_key() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(update_key_tdes2, update_key_tdes2_verify, sizeof(update_key_tdes2_verify)) != 0) {
		fprintf(stderr, "Update key (TDES2) derivation is incorrect\n");
		print_buf("update_key_tdes2", update_key_tdes2, sizeof(update_key_tdes2));
		print_buf("update_key_tdes2_verify", update_key_tdes2_verify,sizeof(update_key_tdes2_verify));
		r = 1;
		goto exit;
	}

	// Test TDES3 update key
	r = dukpt_aes_derive_update_key(ik, sizeof(ik), ikid, DUKPT_AES_KEY_TYPE_TDES3, update_key_tdes3);
	if (r) {
		fprintf(stderr, "dukpt_aes_derive_update_key() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(update_key_tdes3, update_key_tdes3_verify, sizeof(update_key_tdes3_verify)) != 0) {
		fprintf(stderr, "Update key (TDES3) derivation is incorrect\n");
		print_buf("update_key_tdes3", update_key_tdes3, sizeof(update_key_tdes3));
		print_buf("update_key_tdes3_verify", update_key_tdes3_verify,sizeof(update_key_tdes3_verify));
		r = 1;
		goto exit;
	}
	*/

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
