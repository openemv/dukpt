/**
 * @file dukpt_aes256_update_key_test.c
 *
 * Copyright (c) 2021 Leon Lynch
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

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-256 BDK
static const uint8_t ik[] = {
	0xCE, 0x9C, 0xE0, 0xC1, 0x01, 0xD1, 0x13, 0x8F, 0x97, 0xFB, 0x6C, 0xAD, 0x4D, 0xF0, 0x45, 0xA7,
	0x08, 0x3D, 0x4E, 0xAE, 0x2D, 0x35, 0xA3, 0x17, 0x89, 0xD0, 0x1C, 0xCF, 0x09, 0x49, 0x55, 0x0F,
};
static const uint8_t ikid[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 };

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-256 BDK (update key for AES-128; middle of page 12)
static const uint8_t update_key_aes128_verify[] = {
	0x90, 0xE5, 0x4E, 0x4A, 0x70, 0x16, 0x0C, 0x7E, 0x08, 0x5C, 0x09, 0xD2, 0xB2, 0x41, 0xD3, 0x43,
};
// ANSI X9.24-3:2017 Supplement Test Vectors for AES-256 BDK (update key for AES-256; bottom of page 18)
static const uint8_t update_key_aes256_verify[] = {
	0xAE, 0xFB, 0x21, 0x0C, 0x13, 0x62, 0x78, 0xA1, 0x27, 0x9F, 0x7C, 0x88, 0x15, 0xF4, 0x46, 0xDB,
	0x8E, 0xBE, 0x2A, 0xA9, 0x10, 0xB1, 0x57, 0xAA, 0x4E, 0x64, 0x84, 0xD8, 0xDE, 0x9C, 0x48, 0x07,
};

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
	uint8_t update_key_aes256[DUKPT_AES_KEY_LEN(AES256)];

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

	// Test AES-256 update key
	r = dukpt_aes_derive_update_key(ik, sizeof(ik), ikid, DUKPT_AES_KEY_TYPE_AES256, update_key_aes256);
	if (r) {
		fprintf(stderr, "dukpt_aes_derive_update_key() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(update_key_aes256, update_key_aes256_verify, sizeof(update_key_aes256_verify)) != 0) {
		fprintf(stderr, "Update key (AES128) derivation is incorrect\n");
		print_buf("update_key_aes256", update_key_aes256, sizeof(update_key_aes256));
		print_buf("update_key_aes256_verify", update_key_aes256_verify,sizeof(update_key_aes256_verify));
		r = 1;
		goto exit;
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
