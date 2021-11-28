/**
 * @file dukpt_aes_test.c
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

// ANSI X9.24-3:2017 B.1 Sample Test Vectors
static const uint8_t bdk128[] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1 };
static const uint8_t ikid[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 };
static const uint8_t ik128_verify[] = { 0x12, 0x73, 0x67, 0x1E, 0xA2, 0x6A, 0xC2, 0x9A, 0xFA, 0x4D, 0x10, 0x84, 0x12, 0x76, 0x52, 0xA1 };

// ANSI X9.24-3:2017 Supplement Test Vectors
static const uint8_t bdk256[] = {
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1,
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1,
};
static const uint8_t ik256_verify[] = {
	0xCE, 0x9C, 0xE0, 0xC1, 0x01, 0xD1, 0x13, 0x8F, 0x97, 0xFB, 0x6C, 0xAD, 0x4D, 0xF0, 0x45, 0xA7,
	0x08, 0x3D, 0x4E, 0xAE, 0x2D, 0x35, 0xA3, 0x17, 0x89, 0xD0, 0x1C, 0xCF, 0x09, 0x49, 0x55, 0x0F,
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
	uint8_t ik128[DUKPT_AES_KEY_LEN(AES128)];
	uint8_t ik256[DUKPT_AES_KEY_LEN(AES256)];

	// Test Initial Key (IK) derivation using AES128
	r = dukpt_aes_derive_ik(DUKPT_AES_KEY_TYPE_AES128, bdk128, ikid, ik128);
	if (r) {
		fprintf(stderr, "dukpt_aes_derive_ik() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(ik128, ik128_verify, sizeof(ik128_verify)) != 0) {
		fprintf(stderr, "Initial key derivation is incorrect\n");
		print_buf("ik128", ik128, sizeof(ik128));
		print_buf("ik128_verify", ik128_verify,sizeof(ik128_verify));
		r = 1;
		goto exit;
	}

	// Test Initial Key (IK) derivation using AES256
	r = dukpt_aes_derive_ik(DUKPT_AES_KEY_TYPE_AES256, bdk256, ikid, ik256);
	if (r) {
		fprintf(stderr, "dukpt_aes_derive_ik() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(ik256, ik256_verify, sizeof(ik256_verify)) != 0) {
		fprintf(stderr, "Initial key derivation is incorrect\n");
		print_buf("ik256", ik256, sizeof(ik256));
		print_buf("ik256_verify", ik256_verify,sizeof(ik256_verify));
		r = 1;
		goto exit;
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
