/**
 * @file dukpt_aes128_test.c
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
static const uint8_t bdk[] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1 };
static const uint8_t ikid[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 };
static const uint8_t ik_verify[] = { 0x12, 0x73, 0x67, 0x1E, 0xA2, 0x6A, 0xC2, 0x9A, 0xFA, 0x4D, 0x10, 0x84, 0x12, 0x76, 0x52, 0xA1 };

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
	uint8_t ik[DUKPT_AES_KEY_LEN(AES128)];

	// Test Initial Key (IK) derivation using AES128
	r = dukpt_aes_derive_ik(DUKPT_AES_KEY_TYPE_AES128, bdk, ikid, ik);
	if (r) {
		fprintf(stderr, "dukpt_aes_derive_ik() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(ik, ik_verify, sizeof(ik_verify)) != 0) {
		fprintf(stderr, "Initial key derivation is incorrect\n");
		print_buf("ik", ik, sizeof(ik));
		print_buf("ik_verify", ik_verify, sizeof(ik_verify));
		r = 1;
		goto exit;
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
