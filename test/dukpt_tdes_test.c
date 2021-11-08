/**
 * @file dukpt_tdes_test.c
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

#include "dukpt_tdes.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ANSI X9.24-1:2009 A.4 DUKPT Test Data Examples
static const uint8_t bdk[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 };
static const uint8_t iksn[] = { 0xFF, 0xFF, 0x98, 0x76, 0x54, 0x32, 0x10, 0xE0, 0x00, 0x00 };
static const uint8_t ik_verify[] = { 0x6A, 0xC2, 0x92, 0xFA, 0xA1, 0x31, 0x5B, 0x4D, 0x85, 0x8A, 0xB3, 0xA3, 0xD7, 0xD5, 0x93, 0x3A };

int main(void)
{
	int r;
	uint8_t ik[DUKPT_TDES_KEY_LEN];

	// Test Initial Key (IK) derivation
	r = dukpt_tdes_derive_ik(bdk, iksn, ik);
	if (r) {
		fprintf(stderr, "dukpt_tdes_derive_ik() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(ik, ik_verify, sizeof(ik_verify)) != 0) {
		fprintf(stderr, "Initial key derivation is incorrect\n");
		r = 1;
		goto exit;
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
