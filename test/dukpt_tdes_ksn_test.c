/**
 * @file dukpt_tdes_ksn_test.c
 *
 * Copyright 2021 Leon Lynch
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

#include <stdio.h>

int main(void)
{
	int r;
	unsigned int txn_count = 0;
	unsigned int bit_combinations;

	uint8_t ksn[] = { 0xFF, 0xFF, 0x98, 0x76, 0x54, 0x32, 0x10, 0xE0, 0x00, 0x00 };

	do {
		r = dukpt_tdes_ksn_advance(ksn);
		if (r < 0) {
			fprintf(stderr, "dukpt_tdes_ksn_advance() failed; r=%d\n", r);
			goto exit;
		}
		if (r > 0) {
			// KSN exhausted
			break;
		}

		++txn_count;

		// Validate KSN
		if (!dukpt_tdes_ksn_is_valid(ksn)) {
			fprintf(stderr, "KSN %u is invalid\n", txn_count);
			r = 1;
			goto exit;
		}
	} while (1);

	// Selecting a sample of 10 or less bits from a total of 21 bits would
	// result in this list of combinations
	// C(21,10) = 352716
	// C(21,9) = 293930
	// C(21,8) = 203490
	// C(21,7) = 116280
	// C(21,6) = 54264
	// C(21,5) = 20349
	// C(21,4) = 5985
	// C(21,3) = 1330
	// C(21,2) = 210
	// C(21,1) = 21
	bit_combinations =
		352716u +
		293930u +
		203490u +
		116280u +
		54264u +
		20349u +
		5985u +
		1330u +
		210u +
		21u;

	if (txn_count != bit_combinations) {
		fprintf(stderr, "Total txn count does not match total bit combinations; %u vs %u\n", txn_count, bit_combinations);
		r = 1;
		goto exit;
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
