/**
 * @file dukpt_aes_ksn_test.c
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

#include <stdio.h>

int main(void)
{
	int r;
	unsigned int txn_count = 1;
	unsigned int bit_combinations;

	uint8_t ksn[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x01 };

	do {
		r = dukpt_aes_ksn_advance(ksn);
		if (r < 0) {
			fprintf(stderr, "dukpt_aes_ksn_advance() failed; r=%d\n", r);
			goto exit;
		}
		if (r > 0) {
			// KSN exhausted
			break;
		}

		++txn_count;

		// Validate KSN
		if (!dukpt_aes_ksn_is_valid(ksn)) {
			fprintf(stderr, "KSN %u is invalid\n", txn_count);
			r = 1;
			goto exit;
		}
	} while (1);

	// Selecting a sample of 16 or less bits from a total of 32 bits would
	// result in this list of combinations
	// C(32,16) = 300540195
	// C(32,15) = 565722720
	// C(32,14) = 471435600
	// C(32,13) = 347373600
	// C(32,12) = 225792840
	// C(32,11) = 129024480
	// C(32,10) = 64512240
	// C(32,9) = 28048800
	// C(32,8) = 10518300
	// C(32,7) = 3365856
	// C(32,6) = 906192
	// C(32,5) = 201376
	// C(32,4) = 35960
	// C(32,3) = 4960
	// C(32,2) = 496
	// C(32,1) = 32
	bit_combinations =
		601080390u +
		565722720u +
		471435600u +
		347373600u +
		225792840u +
		129024480u +
		64512240u +
		28048800u +
		10518300u +
		3365856u +
		906192u +
		201376u +
		35960u +
		4960u +
		496u +
		32u;

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
