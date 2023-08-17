/**
 * @file dukpt_tdes_state_test.c
 *
 * Copyright (c) 2023 Leon Lynch
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
	struct dukpt_tdes_state_t state;
	uint8_t ik[DUKPT_TDES_KEY_LEN];
	uint8_t ksn[DUKPT_TDES_KSN_LEN];
	uint8_t txn_key1[DUKPT_TDES_KEY_LEN];
	uint8_t txn_key2[DUKPT_TDES_KEY_LEN];

	// Derive Initial Key (IK)
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

	// Advance to first KSN
	memcpy(ksn, iksn, DUKPT_TDES_KSN_LEN);
	r = dukpt_tdes_ksn_advance(ksn);
	if (r) {
		fprintf(stderr, "dukpt_tdes_ksn_advance() failed; r=%d\n", r);
		goto exit;
	}

	// Initialise transaction originating state
	r = dukpt_tdes_state_init(ik, iksn, &state);
	if (r) {
		fprintf(stderr, "dukpt_tdes_state_init() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(state.ksn, ksn, sizeof(ksn)) != 0) {
		fprintf(stderr, "Initial DUKPT state KSN is incorrect\n");
		r = 1;
		goto exit;
	}
	for (size_t i = 0; i < DUKPT_TDES_TC_BITS; ++i) {
		if (!state.valid[i]) {
			fprintf(stderr, "Initial DUKPT state valid field is incorrect\n");
			r = 1;
			goto exit;
		}
	}

	// Compare transaction keys generated by transaction originating and
	// transaction receiving implementations for all possible transactions
	for (size_t i = 0; ; ++i) {
		// Transaction key derivation from DUKPT state
		r = dukpt_tdes_state_next_txn_key(&state, txn_key1);
		if (r) {
			if (r == 2 && // Returned by dukpt_tdes_ksn_advance() via dukpt_tdes_state_next_txn_key()
				dukpt_tdes_ksn_is_exhausted(state.ksn) &&
				dukpt_tdes_ksn_advance(ksn) == 2
			) {
				// If both implementations agree that the KSN is exhausted,
				// end the test
				break;
			}

			fprintf(stderr, "dukpt_tdes_state_next_txn_key() failed; r=%d\n", r);
			goto error;
		}

		// Transaction key derivation from Initial Key (IK)
		r = dukpt_tdes_derive_txn_key(ik, ksn, txn_key2);
		if (r) {
			fprintf(stderr, "dukpt_tdes_derive_txn_key() failed; r=%d\n", r);
			goto error;
		}
		if (memcmp(txn_key1, txn_key2, DUKPT_TDES_KEY_LEN) != 0) {
			fprintf(stderr, "Transaction key derivation %zu is incorrect\n", i);
			r = 1;
			goto error;
		}

		// Advance KSN
		r = dukpt_tdes_ksn_advance(ksn);
		if (r) {
			fprintf(stderr, "dukpt_tdes_ksn_advance() failed; r=%d\n", r);
			goto error;
		}
		if (memcmp(state.ksn, ksn, sizeof(ksn)) != 0) {
			fprintf(stderr, "KSN mismatch\n");
			r = 1;
			goto error;
		}
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

error:
	fprintf(stderr, "KSN: ");
	for (size_t i = 0; i < sizeof(state.ksn); ++i) {
		fprintf(stderr, "%02X", state.ksn[i]);
	}
	fprintf(stderr, "\n");
	fprintf(stderr, "KSN: ");
	for (size_t i = 0; i < sizeof(ksn); ++i) {
		fprintf(stderr, "%02X", ksn[i]);
	}
	fprintf(stderr, "\n");
exit:
	return r;
}
