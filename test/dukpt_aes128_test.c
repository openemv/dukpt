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

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK
static const uint8_t bdk[] = { 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1 };
static const uint8_t ikid[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 };
static const uint8_t ik_verify[] = { 0x12, 0x73, 0x67, 0x1E, 0xA2, 0x6A, 0xC2, 0x9A, 0xFA, 0x4D, 0x10, 0x84, 0x12, 0x76, 0x52, 0xA1 };

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK (Calculation of AES PIN Block Format 4; top of page 31)
static const uint8_t pinblock[] = { 0x44, 0x12, 0x34, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x2F, 0x69, 0xAD, 0xDE, 0x2E, 0x9E, 0x7A, 0xCE };
static const uint8_t panblock[] = { 0x44, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// ANSI X9.24-3:2017 Supplement Test Vectors (first eight KSNs)
static const uint8_t ksn_verify[][DUKPT_AES_KSN_LEN] = {
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x01 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x02 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x03 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x04 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x05 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x06 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x07 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x08 },
};

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK (first eight transaction/derivation keys; middle of page 2)
static const uint8_t txn_key_verify[][DUKPT_AES_KEY_LEN(AES128)] = {
	{ 0x4F, 0x21, 0xB5, 0x65, 0xBA, 0xD9, 0x83, 0x5E, 0x11, 0x2B, 0x64, 0x65, 0x63, 0x5E, 0xAE, 0x44 },
	{ 0x2F, 0x34, 0xD6, 0x8D, 0xE1, 0x0F, 0x68, 0xD3, 0x80, 0x91, 0xA7, 0x3B, 0x9E, 0x7C, 0x43, 0x7C },
	{ 0x03, 0x15, 0x04, 0xE5, 0x30, 0x36, 0x5C, 0xF8, 0x12, 0x64, 0x23, 0x85, 0x40, 0x51, 0x83, 0x18 },
	{ 0x0E, 0xEF, 0xC7, 0xAD, 0xA6, 0x28, 0xBA, 0x68, 0x87, 0x8D, 0xA9, 0x16, 0x5A, 0x8A, 0x18, 0x87 },
	{ 0xC2, 0xA7, 0xAC, 0x32, 0x8A, 0x5D, 0xA2, 0xD6, 0x00, 0x2D, 0x62, 0x46, 0x5B, 0xFC, 0x02, 0x8B },
	{ 0xD3, 0x0F, 0x7D, 0x93, 0x51, 0xDA, 0x58, 0x44, 0x8A, 0x2F, 0x5E, 0x92, 0xB4, 0xEE, 0x3B, 0x7D },
	{ 0xA8, 0x25, 0x3C, 0xEE, 0xD9, 0xAC, 0x04, 0x2C, 0x54, 0xF7, 0x5D, 0x35, 0xC8, 0x35, 0x22, 0x78 },
	{ 0x71, 0x8E, 0xE6, 0xCF, 0x0B, 0x27, 0xE5, 0x3D, 0x5F, 0x7A, 0xF9, 0x9C, 0x4D, 0x81, 0x46, 0xA2 },
};

// ANSI X9.24-1:2009 Supplement Test Vectors for AES-128 BDK (first eight encrypted PIN blocks; page 31)
static const uint8_t encrypted_pinblock_verify[][DUKPT_AES_PINBLOCK_LEN] = {
	{ 0xA9, 0x12, 0x15, 0x03, 0x91, 0xAB, 0x65, 0xA6, 0x7E, 0x52, 0x88, 0x3D, 0x81, 0xCE, 0x2D, 0x15 },
	{ 0x52, 0xA0, 0x05, 0x03, 0xBD, 0x34, 0xBA, 0x13, 0x83, 0xF6, 0xA7, 0xEE, 0x9F, 0xE2, 0x54, 0x7F },
	{ 0xA5, 0xA2, 0x7E, 0x82, 0xB4, 0x3A, 0x9A, 0x86, 0x6A, 0x93, 0xD7, 0xAB, 0xE8, 0x9C, 0xEF, 0x93 },
	{ 0x71, 0xB3, 0xD0, 0x52, 0x86, 0x69, 0x49, 0x87, 0x77, 0x55, 0x5A, 0x8B, 0xE6, 0x69, 0x8E, 0x44 },
	{ 0x88, 0x1A, 0x7F, 0x77, 0xA2, 0xE0, 0x4E, 0x5B, 0xEA, 0x98, 0x5E, 0x34, 0x2F, 0xD0, 0xB6, 0x28 },
	{ 0xBD, 0xC1, 0xC3, 0x87, 0x1A, 0xFB, 0x0B, 0x34, 0x0A, 0xA5, 0xB5, 0xCE, 0xFD, 0x08, 0x69, 0x5E },
	{ 0x4A, 0x8E, 0x6B, 0x8C, 0x7D, 0xBE, 0xE6, 0xCB, 0xA6, 0xDC, 0x77, 0x4F, 0x0C, 0xB8, 0x33, 0x96 },
	{ 0x83, 0x08, 0xBB, 0x85, 0x7C, 0x17, 0xF3, 0x90, 0x36, 0x9F, 0x76, 0x1F, 0x8E, 0xB3, 0x58, 0xFA },
};

// ANSI X9.24-3:2017 Supplement Test Vectors (transaction counters 0x1fffe, 0x1ffff, 0x20000, 0x20001)
// NOTE: transaction counter 0x1ffff is commented out because it has more than the allowed 16 set bits
static const uint8_t ksn_verify2[][DUKPT_AES_KSN_LEN] = {
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x01, 0xFF, 0xFE },
	//{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x01, 0xFF, 0xFF },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x02, 0x00, 0x00 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x02, 0x00, 0x01 },
};

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK (transaction keys for 0x1fffe, 0x1ffff, 0x20000, 0x20001; page 5)
// NOTE: transaction counter 0x1ffff is commented out because it has more than the allowed 16 set bits
static const uint8_t txn_key_verify2[][DUKPT_AES_KEY_LEN(AES128)] = {
	{ 0xE2, 0x1E, 0x8C, 0x8D, 0x34, 0x7F, 0x85, 0x61, 0xA2, 0xBE, 0x75, 0x2D, 0xAA, 0x85, 0xA1, 0x11 },
	//{ 0x1F, 0xE3, 0x68, 0x98, 0x80, 0x89, 0xCD, 0xD7, 0x6D, 0xA1, 0x8A, 0x34, 0x58, 0xE1, 0x13, 0xBA },
	{ 0xF7, 0xAE, 0x90, 0x25, 0x46, 0x8A, 0x25, 0xD3, 0x7B, 0x72, 0x49, 0xCF, 0xFE, 0xD2, 0x24, 0xC8 },
	{ 0x69, 0x2C, 0x8E, 0xA4, 0x01, 0x36, 0x45, 0x13, 0x5B, 0x36, 0x49, 0x71, 0x31, 0xDF, 0x9D, 0x2C },
};

// ANSI X9.24-3:2017 Supplement Test Vectors (last four transaction counters)
static const uint8_t ksn_verify3[][DUKPT_AES_KSN_LEN] = {
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0xFF, 0xFE, 0x20, 0x00 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0xFF, 0xFE, 0x40, 0x00 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0xFF, 0xFE, 0x80, 0x00 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0xFF, 0xFF, 0x00, 0x00 },
};

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK (last four transaction; middle of page 6)
static const uint8_t txn_key_verify3[][DUKPT_AES_KEY_LEN(AES128)] = {
	{ 0x48, 0xE5, 0x85, 0xB6, 0x94, 0xEB, 0x0B, 0x18, 0xD5, 0xC3, 0x54, 0x43, 0xE1, 0x63, 0xC0, 0xBA },
	{ 0x39, 0x6C, 0x2C, 0x7C, 0xA1, 0xEA, 0x70, 0x1C, 0x03, 0xB8, 0x6B, 0x7D, 0x41, 0xF0, 0xC5, 0x62 },
	{ 0x03, 0x87, 0x62, 0x5F, 0x18, 0x9B, 0x58, 0xAE, 0x03, 0xEF, 0x0E, 0x8C, 0xCA, 0x41, 0x10, 0x5E },
	{ 0xF6, 0xBA, 0x59, 0x38, 0x9B, 0xD1, 0x4A, 0x98, 0x55, 0xBE, 0x97, 0x27, 0xE7, 0xC5, 0x2E, 0x3C },
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
	uint8_t ik[DUKPT_AES_KEY_LEN(AES128)];
	uint8_t ksn[DUKPT_AES_KSN_LEN];
	uint8_t txn_key[DUKPT_AES_KEY_LEN(AES128)];
	uint8_t encrypted_pinblock[DUKPT_AES_PINBLOCK_LEN];
	uint8_t decrypted_pinblock[DUKPT_AES_PINBLOCK_LEN];

	// Test Initial Key (IK) derivation using AES128
	r = dukpt_aes_derive_ik(bdk, sizeof(bdk), ikid, ik);
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

	// Advance to first KSN
	memcpy(ksn, ikid, DUKPT_AES_KSN_LEN);
	memset(ksn + DUKPT_AES_IK_ID_LEN, 0, DUKPT_AES_KSN_LEN - DUKPT_AES_IK_ID_LEN);
	r = dukpt_aes_ksn_advance(ksn);
	if (r) {
		fprintf(stderr, "dukpt_aes_ksn_advance() failed; r=%d\n", r);
		goto exit;
	}

	// Test transaction key derivation from Initial Key (IK) for initial KSNs
	for (size_t i = 0; i < sizeof(ksn_verify) / sizeof(ksn_verify[0]); ++i) {
		// Validate KSN
		if (!dukpt_aes_ksn_is_valid(ksn)) {
			fprintf(stderr, "KSN %zu is invalid\n", i);
			r = 1;
			goto exit;
		}
		if (memcmp(ksn, ksn_verify[i], DUKPT_AES_KSN_LEN) != 0) {
			fprintf(stderr, "KSN %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Test transaction key derivation from Initial Key (IK)
		r = dukpt_aes_derive_txn_key(ik, sizeof(ik), ksn, txn_key);
		if (r) {
			fprintf(stderr, "dukpt_aes_derive_txn_key() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(txn_key, txn_key_verify[i], sizeof(txn_key_verify[i])) != 0) {
			fprintf(stderr, "Transaction key derivation %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Test PIN block encryption
		r = dukpt_aes_encrypt_pinblock(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			pinblock,
			panblock,
			encrypted_pinblock
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_encrypt_pinblock() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(encrypted_pinblock, encrypted_pinblock_verify[i], sizeof(encrypted_pinblock_verify[i])) != 0) {
			fprintf(stderr, "Encrypted PIN block %zu is incorrect\n", i);
			print_buf("encrypted_pinblock", encrypted_pinblock, sizeof(encrypted_pinblock));
			print_buf("encrypted_pinblock_verify", encrypted_pinblock_verify[i], sizeof(encrypted_pinblock_verify[i]));
			r = 1;
			goto exit;
		}

		// Test PIN block decryption
		r = dukpt_aes_decrypt_pinblock(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			encrypted_pinblock,
			panblock,
			decrypted_pinblock
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_decrypt_pinblock() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(decrypted_pinblock, pinblock, sizeof(pinblock)) != 0) {
			fprintf(stderr, "Decrypted PIN block %zu is incorrect\n", i);
			print_buf("decrypted_pinblock", decrypted_pinblock, sizeof(decrypted_pinblock));
			print_buf("pinblock", pinblock, sizeof(pinblock));
			r = 1;
			goto exit;
		}

		// Advance KSN
		r = dukpt_aes_ksn_advance(ksn);
		if (r) {
			fprintf(stderr, "dukpt_aes_ksn_advance() failed; r=%d\n", r);
			goto exit;
		}
	}

	// Test transaction key derivation from Initial Key (IK) for rollover KSNs
	memcpy(ksn, ksn_verify2[0], DUKPT_AES_KSN_LEN);
	for (size_t i = 0; i < sizeof(ksn_verify2) / sizeof(ksn_verify2[0]); ++i) {
		// Validate KSN
		if (!dukpt_aes_ksn_is_valid(ksn)) {
			fprintf(stderr, "KSN %zu is invalid\n", i);
			r = 1;
			goto exit;
		}
		if (memcmp(ksn, ksn_verify2[i], DUKPT_AES_KSN_LEN) != 0) {
			fprintf(stderr, "KSN %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Test transaction key derivation from Initial Key (IK)
		r = dukpt_aes_derive_txn_key(ik, sizeof(ik), ksn, txn_key);
		if (r) {
			fprintf(stderr, "dukpt_aes_derive_txn_key() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(txn_key, txn_key_verify2[i], sizeof(txn_key_verify2[i])) != 0) {
			fprintf(stderr, "Transaction key derivation %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Advance KSN
		r = dukpt_aes_ksn_advance(ksn);
		if (r) {
			fprintf(stderr, "dukpt_aes_ksn_advance() failed; r=%d\n", r);
			goto exit;
		}
	}

	// Test transaction key derivation from Initial Key (IK) for last KSNs
	memcpy(ksn, ksn_verify3[0], DUKPT_AES_KSN_LEN);
	for (size_t i = 0; i < sizeof(ksn_verify3) / sizeof(ksn_verify3[0]); ++i) {
		// Validate KSN
		if (!dukpt_aes_ksn_is_valid(ksn)) {
			fprintf(stderr, "KSN %zu is invalid\n", i);
			r = 1;
			goto exit;
		}
		if (memcmp(ksn, ksn_verify3[i], DUKPT_AES_KSN_LEN) != 0) {
			fprintf(stderr, "KSN %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Test transaction key derivation from Initial Key (IK)
		r = dukpt_aes_derive_txn_key(ik, sizeof(ik), ksn, txn_key);
		if (r) {
			fprintf(stderr, "dukpt_aes_derive_txn_key() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(txn_key, txn_key_verify3[i], sizeof(txn_key_verify3[i])) != 0) {
			fprintf(stderr, "Transaction key derivation %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Advance KSN
		r = dukpt_aes_ksn_advance(ksn);
		if (i != (sizeof(ksn_verify3) / sizeof(ksn_verify3[0])) - 1) {
			// If not last KSN, it must advance
			if (r) {
				fprintf(stderr, "dukpt_aes_ksn_advance() failed; r=%d\n", r);
				goto exit;
			}
		}
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}