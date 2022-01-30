/**
 * @file dukpt_tdes_crypto.c
 * @brief DES and TDES crypto helper functions
 *
 * Copyright (c) 2021, 2022 Leon Lynch
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "dukpt_tdes_crypto.h"
#include "dukpt_mem.h"
#include "dukpt_config.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef MBEDTLS_FOUND
#include <mbedtls/des.h>

int dukpt_des_encrypt(const void* key, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	int r;
	mbedtls_des_context ctx;
	uint8_t iv_buf[DES_BLOCK_SIZE];

	// Ensure that plaintext length is a multiple of the DES block length
	if ((plen & (DES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && plen != DES_BLOCK_SIZE) {
		return -2;
	}

	mbedtls_des_init(&ctx);

	r = mbedtls_des_setkey_enc(&ctx, key);
	if (r) {
		r = -3;
		goto exit;
	}

	if (iv) { // IV implies CBC block mode
		memcpy(iv_buf, iv, DES_BLOCK_SIZE);
		r = mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, plen, iv_buf, plaintext, ciphertext);
	} else {
		r = mbedtls_des_crypt_ecb(&ctx, plaintext, ciphertext);
	}
	if (r) {
		r = -4;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_des_free(&ctx);

	return r;
}

int dukpt_tdes2_encrypt(const void* key, const void* iv, const void* plaintext, size_t plen, void* ciphertext)
{
	int r;
	mbedtls_des3_context ctx;
	uint8_t iv_buf[DES_BLOCK_SIZE];

	// Ensure that plaintext length is a multiple of the DES block length
	if ((plen & (DES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && plen != DES_BLOCK_SIZE) {
		return -2;
	}

	mbedtls_des3_init(&ctx);

	r = mbedtls_des3_set2key_enc(&ctx, key);
	if (r) {
		r = -3;
		goto exit;
	}

	if (iv) { // IV implies CBC block mode
		memcpy(iv_buf, iv, DES_BLOCK_SIZE);
		r = mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, plen, iv_buf, plaintext, ciphertext);
	} else {
		r = mbedtls_des3_crypt_ecb(&ctx, plaintext, ciphertext);
	}
	if (r) {
		r = -4;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_des3_free(&ctx);

	return r;
}

int dukpt_tdes2_decrypt(const void* key, const void* iv, const void* ciphertext, size_t clen, void* plaintext)
{
	int r;
	mbedtls_des3_context ctx;
	uint8_t iv_buf[DES_BLOCK_SIZE];

	// Ensure that ciphertext length is a multiple of the DES block length
	if ((clen & (DES_BLOCK_SIZE-1)) != 0) {
		return -1;
	}

	// Only allow a single block for ECB block mode
	if (!iv && clen != DES_BLOCK_SIZE) {
		return -2;
	}

	mbedtls_des3_init(&ctx);

	r = mbedtls_des3_set2key_dec(&ctx, key);
	if (r) {
		r = -3;
		goto exit;
	}

	if (iv) { // IV implies CBC block mode
		memcpy(iv_buf, iv, DES_BLOCK_SIZE);
		r = mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, clen, iv_buf, ciphertext, plaintext);
	} else {
		r = mbedtls_des3_crypt_ecb(&ctx, ciphertext, plaintext);
	}
	if (r) {
		r = -4;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_des3_free(&ctx);

	return r;
}

int dukpt_tdes2_retail_mac(const void* key, const void* buf, size_t buf_len, void* mac)
{
	int r;
	size_t initial_len;
	size_t remaining_len;
	uint8_t iv[DES_BLOCK_SIZE];
	uint8_t last_block[DES_BLOCK_SIZE];
	uint8_t result[DES_BLOCK_SIZE];

	// See ISO 9797-1, MAC algorithm 3, Padding method 1
	// - No key derivation
	// - Zero padding
	// - Final iteration 1
	// - Output transformation 3

	// Determine initial length and remaining length based on last block boundary
	remaining_len = buf_len & (DES_BLOCK_SIZE-1);
	if (buf_len && !remaining_len) {
		remaining_len = DES_BLOCK_SIZE; // For last block
	}
	initial_len = buf_len - remaining_len;

	// Compute DES CBC-MAC for all but the last block
	memset(iv, 0, sizeof(iv)); // Start with zero IV
	for (size_t i = 0; i < initial_len; i += DES_BLOCK_SIZE) {
		r = dukpt_des_encrypt(key, iv, buf + i, DES_BLOCK_SIZE, iv);
		if (r) {
			goto exit;
		}
	}

	// Padding method 1:
	// Zero padding of last block, even if there was no input data
	memset(last_block, 0, sizeof(last_block));
	if (remaining_len) {
		memcpy(last_block, buf + buf_len - remaining_len, remaining_len);
	}

	// Output transformation 3:
	// TDES CBC-MAC of last block
	r = dukpt_tdes2_encrypt(key, iv, last_block, sizeof(last_block), result);
	if (r) {
		goto exit;
	}

	// Truncate result
	memcpy(mac, result, DES_RETAIL_MAC_LEN);

exit:
	// Cleanup
	dukpt_cleanse(iv, sizeof(iv));
	dukpt_cleanse(last_block, sizeof(last_block));
	dukpt_cleanse(result, sizeof(result));

	return r;
}

#endif
