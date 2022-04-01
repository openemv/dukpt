/**
 * @file dukpt_aes_crypto.c
 * @brief AES crypto helper functions
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

#include "dukpt_aes_crypto.h"
#include "dukpt_mem.h"
#include "dukpt_config.h"

#include "crypto_aes.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// See NIST SP 800-38B, section 5.3
static const uint8_t dukpt_aes_cmac_subkey_r128[] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x87 };

static int dukpt_aes_cmac_derive_subkeys(const void* key, size_t key_len, void* k1, void* k2)
{
	int r;
	uint8_t zero[AES_BLOCK_SIZE];
	uint8_t l_buf[AES_BLOCK_SIZE];

	// See NIST SP 800-38B, section 6.1

	// Encrypt zero block with input key
	memset(zero, 0, sizeof(zero));
	r = crypto_aes_encrypt_ecb(key, key_len, zero, l_buf);
	if (r) {
		// Internal error
		goto exit;
	}

	// Generate K1 subkey
	memcpy(k1, l_buf, AES_BLOCK_SIZE);
	r = dukpt_lshift(k1, AES_BLOCK_SIZE);
	// If carry bit is set, XOR with R128
	if (r) {
		dukpt_xor(k1, dukpt_aes_cmac_subkey_r128, sizeof(dukpt_aes_cmac_subkey_r128));
	}

	// Generate K2 subkey
	memcpy(k2, k1, AES_BLOCK_SIZE);
	r = dukpt_lshift(k2, AES_BLOCK_SIZE);
	// If carry bit is set, XOR with R128
	if (r) {
		dukpt_xor(k2, dukpt_aes_cmac_subkey_r128, sizeof(dukpt_aes_cmac_subkey_r128));
	}

	// Success
	r = 0;
	goto exit;

exit:
	// Cleanup
	dukpt_cleanse(l_buf, sizeof(l_buf));

	return r;
}

int dukpt_aes_cmac(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* cmac
)
{
	int r;
	uint8_t k1[AES_BLOCK_SIZE];
	uint8_t k2[AES_BLOCK_SIZE];
	uint8_t iv[AES_BLOCK_SIZE];
	const void* ptr = buf;

	size_t last_block_len;
	uint8_t last_block[AES_BLOCK_SIZE];

	if (!key || !cmac) {
		return -1;
	}
	if (key_len != AES128_KEY_SIZE &&
		key_len != AES192_KEY_SIZE &&
		key_len != AES256_KEY_SIZE
	) {
		return -2;
	}
	if (buf_len && !buf) {
		return -3;
	}

	// See NIST SP 800-38B, section 6.2
	// See ISO 9797-1:2011 MAC algorithm 5
	// If CMAC message input (M) is a multiple of the cipher block size, then
	// the last message input block is XOR'd with subkey K1.
	// If CMAC message input (M) is not a multiple of the cipher block size,
	// then the last message input block is padded and XOR'd with subkey K2.
	// The cipher is applied in CBC mode to all message input blocks,
	// including the modified last block.

	// Derive CMAC subkeys
	r = dukpt_aes_cmac_derive_subkeys(key, key_len, k1, k2);
	if (r) {
		// Internal error
		goto exit;
	}

	// Compute CMAC
	// See NIST SP 800-38B, section 6.2
	// See ISO 9797-1:2011 MAC algorithm 5
	memset(iv, 0, sizeof(iv)); // Start with zero IV
	if (buf_len > AES_BLOCK_SIZE) {
		// For all blocks except the last block, compute CBC-MAC
		for (size_t i = 0; i < buf_len - AES_BLOCK_SIZE; i += AES_BLOCK_SIZE) {
			r = crypto_aes_encrypt(key, key_len, iv, ptr, AES_BLOCK_SIZE, iv);
			if (r) {
				// Internal error
				goto exit;
			}

			ptr += AES_BLOCK_SIZE;
		}
	}

	// Prepare last block
	if (buf_len) {
		last_block_len = buf_len - (ptr - buf);
	} else {
		last_block_len = 0;
	}
	if (last_block_len == AES_BLOCK_SIZE) {
		// If message input is a multiple of cipher block size,
		// XOR with subkey K1
		dukpt_xor(iv, k1, sizeof(iv));
	} else {
		// If message input is a multiple of cipher block size,
		// XOR with subkey K2
		dukpt_xor(iv, k2, sizeof(iv));

		// Build new last block
		memcpy(last_block, ptr, last_block_len);

		// Pad last block with 1 bit followed by zeros
		last_block[last_block_len] = 0x80;
		if (last_block_len + 1 < AES_BLOCK_SIZE) {
			memset(last_block + last_block_len + 1, 0, AES_BLOCK_SIZE - last_block_len - 1);
		}

		ptr = last_block;
	}

	// Process last block
	r = crypto_aes_encrypt(key, key_len, iv, ptr, AES_BLOCK_SIZE, cmac);
	if (r) {
		// Internal error
		goto exit;
	}

	// Success
	r = 0;
	goto exit;

exit:
	// Cleanup
	dukpt_cleanse(k1, sizeof(k1));
	dukpt_cleanse(k2, sizeof(k2));
	dukpt_cleanse(iv, sizeof(iv));
	dukpt_cleanse(last_block, sizeof(last_block));

	return r;
}

#ifdef MBEDTLS_FOUND
#include <mbedtls/md.h>

int dukpt_hmac_sha256(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* hmac
)
{
	int r;
	mbedtls_md_context_t ctx;

	mbedtls_md_init(&ctx);
	r = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	if (r) {
		r = -1;
		goto exit;
	}

	r = mbedtls_md_hmac_starts(&ctx, key, key_len);
	if (r) {
		r = -2;
		goto exit;
	}

	r = mbedtls_md_hmac_update(&ctx, buf, buf_len);
	if (r) {
		r = -3;
		goto exit;
	}

	r = mbedtls_md_hmac_finish(&ctx, hmac);
	if (r) {
		r = -4;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_md_free(&ctx);

	return r;
}

#endif
