/**
 * @file dukpt_aes.c
 * @brief ANSI X9.24-3:2017 AES DUKPT implementation
 *
 * Copyright (c) 2021 Leon Lynch
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

#include "dukpt_aes.h"
#include "dukpt_config.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h> // for htons and friends

// Derivation data version ID for AES DUKPT
// See ANSI X9.24-3:2017 6.3.2 table 2 and table 3
#define DUKPT_AES_DERIVATION_DATA_VERSION (0x01);

// Key usage indicators for AES DUKPT
// See ANSI X9.24-3:2017 6.3.2 table 2 and table 3
enum dukpt_aes_key_usage_t {
	DUKPT_AES_KEY_USAGE_KEY_ENCRYPTION_KEY = 0x0002,
	DUKPT_AES_KEY_USAGE_PIN_ENCRYPTION = 0x1000,
	DUKPT_AES_KEY_USAGE_MAC_GENERATION = 0x2000,
	DUKPT_AES_KEY_USAGE_MAC_VERIFICATION = 0x2001,
	DUKPT_AES_KEY_USAGE_MAC_BOTH = 0x2002,
	DUKPT_AES_KEY_USAGE_DATA_ENCRYPTION_ENCRYPT = 0x3000,
	DUKPT_AES_KEY_USAGE_DATA_ENCRYPTION_DECRYPT = 0x3001,
	DUKPT_AES_KEY_USAGE_DATA_ENCRYPTION_BOTH = 0x3002,
	DUKPT_AES_KEY_USAGE_KEY_DERIVATION = 0x8000,
	DUKPT_AES_KEY_USAGE_KEY_DERIVATION_INITIAL_KEY = 0x8001,
};

// Algorithm indicators for AES DUKPT
// See ANSI X9.24-3:2017 6.3.2 table 2 and table 3
enum dukpt_aes_algorithm_t {
	DUKPT_AES_ALGORITHM_2TDEA = 0x0000,
	DUKPT_AES_ALGORITHM_3TDEA = 0x0001,
	DUKPT_AES_ALGORITHM_AES128 = 0x0002,
	DUKPT_AES_ALGORITHM_AES192 = 0x0003,
	DUKPT_AES_ALGORITHM_AES256 = 0x0004,
	DUKPT_AES_ALGORITHM_HMAC = 0x0005,
};

// Key derivation data
// See ANSI X9.24-3:2017 6.3.2 table 2 and table 3
struct dukpt_aes_derivation_data_t {
	uint8_t version;
	uint8_t key_block_counter;
	uint16_t key_usage;
	uint16_t algorithm;
	uint16_t length;
	uint8_t ksn_data[8]; // Either IK ID, or rightmost half of IK ID together with transaction counter
} __attribute__((packed));

typedef int (*aes_ecb_encrypt_func_t)(const void* key, const void* plaintext, void* ciphertext);

#ifdef MBEDTLS_FOUND

#include <mbedtls/aes.h>

#define AES_BLOCK_SIZE (16) ///< AES block size in bytes

static int dukpt_aes128_ecb_encrypt(const void* key, const void* plaintext, void* ciphertext)
{
	int r;
	mbedtls_aes_context ctx;

	mbedtls_aes_init(&ctx);

	r = mbedtls_aes_setkey_enc(&ctx, key, 128);
	if (r) {
		r = -1;
		goto exit;
	}

	r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);
	if (r) {
		r = -2;
		goto exit;
	}

exit:
	// Cleanup
	mbedtls_aes_free(&ctx);

	return r;
}

static int dukpt_aes192_ecb_encrypt(const void* key, const void* plaintext, void* ciphertext)
{
	int r;
	mbedtls_aes_context ctx;

	mbedtls_aes_init(&ctx);

	r = mbedtls_aes_setkey_enc(&ctx, key, 192);
	if (r) {
		r = -1;
		goto exit;
	}

	r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);
	if (r) {
		r = -2;
		goto exit;
	}

exit:
	// Cleanup
	mbedtls_aes_free(&ctx);

	return r;
}

static int dukpt_aes256_ecb_encrypt(const void* key, const void* plaintext, void* ciphertext)
{
	int r;
	mbedtls_aes_context ctx;

	mbedtls_aes_init(&ctx);

	r = mbedtls_aes_setkey_enc(&ctx, key, 256);
	if (r) {
		r = -1;
		goto exit;
	}

	r = mbedtls_aes_crypt_ecb(&ctx, MBEDTLS_AES_ENCRYPT, plaintext, ciphertext);
	if (r) {
		r = -2;
		goto exit;
	}

exit:
	// Cleanup
	mbedtls_aes_free(&ctx);

	return r;
}

#endif

__attribute__((noinline))
static void dukpt_memset_s(void* ptr, size_t len)
{
	memset(ptr, 0, len);

	// From GCC documentation:
	// If the function does not have side effects, there are optimizations
	// other than inlining that cause function calls to be optimized away,
	// although the function call is live. To keep such calls from being
	// optimized away, put...
	__asm__ ("");
}

static int dukpt_aes_create_derivation_data(
	enum dukpt_aes_key_usage_t key_usage,
	enum dukpt_aes_algorithm_t key_type,
	const uint8_t* ikid,
	uint32_t tc,
	struct dukpt_aes_derivation_data_t* derivation_data
)
{
	// Create key derivation data
	// See ANSI X9.24-3:2017 6.3.3

	derivation_data->version = DUKPT_AES_DERIVATION_DATA_VERSION;
	derivation_data->key_block_counter = 1;
	derivation_data->key_usage = htons(key_usage);

	// Key type determines the algorithm for which the derived key will be used
	// as well as the length of the derived key
	// See ANSI X9.24-3:2017 6.2.2
	derivation_data->algorithm = htons(key_type);
	switch (key_type) {
		case DUKPT_AES_ALGORITHM_2TDEA:
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_2TDEA);
			break;

		case DUKPT_AES_ALGORITHM_3TDEA:
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_3TDEA);
			break;

		case DUKPT_AES_ALGORITHM_AES128:
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_AES128);
			break;

		case DUKPT_AES_ALGORITHM_AES192:
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_AES192);
			break;

		case DUKPT_AES_ALGORITHM_AES256:
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_AES256);
			break;

		default:
			// Unsupported key type
			return 1;
	}

	// Key usage determines the KSN data to be used
	switch (key_usage) {
		case DUKPT_AES_KEY_USAGE_KEY_DERIVATION_INITIAL_KEY: {
			// Initial key derivation uses full initial key ID
			memcpy(derivation_data->ksn_data, ikid, DUKPT_AES_IK_ID_LEN);
			break;
		}

		case DUKPT_AES_KEY_USAGE_KEY_DERIVATION: {
			// Intermediate key derivation uses rightmost half of
			// initial key ID together with transaction counter
			uint32_t tc_msb = htonl(tc); // Must be big endian
			memcpy(derivation_data->ksn_data, ikid + DUKPT_AES_BDK_ID_LEN, DUKPT_AES_DERIVATION_ID_LEN);
			memcpy(derivation_data->ksn_data + DUKPT_AES_DERIVATION_ID_LEN, &tc_msb, DUKPT_AES_TC_LEN);
			break;
		}

		default: {
			// Working key derivation uses rightmost half of
			// initial key ID together with transaction counter
			uint32_t tc_msb = htonl(tc); // Must be big endian
			memcpy(derivation_data->ksn_data, ikid + DUKPT_AES_BDK_ID_LEN, DUKPT_AES_DERIVATION_ID_LEN);
			memcpy(derivation_data->ksn_data + DUKPT_AES_DERIVATION_ID_LEN, &tc_msb, DUKPT_AES_TC_LEN);
			break;
		}
	}

	return 0;
}

static int dukpt_aes_derive_key(
	enum dukpt_aes_key_type_t key_type,
	const void* key,
	struct dukpt_aes_derivation_data_t* derivation_data,
	void* derived_key
)
{
	int r;
	size_t derived_key_len;
	aes_ecb_encrypt_func_t aes_ecb_encrypt;

	// Determine derived key length in bytes
	derived_key_len = ntohs(derivation_data->length) / 8;

	// Key type determines derivation algorithm
	switch (key_type) {
		case DUKPT_AES_KEY_TYPE_AES128:
			aes_ecb_encrypt = &dukpt_aes128_ecb_encrypt;
			break;

		case DUKPT_AES_KEY_TYPE_AES192:
			aes_ecb_encrypt = &dukpt_aes192_ecb_encrypt;
			break;

		case DUKPT_AES_KEY_TYPE_AES256:
			aes_ecb_encrypt = &dukpt_aes256_ecb_encrypt;
			break;

		default:
			// Only AES may be used for derivation
			// See ANSI X9.24-3:2017 6.3.1
			r = -1;
			goto error;
	}

	// Derive key material
	// See ANSI X9.24-3:2017 6.3.1
	for (size_t key_len = 0; key_len < derived_key_len; key_len += AES_BLOCK_SIZE) {
		// Each AES ECB computation provides key material of length AES_BLOCK_SIZE
		r = aes_ecb_encrypt(key, derivation_data, derived_key + key_len);
		if (r) {
			goto error;
		}

		// Increment block counter for each block of key material
		// See ANSI X9.24-3:2017 6.3.2 table 2 and table 3
		++derivation_data->key_block_counter;
	}

	// Success
	r = 0;
	goto exit;

error:
	// TODO: randomise instead
	dukpt_memset_s(derived_key, derived_key_len);
exit:
	return r;
}
