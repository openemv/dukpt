/**
 * @file dukpt_aes.c
 * @brief ANSI X9.24-3:2017 AES DUKPT implementation
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

#include "dukpt_aes.h"
#include "dukpt_config.h"

#include "crypto_aes.h"
#include "crypto_hmac.h"
#include "crypto_mem.h"
#include "crypto_rand.h"

#include "pinblock.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#if defined(HAVE_ARPA_INET_H)
#include <arpa/inet.h> // for htons and friends
#elif defined(HAVE_WINSOCK_H)
#include <winsock.h>
#endif

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

static int dukpt_aes_get_derivation_key_type(size_t key_len, enum dukpt_aes_key_type_t* key_type)
{
	switch (key_len) {
		case DUKPT_AES_KEY_LEN(AES128):
			*key_type = DUKPT_AES_KEY_TYPE_AES128;
			return 0;

		case DUKPT_AES_KEY_LEN(AES192):
			*key_type = DUKPT_AES_KEY_TYPE_AES192;
			return 0;

		case DUKPT_AES_KEY_LEN(AES256):
			*key_type = DUKPT_AES_KEY_TYPE_AES256;
			return 0;

		default:
			// Invalid AES key length
			return 1;
	}
}

static int dukpt_aes_get_working_key_length_aes(size_t txn_key_len, enum dukpt_aes_key_type_t key_type, size_t* working_key_len)
{
	// Validate transaction/intermediate key length
	if (txn_key_len != DUKPT_AES_KEY_LEN(AES128) &&
		txn_key_len != DUKPT_AES_KEY_LEN(AES192) &&
		txn_key_len != DUKPT_AES_KEY_LEN(AES256)
	) {
		return 1;
	}

	// Determine key length from key type
	switch (key_type) {
		case DUKPT_AES_KEY_TYPE_AES128:
			*working_key_len = DUKPT_AES_KEY_LEN(AES128);
			break;

		case DUKPT_AES_KEY_TYPE_AES192:
			*working_key_len = DUKPT_AES_KEY_LEN(AES192);
			break;

		case DUKPT_AES_KEY_TYPE_AES256:
			*working_key_len = DUKPT_AES_KEY_LEN(AES256);
			break;

		default:
			// Unsupported key type
			return 2;
	}

	if (*working_key_len > txn_key_len) {
		// Working keys shall be the same strength or weaker than the key from
		// which they are derived
		// See ANSI X9.24-3:2017 6.1.3
		return 3;
	}

	return 0;
}

static int dukpt_aes_get_working_key_length_hmac(size_t txn_key_len, enum dukpt_aes_key_type_t key_type, size_t* working_key_len)
{
	// Validate transaction/intermediate key length
	if (txn_key_len != DUKPT_AES_KEY_LEN(AES128) &&
		txn_key_len != DUKPT_AES_KEY_LEN(AES192) &&
		txn_key_len != DUKPT_AES_KEY_LEN(AES256)
	) {
		return 1;
	}

	// Determine key length from key type
	switch (key_type) {
		case DUKPT_AES_KEY_TYPE_HMAC128:
			*working_key_len = DUKPT_AES_KEY_LEN(HMAC128);
			break;

		case DUKPT_AES_KEY_TYPE_HMAC192:
			*working_key_len = DUKPT_AES_KEY_LEN(HMAC192);
			break;

		case DUKPT_AES_KEY_TYPE_HMAC256:
			*working_key_len = DUKPT_AES_KEY_LEN(HMAC256);
			break;

		default:
			// Unsupported key type
			return 2;
	}

	if (*working_key_len > txn_key_len) {
		// Working keys shall be the same strength or weaker than the key from
		// which they are derived
		// See ANSI X9.24-3:2017 6.1.3
		return 3;
	}

	return 0;
}

static int dukpt_aes_create_derivation_data(
	enum dukpt_aes_key_usage_t key_usage,
	enum dukpt_aes_key_type_t key_type,
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
	switch (key_type) {
		case DUKPT_AES_KEY_TYPE_TDES2:
			derivation_data->algorithm = htons(DUKPT_AES_ALGORITHM_2TDEA);
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_TDES2);
			break;

		case DUKPT_AES_KEY_TYPE_TDES3:
			derivation_data->algorithm = htons(DUKPT_AES_ALGORITHM_3TDEA);
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_TDES3);
			break;

		case DUKPT_AES_KEY_TYPE_AES128:
			derivation_data->algorithm = htons(DUKPT_AES_ALGORITHM_AES128);
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_AES128);
			break;

		case DUKPT_AES_KEY_TYPE_AES192:
			derivation_data->algorithm = htons(DUKPT_AES_ALGORITHM_AES192);
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_AES192);
			break;

		case DUKPT_AES_KEY_TYPE_AES256:
			derivation_data->algorithm = htons(DUKPT_AES_ALGORITHM_AES256);
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_AES256);
			break;

		case DUKPT_AES_KEY_TYPE_HMAC128:
			derivation_data->algorithm = htons(DUKPT_AES_ALGORITHM_HMAC);
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_HMAC128);
			break;

		case DUKPT_AES_KEY_TYPE_HMAC192:
			derivation_data->algorithm = htons(DUKPT_AES_ALGORITHM_HMAC);
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_HMAC192);
			break;

		case DUKPT_AES_KEY_TYPE_HMAC256:
			derivation_data->algorithm = htons(DUKPT_AES_ALGORITHM_HMAC);
			derivation_data->length = htons(DUKPT_AES_KEY_BITS_HMAC256);
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
	const void* key,
	size_t key_len,
	struct dukpt_aes_derivation_data_t* derivation_data,
	void* derived_key
)
{
	int r;
	size_t derived_key_len;

	// Use separate output buffer to avoid overriding the input key if it
	// happens to use the same buffer as the derived key
	uint8_t derived_key_output[DUKPT_AES_KEY_LEN(AES256)];

	// Determine derived key length in bytes
	derived_key_len = ntohs(derivation_data->length) / 8;

	// Derive key material
	// See ANSI X9.24-3:2017 6.3.1
	for (size_t offset = 0; offset < derived_key_len; offset += AES_BLOCK_SIZE) {
		// Each AES ECB computation provides key material of length AES_BLOCK_SIZE
		r = crypto_aes_encrypt(key, key_len, NULL, derivation_data, AES_BLOCK_SIZE, derived_key_output + offset);
		if (r) {
			goto error;
		}

		// Increment block counter for each block of key material
		// See ANSI X9.24-3:2017 6.3.2 table 2 and table 3
		++derivation_data->key_block_counter;
	}

	// Success
	memcpy(derived_key, derived_key_output, derived_key_len);
	r = 0;
	goto exit;

error:
	crypto_cleanse(derived_key, derived_key_len);
exit:
	crypto_cleanse(derived_key_output, sizeof(derived_key_output));
	return r;
}

const char* dukpt_aes_lib_version_string(void)
{
	return DUKPT_LIB_VERSION_STRING;
}

int dukpt_aes_derive_ik(
	const void* bdk,
	size_t bdk_len,
	const uint8_t* ikid,
	void* ik
)
{
	int r;
	enum dukpt_aes_key_type_t key_type;
	struct dukpt_aes_derivation_data_t derivation_data;

	// Determine key type from key length
	// Only AES may be used for derivation
	// See ANSI X9.24-3:2017 6.3.1
	r = dukpt_aes_get_derivation_key_type(bdk_len, &key_type);
	if (r) {
		goto error;
	}

	// Create key derivation data
	// See ANSI X9.24-3:2017 6.3.3
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_KEY_DERIVATION_INITIAL_KEY,
		key_type,
		ikid,
		0,
		&derivation_data
	);
	if (r) {
		goto error;
	}

	// Derive initial key
	// See ANSI X9.24-3:2017 6.3.1
	r = dukpt_aes_derive_key(
		bdk,
		bdk_len,
		&derivation_data,
		ik
	);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that output key is unusable on error
	crypto_rand(ik, bdk_len);
exit:
	crypto_cleanse(&derivation_data, sizeof(derivation_data));

	return r;
}

static uint32_t dukpt_aes_ksn_get_tc(const uint8_t* ksn)
{
	uint32_t tc;

	memcpy(&tc, ksn + DUKPT_AES_IK_ID_LEN, DUKPT_AES_TC_LEN);
	return ntohl(tc);
}

int dukpt_aes_derive_txn_key(
	const void* ik,
	size_t ik_len,
	const uint8_t* ksn,
	void* txn_key
)
{
	int r;
	size_t txn_key_len;
	enum dukpt_aes_key_type_t key_type;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint32_t tc;
	uint32_t working_tc;

	// This process is explained in ANSI X9.24-3:2017 6.1 and 6.3.1
	// A recursive description of the process would be that the key associated
	// with a specific KSN is derived from the key associated with a KSN
	// formed by unsettign the least significant transaction counter bit set
	// in the previous KSN. When no transaction counter bits are set, the
	// associated key is the IK.

	// An iterative description of the process would be that one starts with
	// the IK and IKSN, thus no transaction bits are set, and then derives
	// each subsequent key from the previous key according to the transaction
	// counter bits. For each bit set in the transaction counter, starting at
	// the most most significant bit set, the corresponding bit is set in the
	// KSN and the next key is derived from the previous key and this KSN.
	// This continues until the last key is derived when the KSN contains all
	// the set bits of the transaction counter.

	// Start with Initial Key (IK) and current Transaction Counter
	memcpy(txn_key, ik, ik_len);
	txn_key_len = ik_len;
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Determine key type from key length
	// Only AES may be used for derivation
	// See ANSI X9.24-3:2017 6.3.1
	r = dukpt_aes_get_derivation_key_type(ik_len, &key_type);
	if (r) {
		goto error;
	}

	// For each mask bit, starting at the highest bit:
	// If the corresponding bit in the transaction counter is set, then set
	// the corresponding bit in the KSN register and derive the next key from
	// the previous key.
	working_tc = 0;
	for (uint32_t mask = 0x80000000; mask != 0; mask >>= 1) {
		if ((tc & mask) == 0) {
			// Transaction counter bit not set; skip
			continue;
		}

		working_tc |= mask;

		// Create key derivation data
		// See ANSI X9.24-3:2017 6.3.3
		r = dukpt_aes_create_derivation_data(
			DUKPT_AES_KEY_USAGE_KEY_DERIVATION,
			key_type,
			ksn,
			working_tc,
			&derivation_data
		);
		if (r) {
			goto error;
		}

		// Derive current derivation key from previous derivation key
		// See ANSI X9.24-3:2017 6.4
		r = dukpt_aes_derive_key(
			txn_key,
			txn_key_len,
			&derivation_data,
			txn_key
		);
		if (r) {
			goto error;
		}
	}

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that output key is unusable on error
	crypto_rand(txn_key, txn_key_len);
exit:
	crypto_cleanse(&derivation_data, sizeof(derivation_data));

	return r;
}

int dukpt_aes_ksn_advance(uint8_t* ksn)
{
	uint32_t tc;

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);
	if (tc > DUKPT_AES_TC_MAX) {
		// Transaction already counter exhausted
		return 1;
	}

	// Advance to next possible transaction counter
	++tc;

	// Loop continues until transaction counter is exhausted or
	// until a valid transaction counter is found
	while (tc <= DUKPT_AES_TC_MAX) {
		unsigned int bit_count;

		// Count number of bits in transaction counter
#ifdef HAS_BUILTIN_POPCOUNT
		bit_count = __builtin_popcount(tc);
#else
		// Use optimised bit counting algorithm discovered by:
		// * Peter Wegner, CACM 3 (1960)
		// * Derrick Lehmer (1964)
		// * Brian W. Kernighan and Dennis M. Ritchie, C Programming Language 2nd Ed (1988)
		// This loop will only have as many iterations as there are set bits
		// in the transaction counter
		bit_count = 0;
		for (uint32_t tmp = tc; tmp != 0; ++bit_count) {
			// Clear least significant bit
			tmp &= tmp - 1;
		}
#endif

		// Transaction counter should have 16 or fewer "one" bits
		// See ANSI X9.24-3:2017 6.1 Algorithm Description
		if (bit_count <= 16) {
			// Current transaction counter is valid
			break;
		}

		// Use some bit magic to find the least significant set bit
		// tc - 1 unsets the least significant set bit
		// ~(tc - 1) inverts it such that all previously set bits are unset,
		// except for the previously least significant set bit
		uint32_t lsb_set_bit = tc & ~(tc - 1);

		// Advance to next possible transaction counter
		// If the least significant bit is not set, simply incrementing by one
		// still yield an invalid transaction counter. And if more than one of
		// the lowest bits are not set, it would require many iterations to
		// reach the next valid transaction counter. A better approach is to
		// add the least significant set bit which will either yield the same
		// number of set bits or fewer set bits.
		tc += lsb_set_bit;
	}

	// Update KSN with latest transaction counter
	uint32_t tc_msb = htonl(tc); // Must be big endian
	memcpy(ksn + DUKPT_AES_IK_ID_LEN, &tc_msb, DUKPT_AES_TC_LEN);

	if (tc > DUKPT_AES_TC_MAX) {
		// Transaction counter exhausted
		return 2;
	}

	// Transaction counter valid
	return 0;
}

bool dukpt_aes_ksn_is_valid(const uint8_t* ksn)
{
	uint32_t tc;
	unsigned int bit_count;

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);
	if (tc == 0) {
		// Transaction counter is absent
		return false;
	}

	// Count number of bits in transaction counter
#ifdef HAS_BUILTIN_POPCOUNT
	bit_count = __builtin_popcount(tc);
#else
	// Use optimised bit counting algorithm discovered by:
	// * Peter Wegner, CACM 3 (1960)
	// * Derrick Lehmer (1964)
	// * Brian W. Kernighan and Dennis M. Ritchie, C Programming Language 2nd Ed (1988)
	// This loop will only have as many iterations as there are set bits
	// in the transaction counter
	bit_count = 0;
	for (uint32_t tmp = tc; tmp != 0; ++bit_count) {
		// Clear least significant bit
		tmp &= tmp - 1;
	}
#endif

	// Transaction counter should have 16 or fewer "one" bits
	// See ANSI X9.24-3:2017 6.1 Algorithm Description
	if (bit_count > 16) {
		// Too many bits in transaction counter
		return false;
	}

	// Valid
	return true;
}

bool dukpt_aes_ksn_is_exhausted(const uint8_t* ksn)
{
	uint32_t tc;

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);
	if (tc > DUKPT_AES_TC_MAX) {
		// Transaction counter exhausted
		return true;
	}

	// Transaction counter not exhausted
	return false;
}

int dukpt_aes_derive_update_key(
	const void* ik,
	size_t ik_len,
	const uint8_t* ikid,
	enum dukpt_aes_key_type_t key_type,
	void* update_key
)
{
	int r;
	uint8_t ksn[DUKPT_AES_KSN_LEN];
	uint8_t txn_key[DUKPT_AES_KEY_LEN(AES256)];
	size_t update_key_len;
	struct dukpt_aes_derivation_data_t derivation_data;

	// Determine length of update key
	// This function only supports AES update keys
	r = dukpt_aes_get_working_key_length_aes(
		ik_len,
		key_type,
		&update_key_len
	);
	if (r) {
		return r;
	}

	// Prepare KSN with transaction counter 0xFFFFFFFF
	// See ANSI X9.24-3:2017 6.5.2 Transaction Counter
	memcpy(ksn, ikid, DUKPT_AES_IK_ID_LEN);
	memset(ksn + DUKPT_AES_IK_ID_LEN, 0xFF, DUKPT_AES_TC_LEN);

	// Derive transaction key for transaction counter 0xFFFFFFFF
	// See ANSI X9.24-3:2017 6.5.3 Calculate DUKPT Update Key
	r = dukpt_aes_derive_txn_key(ik, ik_len, ksn, txn_key);
	if (r) {
		goto error;
	}

	// Derive update key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_KEY_ENCRYPTION_KEY,
		key_type,
		ikid,
		0xFFFFFFFF,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		ik_len,
		&derivation_data,
		update_key
	);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that output key is unusable on error
	crypto_rand(update_key, update_key_len);
exit:
	crypto_cleanse(txn_key, sizeof(txn_key));
	return r;
}

int dukpt_aes_encrypt_pinblock(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const uint8_t* pinfield,
	const uint8_t* pan,
	size_t pan_len,
	void* ciphertext
)
{
	int r;
	uint32_t tc;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint8_t pin_key[DUKPT_AES_KEY_LEN(AES256)];
	size_t pin_key_len;
	uint8_t panfield[DUKPT_AES_PINBLOCK_LEN];

	// Determine length of PIN key
	// This function only supports AES PIN keys
	r = dukpt_aes_get_working_key_length_aes(
		txn_key_len,
		key_type,
		&pin_key_len
	);
	if (r) {
		return r;
	}

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Derive PIN key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_PIN_ENCRYPTION,
		key_type,
		ksn,
		tc,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		txn_key_len,
		&derivation_data,
		pin_key
	);
	if (r) {
		goto error;
	}

	// Encode PAN field
	r = pinblock_encode_iso9564_format4_panfield(
		pan,
		pan_len,
		panfield
	);
	if (r) {
		// PAN field encoding failed
		goto error;
	}

	// Encrypt PIN block
	// See ISO 9564-1:2017 9.4.2.3
	r = crypto_aes_encrypt(pin_key, pin_key_len, NULL, pinfield, DUKPT_AES_PINBLOCK_LEN, ciphertext);
	if (r) {
		goto error;
	}

	crypto_xor(ciphertext, panfield, DUKPT_AES_PINBLOCK_LEN);

	r = crypto_aes_encrypt(pin_key, pin_key_len, NULL, ciphertext, DUKPT_AES_PINBLOCK_LEN, ciphertext);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(ciphertext, DUKPT_AES_PINBLOCK_LEN);
exit:
	crypto_cleanse(pin_key, sizeof(pin_key));
	crypto_cleanse(panfield, sizeof(panfield));

	return r;
}

int dukpt_aes_decrypt_pinblock(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* ciphertext,
	const uint8_t* pan,
	size_t pan_len,
	uint8_t* pinfield
)
{
	int r;
	uint32_t tc;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint8_t pin_key[DUKPT_AES_KEY_LEN(AES256)];
	size_t pin_key_len;
	uint8_t panfield[DUKPT_AES_PINBLOCK_LEN];

	// Determine length of PIN key
	// This function only supports AES PIN keys
	r = dukpt_aes_get_working_key_length_aes(
		txn_key_len,
		key_type,
		&pin_key_len
	);
	if (r) {
		return r;
	}

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Derive PIN key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_PIN_ENCRYPTION,
		key_type,
		ksn,
		tc,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		txn_key_len,
		&derivation_data,
		pin_key
	);
	if (r) {
		goto error;
	}

	// Encode PAN field
	r = pinblock_encode_iso9564_format4_panfield(
		pan,
		pan_len,
		panfield
	);
	if (r) {
		// PAN field encoding failed
		goto error;
	}

	// Decrypt PIN block
	// See ISO 9564-1:2017 9.4.2.4
	r = crypto_aes_decrypt(pin_key, pin_key_len, NULL, ciphertext, DUKPT_AES_PINBLOCK_LEN, pinfield);
	if (r) {
		goto error;
	}

	crypto_xor(pinfield, panfield, DUKPT_AES_PINBLOCK_LEN);

	r = crypto_aes_decrypt(pin_key, pin_key_len, NULL, pinfield, DUKPT_AES_PINBLOCK_LEN, pinfield);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(pinfield, DUKPT_AES_PINBLOCK_LEN);
exit:
	crypto_cleanse(pin_key, sizeof(pin_key));
	crypto_cleanse(panfield, sizeof(panfield));

	return r;
}

int dukpt_aes_encrypt_pin(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* pan,
	size_t pan_len,
	void* ciphertext
)
{
	int r;
	uint8_t pinfield[DUKPT_AES_PINBLOCK_LEN];

	// Encode PIN field
	r = pinblock_encode_iso9564_format4_pinfield(
		pin,
		pin_len,
		pinfield
	);
	if (r) {
		// PIN field encoding failed
		r = 1;
		goto error;
	}

	// Encrypt PIN block
	r = dukpt_aes_encrypt_pinblock(
		txn_key,
		txn_key_len,
		ksn,
		key_type,
		pinfield,
		pan,
		pan_len,
		ciphertext
	);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(ciphertext, DUKPT_AES_PINBLOCK_LEN);
exit:
	crypto_cleanse(pinfield, sizeof(pinfield));

	return r;
}

int dukpt_aes_decrypt_pin(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* ciphertext,
	const uint8_t* pan,
	size_t pan_len,
	void* pin,
	size_t* pin_len
)
{
	int r;
	uint8_t pinfield[DUKPT_AES_PINBLOCK_LEN];

	// Decrypt PIN block
	r = dukpt_aes_decrypt_pinblock(
		txn_key,
		txn_key_len,
		ksn,
		key_type,
		ciphertext,
		pan,
		pan_len,
		pinfield
	);
	if (r) {
		goto error;
	}

	// Decode PIN field
	r = pinblock_decode_iso9564_format4_pinfield(
		pinfield,
		sizeof(pinfield),
		pin,
		pin_len
	);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	*pin_len = 0;
exit:
	crypto_cleanse(pinfield, sizeof(pinfield));

	return r;
}

int dukpt_aes_generate_request_cmac(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* buf,
	size_t buf_len,
	void* cmac
)
{
	int r;
	uint32_t tc;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint8_t cmac_key[DUKPT_AES_KEY_LEN(AES256)];
	size_t cmac_key_len;

	// Determine length of CMAC key
	// This function only supports AES CMAC keys
	r = dukpt_aes_get_working_key_length_aes(
		txn_key_len,
		key_type,
		&cmac_key_len
	);
	if (r) {
		return r;
	}

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Derive AES CMAC key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_MAC_GENERATION,
		key_type,
		ksn,
		tc,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		txn_key_len,
		&derivation_data,
		cmac_key
	);
	if (r) {
		goto error;
	}

	// Generate AES-CMAC
	r = crypto_aes_cmac(cmac_key, cmac_key_len, buf, buf_len, cmac);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(cmac, DUKPT_AES_CMAC_LEN);
exit:
	crypto_cleanse(cmac_key, sizeof(cmac_key));

	return r;
}

int dukpt_aes_verify_request_cmac(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* buf,
	size_t buf_len,
	const void* cmac
)
{
	int r;
	uint8_t cmac_verify[DUKPT_AES_CMAC_LEN];

	r = dukpt_aes_generate_request_cmac(
		txn_key,
		txn_key_len,
		ksn,
		key_type,
		buf,
		buf_len,
		cmac_verify
	);
	if (r) {
		goto error;
	}

	if (crypto_memcmp_s(cmac_verify, cmac, sizeof(cmac_verify)) != 0) {
		r = 1;
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
exit:
	crypto_cleanse(cmac_verify, sizeof(cmac_verify));

	return r;
}

int dukpt_aes_generate_response_cmac(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* buf,
	size_t buf_len,
	void* cmac
)
{
	int r;
	uint32_t tc;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint8_t cmac_key[DUKPT_AES_KEY_LEN(AES256)];
	size_t cmac_key_len;

	// Determine length of CMAC key
	// This function only supports AES CMAC keys
	r = dukpt_aes_get_working_key_length_aes(
		txn_key_len,
		key_type,
		&cmac_key_len
	);
	if (r) {
		return r;
	}

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Derive AES CMAC key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_MAC_VERIFICATION,
		key_type,
		ksn,
		tc,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		txn_key_len,
		&derivation_data,
		cmac_key
	);
	if (r) {
		goto error;
	}

	// Generate AES-CMAC
	r = crypto_aes_cmac(cmac_key, cmac_key_len, buf, buf_len, cmac);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(cmac, DUKPT_AES_CMAC_LEN);
exit:
	crypto_cleanse(cmac_key, sizeof(cmac_key));

	return r;
}

int dukpt_aes_verify_response_cmac(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* buf,
	size_t buf_len,
	const void* cmac
)
{
	int r;
	uint8_t cmac_verify[DUKPT_AES_CMAC_LEN];

	r = dukpt_aes_generate_response_cmac(
		txn_key,
		txn_key_len,
		ksn,
		key_type,
		buf,
		buf_len,
		cmac_verify
	);
	if (r) {
		goto error;
	}

	if (crypto_memcmp_s(cmac_verify, cmac, sizeof(cmac_verify)) != 0) {
		r = 1;
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
exit:
	crypto_cleanse(cmac_verify, sizeof(cmac_verify));

	return r;
}

int dukpt_aes_generate_request_hmac_sha256(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* buf,
	size_t buf_len,
	void* hmac
)
{
	int r;
	uint32_t tc;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint8_t hmac_key[DUKPT_AES_KEY_LEN(HMAC256)];
	size_t hmac_key_len;

	// Determine length of HMAC key
	r = dukpt_aes_get_working_key_length_hmac(
		txn_key_len,
		key_type,
		&hmac_key_len
	);
	if (r) {
		return r;
	}

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Derive HMAC key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_MAC_GENERATION,
		key_type,
		ksn,
		tc,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		txn_key_len,
		&derivation_data,
		hmac_key
	);
	if (r) {
		goto error;
	}

	// Generate HMAC
	r = crypto_hmac_sha256(hmac_key, hmac_key_len, buf, buf_len, hmac);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(hmac, DUKPT_AES_HMAC_SHA256_LEN);
exit:
	crypto_cleanse(hmac_key, sizeof(hmac_key));

	return r;
}

int dukpt_aes_verify_request_hmac_sha256(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* buf,
	size_t buf_len,
	const void* hmac
)
{
	int r;
	uint8_t hmac_verify[DUKPT_AES_HMAC_SHA256_LEN];

	r = dukpt_aes_generate_request_hmac_sha256(
		txn_key,
		txn_key_len,
		ksn,
		key_type,
		buf,
		buf_len,
		hmac_verify
	);
	if (r) {
		goto error;
	}

	if (crypto_memcmp_s(hmac_verify, hmac, sizeof(hmac_verify)) != 0) {
		r = 1;
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
exit:
	crypto_cleanse(hmac_verify, sizeof(hmac_verify));

	return r;
}

int dukpt_aes_generate_response_hmac_sha256(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* buf,
	size_t buf_len,
	void* hmac
)
{
	int r;
	uint32_t tc;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint8_t hmac_key[DUKPT_AES_KEY_LEN(HMAC256)];
	size_t hmac_key_len;

	// Determine length of HMAC key
	r = dukpt_aes_get_working_key_length_hmac(
		txn_key_len,
		key_type,
		&hmac_key_len
	);
	if (r) {
		return r;
	}

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Derive HMAC key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_MAC_VERIFICATION,
		key_type,
		ksn,
		tc,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		txn_key_len,
		&derivation_data,
		hmac_key
	);
	if (r) {
		goto error;
	}

	// Generate HMAC
	r = crypto_hmac_sha256(hmac_key, hmac_key_len, buf, buf_len, hmac);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(hmac, DUKPT_AES_HMAC_SHA256_LEN);
exit:
	crypto_cleanse(hmac_key, sizeof(hmac_key));

	return r;
}

int dukpt_aes_verify_response_hmac_sha256(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* buf,
	size_t buf_len,
	const void* hmac
)
{
	int r;
	uint8_t hmac_verify[DUKPT_AES_HMAC_SHA256_LEN];

	r = dukpt_aes_generate_response_hmac_sha256(
		txn_key,
		txn_key_len,
		ksn,
		key_type,
		buf,
		buf_len,
		hmac_verify
	);
	if (r) {
		goto error;
	}

	if (crypto_memcmp_s(hmac_verify, hmac, sizeof(hmac_verify)) != 0) {
		r = 1;
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
exit:
	crypto_cleanse(hmac_verify, sizeof(hmac_verify));

	return r;
}

int dukpt_aes_encrypt_request(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* iv,
	const void* buf,
	size_t buf_len,
	void* ciphertext
)
{
	int r;
	uint32_t tc;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint8_t data_key[DUKPT_AES_KEY_LEN(AES256)];
	size_t data_key_len;

	// Determine length of data encryption key
	// This function only supports AES keys
	r = dukpt_aes_get_working_key_length_aes(
		txn_key_len,
		key_type,
		&data_key_len
	);
	if (r) {
		return r;
	}

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Derive data encryption key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_DATA_ENCRYPTION_ENCRYPT,
		key_type,
		ksn,
		tc,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		txn_key_len,
		&derivation_data,
		data_key
	);
	if (r) {
		goto error;
	}

	// Encrypt transaction data
	r = crypto_aes_encrypt(data_key, data_key_len, iv, buf, buf_len, ciphertext);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(ciphertext, buf_len);
exit:
	crypto_cleanse(data_key, sizeof(data_key));

	return r;
}

int dukpt_aes_decrypt_request(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* iv,
	const void* buf,
	size_t buf_len,
	void* plaintext
)
{
	int r;
	uint32_t tc;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint8_t data_key[DUKPT_AES_KEY_LEN(AES256)];
	size_t data_key_len;

	// Determine length of data encryption key
	// This function only supports AES keys
	r = dukpt_aes_get_working_key_length_aes(
		txn_key_len,
		key_type,
		&data_key_len
	);
	if (r) {
		return r;
	}

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Derive data encryption key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_DATA_ENCRYPTION_ENCRYPT,
		key_type,
		ksn,
		tc,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		txn_key_len,
		&derivation_data,
		data_key
	);
	if (r) {
		goto error;
	}

	// Decrypt transaction data
	r = crypto_aes_decrypt(data_key, data_key_len, iv, buf, buf_len, plaintext);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(plaintext, buf_len);
exit:
	crypto_cleanse(data_key, sizeof(data_key));

	return r;
}

int dukpt_aes_encrypt_response(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* iv,
	const void* buf,
	size_t buf_len,
	void* ciphertext
)
{
	int r;
	uint32_t tc;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint8_t data_key[DUKPT_AES_KEY_LEN(AES256)];
	size_t data_key_len;

	// Determine length of data encryption key
	// This function only supports AES keys
	r = dukpt_aes_get_working_key_length_aes(
		txn_key_len,
		key_type,
		&data_key_len
	);
	if (r) {
		return r;
	}

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Derive data encryption key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_DATA_ENCRYPTION_DECRYPT,
		key_type,
		ksn,
		tc,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		txn_key_len,
		&derivation_data,
		data_key
	);
	if (r) {
		goto error;
	}

	// Encrypt transaction data
	r = crypto_aes_encrypt(data_key, data_key_len, iv, buf, buf_len, ciphertext);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(ciphertext, buf_len);
exit:
	crypto_cleanse(data_key, sizeof(data_key));

	return r;
}

int dukpt_aes_decrypt_response(
	const void* txn_key,
	size_t txn_key_len,
	const uint8_t* ksn,
	enum dukpt_aes_key_type_t key_type,
	const void* iv,
	const void* buf,
	size_t buf_len,
	void* plaintext
)
{
	int r;
	uint32_t tc;
	struct dukpt_aes_derivation_data_t derivation_data;
	uint8_t data_key[DUKPT_AES_KEY_LEN(AES256)];
	size_t data_key_len;

	// Determine length of data encryption key
	// This function only supports AES keys
	r = dukpt_aes_get_working_key_length_aes(
		txn_key_len,
		key_type,
		&data_key_len
	);
	if (r) {
		return r;
	}

	// Extract transaction counter value from KSN
	tc = dukpt_aes_ksn_get_tc(ksn);

	// Derive data encryption key
	r = dukpt_aes_create_derivation_data(
		DUKPT_AES_KEY_USAGE_DATA_ENCRYPTION_DECRYPT,
		key_type,
		ksn,
		tc,
		&derivation_data
	);
	if (r) {
		goto error;
	}
	r = dukpt_aes_derive_key(
		txn_key,
		txn_key_len,
		&derivation_data,
		data_key
	);
	if (r) {
		goto error;
	}

	// Decrypt transaction data
	r = crypto_aes_decrypt(data_key, data_key_len, iv, buf, buf_len, plaintext);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(plaintext, buf_len);
exit:
	crypto_cleanse(data_key, sizeof(data_key));

	return r;
}
