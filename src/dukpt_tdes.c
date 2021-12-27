/**
 * @file dukpt_tdes.c
 * @brief ANSI X9.24-1:2009 TDES DUKPT implementation
 *        (equivalent to ANSI X9.24-3:2017 Annex C)
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

#include "dukpt_tdes.h"
#include "dukpt_config.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

// Helper functions
static int dukpt_des_encrypt_ecb(const void* key, const void* plaintext, void* ciphertext);
static int dukpt_tdes2_encrypt_ecb(const void* key, const void* plaintext, void* ciphertext);
static int dukpt_tdes2_decrypt_ecb(const void* key, const void* ciphertext, void* plaintext);
static void dukpt_memset_s(void* ptr, size_t len);

#ifdef MBEDTLS_FOUND

#include <mbedtls/des.h>

static int dukpt_des_encrypt_ecb(const void* key, const void* plaintext, void* ciphertext)
{
	int r;
	mbedtls_des_context ctx;

	mbedtls_des_init(&ctx);

	r = mbedtls_des_setkey_enc(&ctx, key);
	if (r) {
		r = -1;
		goto exit;
	}

	r = mbedtls_des_crypt_ecb(&ctx, plaintext, ciphertext);
	if (r) {
		r = -2;
		goto exit;
	}

exit:
	// Cleanup
	mbedtls_des_free(&ctx);

	return r;
}

static int dukpt_tdes2_encrypt_ecb(const void* key, const void* plaintext, void* ciphertext)
{
	int r;
	mbedtls_des3_context ctx;

	mbedtls_des3_init(&ctx);

	r = mbedtls_des3_set2key_enc(&ctx, key);
	if (r) {
		r = -1;
		goto exit;
	}

	r = mbedtls_des3_crypt_ecb(&ctx, plaintext, ciphertext);
	if (r) {
		r = -2;
		goto exit;
	}

exit:
	// Cleanup
	mbedtls_des3_free(&ctx);

	return r;
}

static int dukpt_tdes2_decrypt_ecb(const void* key, const void* ciphertext, void* plaintext)
{
	int r;
	mbedtls_des3_context ctx;

	mbedtls_des3_init(&ctx);

	r = mbedtls_des3_set2key_dec(&ctx, key);
	if (r) {
		r = -1;
		goto exit;
	}

	r = mbedtls_des3_crypt_ecb(&ctx, ciphertext, plaintext);
	if (r) {
		r = -2;
		goto exit;
	}

exit:
	// Cleanup
	mbedtls_des3_free(&ctx);

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

int dukpt_tdes_derive_ik(const void* bdk, const uint8_t* iksn, void* ik)
{
	int r;
	uint8_t iksn_buf[DUKPT_TDES_KSN_LEN];
	uint8_t bdk_variant[DUKPT_TDES_KEY_LEN];

	// See ANSI X9.24-1:2009 A.6 Derivation of the Initial Key
	// See ANSI X9.24-3:2017 C.7

	// Sanitise Initial Key Serial Number (IKSN)
	memcpy(iksn_buf, iksn, DUKPT_TDES_KSN_LEN);
	iksn_buf[7] &= 0xE0;
	iksn_buf[8] = 0;
	iksn_buf[9] = 0;

	// Derive left half of Initial Key (IK)
	r = dukpt_tdes2_encrypt_ecb(bdk, iksn_buf, ik);
	if (r) {
		goto error;
	}

	// Derive right half of Initial Key (IK)
	memcpy(bdk_variant, bdk, DUKPT_TDES_KEY_LEN);
	bdk_variant[0] ^= 0xC0;
	bdk_variant[1] ^= 0xC0;
	bdk_variant[2] ^= 0xC0;
	bdk_variant[3] ^= 0xC0;
	bdk_variant[8] ^= 0xC0;
	bdk_variant[9] ^= 0xC0;
	bdk_variant[10] ^= 0xC0;
	bdk_variant[11] ^= 0xC0;
	r = dukpt_tdes2_encrypt_ecb(bdk_variant, iksn_buf, ik + 8);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	// TODO: randomise instead
	dukpt_memset_s(ik, sizeof(ik));
exit:
	dukpt_memset_s(bdk_variant, sizeof(bdk_variant));

	return r;
}

static int dukpt_tdes_derive_key(const uint8_t* ksn_reg, uint8_t* key_reg, uint8_t* key_out)
{
	int r;

	// See ANSI X9.24-1:2009 A.1 Key Management
	uint8_t crypto_reg1[8];
	uint8_t crypto_reg2[8];

	// See ANSI X9.24-1:2009 A.2 Processing Algorithms "Non-reversible Key Generation Process"
	// See ANSI X9.24-3:2017 C.3.6 "Derivation process"

	// This algorithm is described in terms of crypto registers and this
	// implementation follows the same style

	// The 64 right-most bits of the Key Serial Number Register is transferred
	// into Crypto Register-1
	memcpy(crypto_reg1, ksn_reg + DUKPT_TDES_KSN_LEN - sizeof(crypto_reg1), sizeof(crypto_reg1));

	// Crypto Register-1 XORed with the right half of the Key Register goes
	// to Crypto Register-2
	for (unsigned int i = 0; i < sizeof(crypto_reg2); ++i) {
		crypto_reg2[i] = crypto_reg1[i] ^ key_reg[i + 8];
	}

	// Crypto Register-2 DEA-encrypted using, as the key, the left half of
	// the Key Register goes to Crypto Register-2
	r = dukpt_des_encrypt_ecb(key_reg, crypto_reg2, crypto_reg2);
	if (r) {
		goto error;
	}

	// Crypto Register-2 XORed with the right half of the Key Register goes
	// to Crypto Register-2
	for (unsigned int i = 0; i < sizeof(crypto_reg2); ++i) {
		crypto_reg2[i] ^= key_reg[i + 8];
	}

	// XOR the Key Register with hexadecimal C0C0 C0C0 0000 0000 C0C0 C0C0 0000 0000
	key_reg[0] ^= 0xC0;
	key_reg[1] ^= 0xC0;
	key_reg[2] ^= 0xC0;
	key_reg[3] ^= 0xC0;
	key_reg[8] ^= 0xC0;
	key_reg[9] ^= 0xC0;
	key_reg[10] ^= 0xC0;
	key_reg[11] ^= 0xC0;

	// Crypto Register-1 XORed with the right half of the Key Register goes
	// to Crypto Register-1
	for (unsigned int i = 0; i < sizeof(crypto_reg1); ++i) {
		crypto_reg1[i] ^= key_reg[i + 8];
	}

	// Crypto Register-1 DEA-encrypted using, as the key, the left half of
	// the Key Register goes to Crypto Register-1
	r = dukpt_des_encrypt_ecb(key_reg, crypto_reg1, crypto_reg1);
	if (r) {
		goto error;
	}

	// Crypto Register-1 XORed with the right half of the Key Register goes
	// to Crypto Register-1
	for (unsigned int i = 0; i < sizeof(crypto_reg1); ++i) {
		crypto_reg1[i] ^= key_reg[i + 8];
	}

	// Output key consists of Crypto Register-1 + Crypto Register-2
	memcpy(key_out, crypto_reg1, sizeof(crypto_reg1));
	memcpy(key_out + sizeof(crypto_reg1), crypto_reg2, sizeof(crypto_reg2));

	// Success
	r = 0;
	goto exit;

error:
	// TODO: randomise instead
	dukpt_memset_s(key_out, sizeof(key_out));
exit:
	dukpt_memset_s(crypto_reg1, sizeof(crypto_reg1));
	dukpt_memset_s(crypto_reg2, sizeof(crypto_reg2));

	return r;
}

static uint32_t dukpt_tdes_ksn_get_tc(const uint8_t* ksn)
{
	// Extract transaction counter value from KSN. The transaction counter is
	// the last 21 bits of the KSN.
	return
		((uint32_t)ksn[DUKPT_TDES_KSN_LEN - 1]) |
		((uint32_t)ksn[DUKPT_TDES_KSN_LEN - 2]) << 8 |
		((uint32_t)ksn[DUKPT_TDES_KSN_LEN - 3] & 0x1f) << 16
	;
}

int dukpt_tdes_derive_txn_key(const void* ik, const uint8_t* ksn, void* txn_key)
{
	int r;

	// See ANSI X9.24-1:2009 A.1 Key Management
	// See ANSI X9.24-3:2017 C.2.3 Key Management
	uint8_t key_reg[DUKPT_TDES_KEY_LEN];
	uint8_t ksn_reg[DUKPT_TDES_KSN_LEN];
	uint8_t shift_reg[3];

	// This process is explained in ANSI X9.24-1:2009 A.3 and
	// ANSI X9.24-3:2017 C.4 but the exact steps aren't described. It can
	// however be implemented by using various parts of the algorithms
	// described in ANSI X9.24-1:2009 A.2 or ANSI X9.24-3:2017 C.3.

	// These algorithm are described in terms of various registers and this
	// implementation follows the same style

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

	// Start with Initial Key (IK) and Initial Key Serial Number (IKSN)
	memcpy(key_reg, ik, sizeof(key_reg));
	memcpy(ksn_reg, ksn, DUKPT_TDES_KSN_LEN);
	ksn_reg[7] &= 0xE0;
	ksn_reg[8] = 0;
	ksn_reg[9] = 0;

	// For each shift register bit, starting at the highest bit:
	// If the corresponding bit in the transaction counter is set, then set
	// the corresponding bit in the KSN register and derive the next key from
	// the previous key.
	for (unsigned int shift_bit = DUKPT_TDES_TC_BITS; shift_bit > 0; --shift_bit) {
		// Set appropriate bit in shift register
		uint8_t shift_reg_idx = (shift_bit-1) >> 3; // Upper bits indicate byte index
		uint8_t shift_reg_val = 0x1 << ((shift_bit-1) & 0x7); // Lower bits indicate shift for byte value
		memset(shift_reg, 0, sizeof(shift_reg));
		shift_reg[shift_reg_idx] = shift_reg_val;

		// If shift bit is not set in KSN register
		if (!(shift_reg[0] & ksn[sizeof(ksn_reg) - 1 - 0]) &&
			!(shift_reg[1] & ksn[sizeof(ksn_reg) - 1 - 1]) &&
			!(shift_reg[2] & ksn[sizeof(ksn_reg) - 1 - 2])
		) {
			// Skip this shift bit
			continue;
		}

		// Set shift bit in KSN register
		for (unsigned int i = 0; i < sizeof(shift_reg); ++i) {
			ksn_reg[sizeof(ksn_reg) - 1 - i] |= shift_reg[i];
		}

		// Derive next key
		r = dukpt_tdes_derive_key(ksn_reg, key_reg, key_reg);
		if (r) {
			goto error;
		}
	}

	// Output key
	memcpy(txn_key, key_reg, sizeof(key_reg));

	// Success
	r = 0;
	goto exit;

error:
	// TODO: randomise instead
	dukpt_memset_s(txn_key, sizeof(txn_key));
exit:
	// Cleanup
	dukpt_memset_s(key_reg, sizeof(key_reg));

	return r;
}

int dukpt_tdes_ksn_advance(uint8_t* ksn)
{
	uint32_t tc;

	// Extract transaction counter value from KSN
	tc = dukpt_tdes_ksn_get_tc(ksn);
	if (tc > DUKPT_TDES_TC_MAX) {
		// Transaction already counter exhausted
		return 1;
	}

	// Advance to next possible transaction counter
	++tc;
	tc &= 0x1FFFFF;

	// Loop continues until transaction counter is exhausted or
	// until a valid transaction counter is found
	while (tc <= DUKPT_TDES_TC_MAX) {
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

		// Transaction counter should have 10 or fewer "one" bits
		// See ANSI X9.24-1:2009 A.3 Key Management Technique
		// See ANSI X9.24-3:2017 C.4 Key Management Technique
		if (bit_count <= 10) {
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
		tc &= 0x1FFFFF;
	}

	// Update KSN with latest transaction counter
	ksn[DUKPT_TDES_KSN_LEN - 1] = tc;
	ksn[DUKPT_TDES_KSN_LEN - 2] = tc >> 8;
	ksn[DUKPT_TDES_KSN_LEN - 3] &= 0xE0;
	ksn[DUKPT_TDES_KSN_LEN - 3] |= tc >> 16;

	if (tc > DUKPT_TDES_TC_MAX) {
		// Transaction counter exhausted
		return 2;
	}

	// Transaction counter valid
	return 0;
}

bool dukpt_tdes_ksn_is_valid(const uint8_t* ksn)
{
	uint32_t tc;
	unsigned int bit_count;

	// Extract transaction counter value from KSN
	tc = dukpt_tdes_ksn_get_tc(ksn);

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

	// Transaction counter should have 10 or fewer "one" bits
	// See ANSI X9.24-1:2009 A.3 Key Management Technique
	// See ANSI X9.24-3:2017 C.4 Key Management Technique
	if (bit_count > 10) {
		// Too many bits in transaction counter
		return false;
	}

	// Valid
	return true;
}

bool dukpt_tdes_ksn_is_exhausted(const uint8_t* ksn)
{
	uint32_t tc;

	// Extract transaction counter value from KSN
	tc = dukpt_tdes_ksn_get_tc(ksn);
	if (tc > DUKPT_TDES_TC_MAX) {
		// Transaction counter exhausted
		return true;
	}

	// Transaction counter not exhausted
	return false;
}

int dukpt_tdes_encrypt_pinblock(
	const void* txn_key,
	const void* pinblock,
	void* ciphertext
)
{
	int r;
	uint8_t pin_key[DUKPT_TDES_KEY_LEN];

	// Derive PIN encryption key variant
	// See ANSI X9.24-1:2009 A.4.1, table A-1
	// See ANSI X9.24-3:2017 C.5.2, table 5
	memcpy(pin_key, txn_key, DUKPT_TDES_KEY_LEN);
	pin_key[7] ^= 0xFF;
	pin_key[15] ^= 0xFF;

	// Encrypt PIN block
	r = dukpt_tdes2_encrypt_ecb(pin_key, pinblock, ciphertext);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	dukpt_memset_s(ciphertext, DUKPT_TDES_PINBLOCK_LEN);
exit:
	dukpt_memset_s(pin_key, sizeof(pin_key));

	return r;
}

int dukpt_tdes_decrypt_pinblock(
	const void* txn_key,
	const void* ciphertext,
	void* pinblock
)
{
	int r;
	uint8_t pin_key[DUKPT_TDES_KEY_LEN];

	// Derive PIN encryption key variant
	// See ANSI X9.24-1:2009 A.4.1, table A-1
	// See ANSI X9.24-3:2017 C.5.2, table 5
	memcpy(pin_key, txn_key, DUKPT_TDES_KEY_LEN);
	pin_key[7] ^= 0xFF;
	pin_key[15] ^= 0xFF;

	// Decrypt PIN block
	r = dukpt_tdes2_decrypt_ecb(pin_key, ciphertext, pinblock);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	dukpt_memset_s(pinblock, DUKPT_TDES_PINBLOCK_LEN);
exit:
	dukpt_memset_s(pin_key, sizeof(pin_key));

	return r;
}
