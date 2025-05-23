/**
 * @file dukpt_tdes.c
 * @brief ANSI X9.24-1:2009 TDES DUKPT implementation
 *        (equivalent to ANSI X9.24-3:2017 Annex C)
 *
 * Copyright 2021-2023 Leon Lynch
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

#include "crypto_tdes.h"
#include "crypto_mem.h"
#include "crypto_rand.h"

#include "pinblock.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

const char* dukpt_tdes_lib_version_string(void)
{
	return DUKPT_LIB_VERSION_STRING;
}

int dukpt_tdes_derive_ik(const void* bdk, const uint8_t* iksn, void* ik)
{
	int r;
	uint8_t iksn_buf[DUKPT_TDES_KSN_LEN];
	uint8_t bdk_variant[DUKPT_TDES_KEY_LEN];

	// See ANSI X9.24-1:2009 A.6 Derivation of the Initial Key
	// See ANSI X9.24-3:2017 C.7

	// Sanitise Initial Key Serial Number (IKSN)
	memcpy(iksn_buf, iksn, DUKPT_TDES_KSN_LEN - 2);
	iksn_buf[7] &= 0xE0;
	iksn_buf[8] = 0;
	iksn_buf[9] = 0;

	// Derive left half of Initial Key (IK)
	r = crypto_tdes2_encrypt_ecb(bdk, iksn_buf, ik);
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
	r = crypto_tdes2_encrypt_ecb(bdk_variant, iksn_buf, ik + DES_BLOCK_SIZE);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that output key is unusable on error
	crypto_rand(ik, DUKPT_TDES_KEY_LEN);
exit:
	crypto_cleanse(bdk_variant, sizeof(bdk_variant));

	return r;
}

static int dukpt_tdes_derive_key(const uint8_t* ksn_reg, uint8_t* key_reg, uint8_t* key_out)
{
	int r;

	// See ANSI X9.24-1:2009 A.1.2 Key Management
	uint8_t crypto_reg1[DES_BLOCK_SIZE];
	uint8_t crypto_reg2[DES_BLOCK_SIZE];

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
	r = crypto_des_encrypt_ecb(key_reg, crypto_reg2, crypto_reg2);
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
	r = crypto_des_encrypt_ecb(key_reg, crypto_reg1, crypto_reg1);
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
	crypto_cleanse(key_out, DUKPT_TDES_KEY_LEN);
exit:
	crypto_cleanse(crypto_reg1, sizeof(crypto_reg1));
	crypto_cleanse(crypto_reg2, sizeof(crypto_reg2));

	return r;
}

static uint32_t dukpt_tdes_ksn_get_tc(const uint8_t* ksn)
{
	// Extract transaction counter value from KSN. The transaction counter is
	// the last 21 bits of the KSN.
	return
		((uint32_t)ksn[DUKPT_TDES_KSN_LEN - 1]) |
		((uint32_t)ksn[DUKPT_TDES_KSN_LEN - 2]) << 8 |
		((uint32_t)ksn[DUKPT_TDES_KSN_LEN - 3] & 0x1F) << 16
	;
}

int dukpt_tdes_derive_txn_key(const void* ik, const uint8_t* ksn, void* txn_key)
{
	int r;

	// See ANSI X9.24-1:2009 A.1.2 Key Management
	// See ANSI X9.24-3:2017 C.2.3 Key Management
	uint8_t key_reg[DUKPT_TDES_KEY_LEN];
	uint8_t ksn_reg[DUKPT_TDES_KSN_LEN];
	uint8_t shift_reg[3];

	// This process is explained in ANSI X9.24-1:2009 A.3 and
	// ANSI X9.24-3:2017 C.4 but the exact steps aren't described. It can
	// however be implemented by using various parts of the algorithms
	// described in ANSI X9.24-1:2009 A.2 or ANSI X9.24-3:2017 C.3.

	// These algorithms are described in terms of various registers and this
	// implementation follows the same style.

	// A recursive description of the process would be that the key associated
	// with a specific KSN is derived from the key associated with a KSN
	// formed by unsetting the least significant transaction counter bit set
	// in the previous KSN. When no transaction counter bits are set, the
	// associated key is the IK.

	// An iterative description of the process would be that one starts with
	// the IK and IKSN, thus no transaction counter bits are set, and then
	// derives each subsequent key from the previous key according to the
	// transaction counter bits. For each bit set in the transaction counter,
	// starting at the most significant bit set, the corresponding bit is set
	// in the KSN and the next key is derived from the previous key and this
	// KSN. This continues until the last key is derived when the KSN contains
	// all the set bits of the transaction counter.

	// Start with Initial Key (IK) and Initial Key Serial Number (IKSN)
	memcpy(key_reg, ik, sizeof(key_reg));
	memcpy(ksn_reg, ksn, DUKPT_TDES_KSN_LEN - 2);
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
	// Ensure that output key is unusable on error
	crypto_rand(txn_key, DUKPT_TDES_KEY_LEN);
exit:
	// Cleanup
	crypto_cleanse(key_reg, sizeof(key_reg));

	return r;
}

int dukpt_tdes_state_init(const void* ik, const uint8_t* iksn, struct dukpt_tdes_state_t* state)
{
	int r;

	// See ANSI X9.24-1:2009 A.1.2 Key Management
	// See ANSI X9.24-3:2017 C.2.3 Key Management
	uint8_t key_reg[DUKPT_TDES_KEY_LEN];
	uint8_t ksn_reg[DUKPT_TDES_KSN_LEN];
	uint8_t shift_reg[3];

	// See ANSI X9.24-1:2009 A.2 Processing Algorithms "Load Initial Key"
	// See ANSI X9.24-3:2017 C.3.1
	// These algorithms are described in terms of various registers and this
	// implementation follows the same style. However, these algorithms are
	// also described in terms of a goto style program flow while this
	// implementation follows an iterative approach.

	// Each future key corresponds with a specific transaction counter bit in
	// the KSN. For each possible bit in the transaction counter, the
	// corresponding bit is set in the KSN, and the future key is then derived
	// from the IK and this KSN.

	// Sanitise Initial Key Serial Number (IKSN) and populate in DUKPT state
	memcpy(ksn_reg, iksn, DUKPT_TDES_KSN_LEN - 2);
	ksn_reg[7] &= 0xE0;
	ksn_reg[8] = 0;
	ksn_reg[9] = 0;
	memcpy(state->ksn, ksn_reg, DUKPT_TDES_KSN_LEN);

	// For each shift register bit, starting at the highest bit:
	// Set the corresponding bit in the KSN register and derive the
	// corresponding future key from the KSN register and the IK
	for (unsigned int shift_bit = DUKPT_TDES_TC_BITS; shift_bit > 0; --shift_bit) {
		// Set appropriate bit in shift register
		uint8_t shift_reg_idx = (shift_bit-1) >> 3; // Upper bits indicate byte index
		uint8_t shift_reg_val = 0x1 << ((shift_bit-1) & 0x7); // Lower bits indicate shift for byte value
		memset(shift_reg, 0, sizeof(shift_reg));
		shift_reg[shift_reg_idx] = shift_reg_val;

		// Set shift bit in KSN register
		for (uint8_t i = 0; i < sizeof(shift_reg); ++i) {
			ksn_reg[sizeof(ksn_reg) - 1 - i] = state->ksn[sizeof(ksn_reg) - 1 - i] | shift_reg[i];
		}

		// Derive future key
		// It is necessary to copy the IK to the key register because the
		// key register is modified during key derivation
		memcpy(key_reg, ik, DUKPT_TDES_KEY_LEN);
		r = dukpt_tdes_derive_key(ksn_reg, key_reg, state->key[shift_bit-1]);
		if (r) {
			goto error;
		}

		// This future key is now valid
		state->valid[shift_bit-1] = 1;
	}

	// Advance to first transaction
	r = dukpt_tdes_ksn_advance(state->ksn);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that DUKPT state is unusable
	crypto_rand(state, sizeof(*state));
exit:
	// Cleanup
	crypto_cleanse(key_reg, sizeof(key_reg));

	return r;
}

int dukpt_tdes_state_next_txn_key(struct dukpt_tdes_state_t* state, void* txn_key)
{
	int r;

	// See ANSI X9.24-1:2009 A.1.2 Key Management
	// See ANSI X9.24-3:2017 C.2.3 Key Management
	uint8_t key_reg[DUKPT_TDES_KEY_LEN];
	uint8_t ksn_reg[DUKPT_TDES_KSN_LEN];
	uint8_t shift_reg[3];
	unsigned int shift_bit;
	uint8_t current_key;

	// See ANSI X9.24-1:2009 A.2 Processing Algorithms "Request PIN Entry 1"
	// See ANSI X9.24-3:2017 C.3.2 "Request PIN Entry 1"
	// These algorithms are described in terms of various registers and this
	// implementation follows the same style. However, these algorithms are
	// also described in terms of a goto style program flow while this
	// implementation follows an iterative approach.

	// If the transaction counter is valid, the future key corresponding with
	// the least significant bit set in the transaction counter is the current
	// transaction key. After the future key state has been advanced, this
	// future key is destroyed and invalidated.

	// Note that both ANSI X9.24-1:2009 A.2 and ANSI X9.24-3:2017 C.3.2 allow
	// the algorithm to continue if the current future key is invalid while
	// this implementation assumes that the future key storage is reliable and
	// will indicate failure if the current future key is invalid.

	// When advancing the future key state, all future keys corresponding to
	// transaction counter bits lower than the least significant bit set in the
	// current transaction counter, are replaced. For each of this subset of
	// transaction counter bits, starting with the most significant bit in the
	// subset, the corresponding bit is set in the KSN and the corresponding
	// future key is then derived from the current transaction key and this
	// KSN.

	memset(key_reg, 0, sizeof(key_reg));
	memcpy(ksn_reg, state->ksn, DUKPT_TDES_KSN_LEN);
	memset(shift_reg, 0, sizeof(shift_reg));

	// Set shift register bit to least significant transaction counter bit
	// See ANSI X9.24-1:2009 A.2 Processing Algorithms "Set Bit"
	// See ANSI X9.24-3:2017 C.3.5 "Set Bit"
	for (shift_bit = 0; shift_bit < DUKPT_TDES_TC_BITS; ++shift_bit) {
		uint8_t shift_reg_idx = (shift_bit >> 3);
		uint8_t shift_reg_val = 0x1 << (shift_bit & 0x7);

		if ((state->ksn[DUKPT_TDES_KSN_LEN - 1 - shift_reg_idx] & shift_reg_val)) {
			// Least significant transaction counter bit found
			break;
		}
	}

	// Transaction counter exhausted
	if (shift_bit == DUKPT_TDES_TC_BITS) {
		r = 3; // Distinguish from dukpt_tdes_ksn_advance() return values
		goto error;
	}

	// Ensure that current key is valid
	current_key = shift_bit;
	if (!state->valid[current_key]) {
		r = 4; // Distinguish from dukpt_tdes_ksn_advance() return values
		goto error;
	}

	// For each shift register bit lower than the current shift register bit:
	// Set the corresponding bit in the KSN register and derive the
	// corresponding future key from the KSN register and the current key
	for (; shift_bit > 0; --shift_bit) {
		// Set appropriate bit in shift register
		uint8_t shift_reg_idx = (shift_bit-1) >> 3; // Upper bits indicate byte index
		uint8_t shift_reg_val = 0x1 << ((shift_bit-1) & 0x7); // Lower bits indicate shift for byte value
		memset(shift_reg, 0, sizeof(shift_reg));
		shift_reg[shift_reg_idx] = shift_reg_val;

		// Set shift bit in KSN register
		for (uint8_t i = 0; i < sizeof(shift_reg); ++i) {
			ksn_reg[sizeof(ksn_reg) - 1 - i] = state->ksn[sizeof(ksn_reg) - 1 - i] | shift_reg[i];
		}

		// Derive future key
		// It is necessary to copy the current key to the key register because the
		// key register is modified during key derivation
		memcpy(key_reg, state->key[current_key], sizeof(key_reg));
		r = dukpt_tdes_derive_key(ksn_reg, key_reg, state->key[shift_bit-1]);
		if (r) {
			goto error;
		}

		// This future key is now valid
		state->valid[shift_bit-1] = 1;
	}

	// Copy current key to transaction key output and destroy current key
	memcpy(txn_key, state->key[current_key], DUKPT_TDES_KEY_LEN);
	memset(state->key[current_key], 0, DUKPT_TDES_KEY_LEN);
	state->valid[current_key] = 0;

	// Advance to next transaction
	r = dukpt_tdes_ksn_advance(state->ksn);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	// Ensure that output key is unusable on error
	crypto_rand(txn_key, DUKPT_TDES_KEY_LEN);
exit:
	// Cleanup
	crypto_cleanse(key_reg, sizeof(key_reg));

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
		// still yields an invalid transaction counter. And if more than one of
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
	r = crypto_tdes2_encrypt_ecb(pin_key, pinblock, ciphertext);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(ciphertext, DUKPT_TDES_PINBLOCK_LEN);
exit:
	crypto_cleanse(pin_key, sizeof(pin_key));

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
	r = crypto_tdes2_decrypt_ecb(pin_key, ciphertext, pinblock);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(pinblock, DUKPT_TDES_PINBLOCK_LEN);
exit:
	crypto_cleanse(pin_key, sizeof(pin_key));

	return r;
}


int dukpt_tdes_encrypt_pin(
	const void* txn_key,
	unsigned int format,
	const uint8_t* pin,
	size_t pin_len,
	const uint8_t* pan,
	size_t pan_len,
	void* ciphertext
)
{
	int r;
	uint8_t pinblock[DUKPT_TDES_PINBLOCK_LEN];

	// Encode PIN block
	switch (format) {
		case 0:
			r = pinblock_encode_iso9564_format0(
				pin,
				pin_len,
				pan,
				pan_len,
				pinblock
			);
			break;

		case 3:
			r = pinblock_encode_iso9564_format3(
				pin,
				pin_len,
				pan,
				pan_len,
				pinblock
			);
			break;

		default:
			// Unsupported PIN block format
			return 1;
	}
	if (r) {
		// PIN block encoding failed
		r = -1;
		goto error;
	}

	// Encrypt PIN block
	r = dukpt_tdes_encrypt_pinblock(
		txn_key,
		pinblock,
		ciphertext
	);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
exit:
	crypto_cleanse(pinblock, sizeof(pinblock));

	return r;
}

int dukpt_tdes_decrypt_pin(
	const void* txn_key,
	const void* ciphertext,
	const uint8_t* pan,
	size_t pan_len,
	void* pin,
	size_t* pin_len
)
{
	int r;
	uint8_t pinblock[DUKPT_TDES_PINBLOCK_LEN];
	unsigned int format;

	// Decrypt PIN block
	r = dukpt_tdes_decrypt_pinblock(
		txn_key,
		ciphertext,
		pinblock
	);
	if (r) {
		goto error;
	}

	// Decode PIN block
	r = pinblock_decode(
		pinblock,
		sizeof(pinblock),
		pan,
		pan_len,
		&format,
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
	crypto_cleanse(pinblock, sizeof(pinblock));

	return r;
}

int dukpt_tdes_generate_request_mac(
	const void* txn_key,
	const void* buf,
	size_t buf_len,
	void* mac
)
{
	int r;
	uint8_t mac_key[DUKPT_TDES_KEY_LEN];

	// Derive request MAC key variant
	// See ANSI X9.24-1:2009 A.4.1, table A-1
	// See ANSI X9.24-3:2017 C.5.2, table 5
	memcpy(mac_key, txn_key, DUKPT_TDES_KEY_LEN);
	mac_key[6] ^= 0xFF;
	mac_key[14] ^= 0xFF;

	// Generate ANSI X9.19 Retail MAC
	r = crypto_tdes2_retail_mac(mac_key, buf, buf_len, mac);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(mac, DUKPT_TDES_MAC_LEN);
exit:
	crypto_cleanse(mac_key, sizeof(mac_key));

	return r;
}

int dukpt_tdes_verify_request_mac(
	const void* txn_key,
	const void* buf,
	size_t buf_len,
	const void* mac
)
{
	int r;
	uint8_t mac_verify[DUKPT_TDES_MAC_LEN];

	r = dukpt_tdes_generate_request_mac(txn_key, buf, buf_len, mac_verify);
	if (r) {
		goto error;
	}

	if (crypto_memcmp_s(mac_verify, mac, sizeof(mac_verify)) != 0) {
		r = 1;
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
exit:
	crypto_cleanse(mac_verify, sizeof(mac_verify));

	return r;
}

int dukpt_tdes_generate_response_mac(
	const void* txn_key,
	const void* buf,
	size_t buf_len,
	void* mac
)
{
	int r;
	uint8_t mac_key[DUKPT_TDES_KEY_LEN];

	// Derive response MAC key variant
	// See ANSI X9.24-1:2009 A.4.1, table A-1
	// See ANSI X9.24-3:2017 C.5.2, table 5
	memcpy(mac_key, txn_key, DUKPT_TDES_KEY_LEN);
	mac_key[4] ^= 0xFF;
	mac_key[12] ^= 0xFF;

	// Generate ANSI X9.19 Retail MAC
	r = crypto_tdes2_retail_mac(mac_key, buf, buf_len, mac);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(mac, DUKPT_TDES_MAC_LEN);
exit:
	crypto_cleanse(mac_key, sizeof(mac_key));

	return r;
}

int dukpt_tdes_verify_response_mac(
	const void* txn_key,
	const void* buf,
	size_t buf_len,
	const void* mac
)
{
	int r;
	uint8_t mac_verify[DUKPT_TDES_MAC_LEN];

	r = dukpt_tdes_generate_response_mac(txn_key, buf, buf_len, mac_verify);
	if (r) {
		goto error;
	}

	if (crypto_memcmp_s(mac_verify, mac, sizeof(mac_verify)) != 0) {
		r = 1;
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
exit:
	crypto_cleanse(mac_verify, sizeof(mac_verify));

	return r;
}

int dukpt_tdes_generate_request_cmac(
	const void* txn_key,
	const void* buf,
	size_t buf_len,
	void* cmac
)
{
	int r;
	uint8_t mac_key[DUKPT_TDES_KEY_LEN];

	// Derive request MAC key variant
	// See ANSI X9.24-1:2009 A.4.1, table A-1
	// See ANSI X9.24-3:2017 C.5.2, table 5
	memcpy(mac_key, txn_key, DUKPT_TDES_KEY_LEN);
	mac_key[6] ^= 0xFF;
	mac_key[14] ^= 0xFF;

	// Generate TDES-CMAC
	r = crypto_tdes_cmac(mac_key, sizeof(mac_key), buf, buf_len, cmac);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(cmac, DUKPT_TDES_CMAC_LEN);
exit:
	crypto_cleanse(mac_key, sizeof(mac_key));

	return r;
}

int dukpt_tdes_verify_request_cmac(
	const void* txn_key,
	const void* buf,
	size_t buf_len,
	const void* cmac
)
{
	int r;
	uint8_t cmac_verify[DUKPT_TDES_CMAC_LEN];

	r = dukpt_tdes_generate_request_cmac(txn_key, buf, buf_len, cmac_verify);
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

int dukpt_tdes_generate_response_cmac(
	const void* txn_key,
	const void* buf,
	size_t buf_len,
	void* cmac
)
{
	int r;
	uint8_t mac_key[DUKPT_TDES_KEY_LEN];

	// Derive response MAC key variant
	// See ANSI X9.24-1:2009 A.4.1, table A-1
	// See ANSI X9.24-3:2017 C.5.2, table 5
	memcpy(mac_key, txn_key, DUKPT_TDES_KEY_LEN);
	mac_key[4] ^= 0xFF;
	mac_key[12] ^= 0xFF;

	// Generate TDES-CMAC
	r = crypto_tdes_cmac(mac_key, sizeof(mac_key), buf, buf_len, cmac);
	if (r) {
		goto error;
	}

	// Success
	r = 0;
	goto exit;

error:
	crypto_cleanse(cmac, DUKPT_TDES_CMAC_LEN);
exit:
	crypto_cleanse(mac_key, sizeof(mac_key));

	return r;
}

int dukpt_tdes_verify_response_cmac(
	const void* txn_key,
	const void* buf,
	size_t buf_len,
	const void* cmac
)
{
	int r;
	uint8_t cmac_verify[DUKPT_TDES_CMAC_LEN];

	r = dukpt_tdes_generate_response_cmac(txn_key, buf, buf_len, cmac_verify);
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

int dukpt_tdes_encrypt_request(
	const void* txn_key,
	const void* iv,
	const void* buf,
	size_t buf_len,
	void* ciphertext
)
{
	int r;
	uint8_t data_key[DUKPT_TDES_KEY_LEN];
	uint8_t owf_key[DUKPT_TDES_KEY_LEN];

	// Derive data encryption (request) key variant
	// See ANSI X9.24-1:2009 A.4.1, table A-1
	// See ANSI X9.24-3:2017 C.5.2, table 5
	memcpy(data_key, txn_key, DUKPT_TDES_KEY_LEN);
	data_key[5] ^= 0xFF;
	data_key[13] ^= 0xFF;

	// Apply one way function
	// See ANSI X9.24-1:2009 A.4.1, figure A-2
	// See ANSI X9.24-3:2017 C.5.2, figure 6
	memcpy(owf_key, data_key, DUKPT_TDES_KEY_LEN);
	r = crypto_tdes2_encrypt_ecb(owf_key, data_key, data_key);
	if (r) {
		goto error;
	}
	r = crypto_tdes2_encrypt_ecb(owf_key, data_key + DES_BLOCK_SIZE, data_key + DES_BLOCK_SIZE);
	if (r) {
		goto error;
	}

	// Encrypt transaction data
	r = crypto_tdes2_encrypt(data_key, iv, buf, buf_len, ciphertext);
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
	crypto_cleanse(owf_key, sizeof(owf_key));

	return r;
}

int dukpt_tdes_decrypt_request(
	const void* txn_key,
	const void* iv,
	const void* buf,
	size_t buf_len,
	void* plaintext
)
{
	int r;
	uint8_t data_key[DUKPT_TDES_KEY_LEN];
	uint8_t owf_key[DUKPT_TDES_KEY_LEN];

	// Derive data encryption (request) key variant
	// See ANSI X9.24-1:2009 A.4.1, table A-1
	// See ANSI X9.24-3:2017 C.5.2, table 5
	memcpy(data_key, txn_key, DUKPT_TDES_KEY_LEN);
	data_key[5] ^= 0xFF;
	data_key[13] ^= 0xFF;

	// Apply one way function
	// See ANSI X9.24-1:2009 A.4.1, figure A-2
	// See ANSI X9.24-3:2017 C.5.2, figure 6
	memcpy(owf_key, data_key, DUKPT_TDES_KEY_LEN);
	r = crypto_tdes2_encrypt_ecb(owf_key, data_key, data_key);
	if (r) {
		goto error;
	}
	r = crypto_tdes2_encrypt_ecb(owf_key, data_key + DES_BLOCK_SIZE, data_key + DES_BLOCK_SIZE);
	if (r) {
		goto error;
	}

	// Decrypt transaction data
	r = crypto_tdes2_decrypt(data_key, iv, buf, buf_len, plaintext);
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
	crypto_cleanse(owf_key, sizeof(owf_key));

	return r;
}

int dukpt_tdes_encrypt_response(
	const void* txn_key,
	const void* iv,
	const void* buf,
	size_t buf_len,
	void* ciphertext
)
{
	int r;
	uint8_t data_key[DUKPT_TDES_KEY_LEN];
	uint8_t owf_key[DUKPT_TDES_KEY_LEN];

	// Derive data encryption (response) key variant
	// See ANSI X9.24-1:2009 A.4.1, table A-1
	// See ANSI X9.24-3:2017 C.5.2, table 5
	memcpy(data_key, txn_key, DUKPT_TDES_KEY_LEN);
	data_key[3] ^= 0xFF;
	data_key[11] ^= 0xFF;

	// Apply one way function
	// See ANSI X9.24-1:2009 A.4.1, figure A-2
	// See ANSI X9.24-3:2017 C.5.2, figure 6
	memcpy(owf_key, data_key, DUKPT_TDES_KEY_LEN);
	r = crypto_tdes2_encrypt_ecb(owf_key, data_key, data_key);
	if (r) {
		goto error;
	}
	r = crypto_tdes2_encrypt_ecb(owf_key, data_key + DES_BLOCK_SIZE, data_key + DES_BLOCK_SIZE);
	if (r) {
		goto error;
	}

	// Encrypt transaction data
	r = crypto_tdes2_encrypt(data_key, iv, buf, buf_len, ciphertext);
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
	crypto_cleanse(owf_key, sizeof(owf_key));

	return r;
}

int dukpt_tdes_decrypt_response(
	const void* txn_key,
	const void* iv,
	const void* buf,
	size_t buf_len,
	void* plaintext
)
{
	int r;
	uint8_t data_key[DUKPT_TDES_KEY_LEN];
	uint8_t owf_key[DUKPT_TDES_KEY_LEN];

	// Derive data encryption (response) key variant
	// See ANSI X9.24-1:2009 A.4.1, table A-1
	// See ANSI X9.24-3:2017 C.5.2, table 5
	memcpy(data_key, txn_key, DUKPT_TDES_KEY_LEN);
	data_key[3] ^= 0xFF;
	data_key[11] ^= 0xFF;

	// Apply one way function
	// See ANSI X9.24-1:2009 A.4.1, figure A-2
	// See ANSI X9.24-3:2017 C.5.2, figure 6
	memcpy(owf_key, data_key, DUKPT_TDES_KEY_LEN);
	r = crypto_tdes2_encrypt_ecb(owf_key, data_key, data_key);
	if (r) {
		goto error;
	}
	r = crypto_tdes2_encrypt_ecb(owf_key, data_key + DES_BLOCK_SIZE, data_key + DES_BLOCK_SIZE);
	if (r) {
		goto error;
	}

	// Decrypt transaction data
	r = crypto_tdes2_decrypt(data_key, iv, buf, buf_len, plaintext);
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
	crypto_cleanse(owf_key, sizeof(owf_key));

	return r;
}
