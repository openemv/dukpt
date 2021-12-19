/**
 * @file dukpt_aes.h
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

#ifndef DUKPT_AES_H
#define DUKPT_AES_H

#include <sys/cdefs.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

__BEGIN_DECLS

#define DUKPT_AES_BDK_ID_LEN (4) ///< Base Derivation Key ID length for AES DUKPT
#define DUKPT_AES_DERIVATION_ID_LEN (4) ///< Derivation ID length for AES DUKPT
#define DUKPT_AES_IK_ID_LEN (DUKPT_AES_BDK_ID_LEN + DUKPT_AES_DERIVATION_ID_LEN) ///< Initial Key ID length for AES DUKPT
#define DUKPT_AES_TC_LEN (4) ///< Transaction counter length for AES DUKPT
#define DUKPT_AES_TC_MAX  (0xFFFF0000) ///< Maximum transaction counter value for AES DUKPT
#define DUKPT_AES_KSN_LEN (DUKPT_AES_IK_ID_LEN + DUKPT_AES_TC_LEN) ///< Key Serial Number length for AES DUKPT

/**
 * Key types for AES DUKPT
 * @remark See ANSI X9.24-3:2017 6.2.1
 */
enum dukpt_aes_key_type_t {
	DUKPT_AES_KEY_TYPE_TDES2,  ///< Key type: Double-length TDES
	DUKPT_AES_KEY_TYPE_TDES3,  ///< Key type: Triple-length TDES
	DUKPT_AES_KEY_TYPE_AES128, ///< Key type: AES-128
	DUKPT_AES_KEY_TYPE_AES192, ///< Key type: AES-192
	DUKPT_AES_KEY_TYPE_AES256, ///< Key type: AES-256
};

/**
 * Key length in bits by key type for AES DUKPT
 * @remark See ANSI X9.24-3:2017 6.2.2
 */
enum dukpt_aes_key_bits_t {
	DUKPT_AES_KEY_BITS_TDES2 = 0x0080,  ///< TDES2 128-bit
	DUKPT_AES_KEY_BITS_TDES3 = 0x00C0,  ///< TDES3 192-bit
	DUKPT_AES_KEY_BITS_AES128 = 0x0080, ///< AES 128-bit
	DUKPT_AES_KEY_BITS_AES192 = 0x00C0, ///< AES 192-bit
	DUKPT_AES_KEY_BITS_AES256 = 0x0100, ///< AES 256-bit
};

/**
 * Key length in bytes for AES DUKPT (depends on @ref dukpt_aes_key_bits_t)
 * @remark See ANSI X9.24-3:2017 6.2.2
 *
 * @param key_type Key type
 */
#define DUKPT_AES_KEY_LEN(key_type) ((DUKPT_AES_KEY_BITS_##key_type) / 8)

/**
 * Derive Initial Key (IK) from Base Derivative Key (BDK) and Initial Key ID.
 * @note This function should only be used by the receiving or key generating
 *       Secure Cryptographic Device (SCD)
 *
 * @param bdk Base Derivative Key
 * @param bdk_len Length of Base Derivation Key in bytes
 * @param ikid Initial Key ID of length @ref DUKPT_AES_IK_ID_LEN
 * @param ik Initial DUKPT key output of length @c bdk_len
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int dukpt_aes_derive_ik(
	const void* bdk,
	size_t bdk_len,
	const uint8_t* ikid,
	void* ik
);

/**
 * Derive DUKPT transaction key from Initial Key (IK) and Key Serial Number (KSN)
 * @note This function should only be used by the receiving
 *       Secure Cryptographic Device (SCD)
 *
 * @param ik Initial Key
 * @param ik_len Length of Initial Key in bytes
 * @param ksn Key Serial Number of length @ref DUKPT_AES_KSN_LEN
 * @param txn_key DUKPT transaction key output of length @c ik_len
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int dukpt_aes_derive_txn_key(
	const void* ik,
	size_t ik_len,
	const uint8_t* ksn,
	void* txn_key
);

/**
 * Advance Key Serial Number (KSN) to next transaction
 * @param ksn Key Serial Number of length @ref DUKPT_AES_KSN_LEN
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for exhausted transaction counter.
 */
int dukpt_aes_ksn_advance(uint8_t* ksn);

/**
 * Determine whether KSN, specifically the transaction counter bits, are valid
 * @param ksn Key Serial Number of length @ref DUKPT_AES_KSN_LEN
 * @return Boolean indicating whether KSN transaction counter is valid
 */
bool dukpt_aes_ksn_is_valid(const uint8_t* ksn);

/**
 * Determine whether Key Serial Number (KSN) transaction counter is exhausted
 * @param ksn Key Serial Number of length @ref DUKPT_AES_KSN_LEN
 * @return Boolean indicating whether KSN transaction counter is exhausted
 */
bool dukpt_aes_ksn_is_exhausted(const uint8_t* ksn);

/**
 * Derive DUKPT update key from Initial Key (IK) and Key Initial Key ID
 * @note This function should only be used by the receiving or key generating
 *       Secure Cryptographic Device (SCD)
 *
 * @param ik Initial Key
 * @param ik_len Length of Initial Key in bytes
 * @param ikid Initial Key ID of length @ref DUKPT_AES_IK_ID_LEN
 * @param key_type Key type of update key
 * @param update_key DUKPT update key output of length @ref DUKPT_AES_KEY_LEN(key_type)
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int dukpt_aes_derive_update_key(
	const void* ik,
	size_t ik_len,
	const uint8_t* ikid,
	enum dukpt_aes_key_type_t key_type,
	void* update_key
);

__END_DECLS

#endif
