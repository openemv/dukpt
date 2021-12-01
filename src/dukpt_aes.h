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
#include <stdint.h>

__BEGIN_DECLS

#define DUKPT_AES_BDK_ID_LEN (4) ///< Base Derivation Key ID length for AES DUKPT
#define DUKPT_AES_DERIVATION_ID_LEN (4) ///< Derivation ID length for AES DUKPT
#define DUKPT_AES_IK_ID_LEN (DUKPT_AES_BDK_ID_LEN + DUKPT_AES_DERIVATION_ID_LEN) ///< Initial Key ID length for AES DUKPT
#define DUKPT_AES_TC_LEN (4) ///< Transaction counter length for AES DUKPT
#define DUKPT_AES_KSN_LEN (DUKPT_AES_IK_ID_LEN + DUKPT_AES_TC_LEN) ///< Key Serial Number length for AES DUKPT

/**
 * Key types for AES DUKPT
 * @remark See ANSI X9.24-3:2017 6.2.1
 */
enum dukpt_aes_key_type_t {
	DUKPT_AES_KEY_TYPE_2TDEA,  ///< Key type: Double-length TDEA
	DUKPT_AES_KEY_TYPE_3TDEA,  ///< Key type: Triple-length TDEA
	DUKPT_AES_KEY_TYPE_AES128, ///< Key type: AES-128
	DUKPT_AES_KEY_TYPE_AES192, ///< Key type: AES-192
	DUKPT_AES_KEY_TYPE_AES256, ///< Key type: AES-256
};

/**
 * Key length in bits by key type for AES DUKPT
 * @remark See ANSI X9.24-3:2017 6.2.2
 */
enum dukpt_aes_key_bits_t {
	DUKPT_AES_KEY_BITS_2TDEA = 0x0080,  ///< TDES2 128-bit
	DUKPT_AES_KEY_BITS_3TDEA = 0x00C0,  ///< TDES3 192-bit
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
 * @param key_type Key type of Base Derivation Key. Only AES key types are allowed.
 *        This parameter also determines the underlying derivation algorithm.
 * @param bdk Base Derivative Key of length @ref DUKPT_AES_KEY_LEN(key_type)
 * @param ikid Initial Key ID of length @ref DUKPT_AES_IK_ID_LEN
 * @param ik Initial DUKPT key output of length @ref DUKPT_AES_KEY_LEN(key_type)
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int dukpt_aes_derive_ik(
	enum dukpt_aes_key_type_t key_type,
	const void* bdk,
	const uint8_t* ikid,
	void* ik
);

/**
 * Derive DUKPT transaction key from Initial Key (IK) and Key Serial Number (KSN)
 * @note This function should only be used by the receiving
 *       Secure Cryptographic Device (SCD)
 *
 * @param key_type Key type of Initial Key. Only AES key types are allowed.
 *        This parameter also determines the underlying derivation algorithm.
 * @param ik Initial Key of length @ref DUKPT_AES_KEY_LEN(key_type)
 * @param ksn Key Serial Number of length @ref DUKPT_AES_KSN_LEN
 * @param txn_key DUKPT transaction key output of length @ref DUKPT_AES_KEY_LEN(key_type)
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for invalid/unsupported parameters.
 */
int dukpt_aes_derive_txn_key(
	enum dukpt_aes_key_type_t key_type,
	const void* ik,
	const uint8_t* ksn,
	void* txn_key
);

__END_DECLS

#endif
