/**
 * @file dukpt_tdes.h
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

#ifndef DUKPT_TDES_H
#define DUKPT_TDES_H

#include <sys/cdefs.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

__BEGIN_DECLS

#define DUKPT_TDES_KEY_LEN (16) ///< Key length for TDES DUKPT
#define DUKPT_TDES_KSN_LEN (10) ///< Key Serial Number length for TDES DUKPT
#define DUKPT_TDES_TC_BITS (21) ///< Number of Transaction Counter (TC) bits in Key Serial Number
#define DUKPT_TDES_TC_MAX  (0x1FF800) ///< Maximum transaction counter value for TDES DUKPT
#define DUKPT_TDES_PINBLOCK_LEN (8) ///< PIN block length for TDES DUKPT. See ISO 9564-1:2017 9.3 formats 0, 1, 3.

/**
 * Derive Initial Key (IK) from Base Derivative Key (BDK) and Key Serial Number (KSN)
 * @note This function should only be used by the receiving or key generating
 *       Tamper-Resistant Security Module (TRSM)
 *
 * @param bdk Base Derivative Key of length @ref DUKPT_TDES_KEY_LEN
 * @param iksn Initial Key Serial Number of length @ref DUKPT_TDES_KSN_LEN
 * @param ik Initial Key output of length @ref DUKPT_TDES_KEY_LEN
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_tdes_derive_ik(const void* bdk, const uint8_t* iksn, void* ik);

/**
 * Derive DUKPT transaction key from Initial Key (IK) and Key Serial Number (KSN)
 * @note This function should only be used by the transaction receiving
 *       Tamper-Resistant Security Module (TRSM)
 *
 * @param ik Initial Key of length @ref DUKPT_TDES_KEY_LEN
 * @param ksn Key Serial Number of length @ref DUKPT_TDES_KSN_LEN
 * @param txn_key DUKPT transaction key output of length @ref DUKPT_TDES_KEY_LEN
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_tdes_derive_txn_key(const void* ik, const uint8_t* ksn, void* txn_key);

/**
 * Advance Key Serial Number (KSN) to next transaction
 * @param ksn Key Serial Number of length @ref DUKPT_TDES_KSN_LEN
 * @return Zero for success. Less than zero for internal error.
 *         Greater than zero for exhausted transaction counter.
 */
int dukpt_tdes_ksn_advance(uint8_t* ksn);

/**
 * Determine whether KSN, specifically the transaction counter bits, are valid
 * @param ksn Key Serial Number of length @ref DUKPT_TDES_KSN_LEN
 * @return Boolean indicating whether KSN transaction counter is valid
 */
bool dukpt_tdes_ksn_is_valid(const uint8_t* ksn);

/**
 * Determine whether Key Serial Number (KSN) transaction counter is exhausted
 * @param ksn Key Serial Number of length @ref DUKPT_TDES_KSN_LEN
 * @return Boolean indicating whether KSN transaction counter is exhausted
 */
bool dukpt_tdes_ksn_is_exhausted(const uint8_t* ksn);

/**
 * Encrypt PIN block using DUKPT transaction key
 * @note This function should only be used by the transaction originating
 *       Tamper-Resistant Security Module (TRSM)
 *
 * @param txn_key DUKPT transaction key of length @ref DUKPT_TDES_KEY_LEN
 * @param pinblock Encoded PIN block of length @ref DUKPT_TDES_PINBLOCK_LEN
 * @param ciphertext Encrypted PIN block output of length @ref DUKPT_TDES_PINBLOCK_LEN
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_tdes_encrypt_pinblock(
	const void* txn_key,
	const void* pinblock,
	void* ciphertext
);

/**
 * Decrypt PIN block using DUKPT transaction key
 * @note This function should only be used by the transaction receiving
 *       Tamper-Resistant Security Module (TRSM)
 *
 * @param txn_key DUKPT transaction key of length @ref DUKPT_TDES_KEY_LEN
 * @param ciphertext Encrypted PIN block of length @ref DUKPT_TDES_PINBLOCK_LEN
 * @param pinblock Encoded PIN block output of length @ref DUKPT_TDES_PINBLOCK_LEN
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_tdes_decrypt_pinblock(
	const void* txn_key,
	const void* ciphertext,
	void* pinblock
);

__END_DECLS

#endif
