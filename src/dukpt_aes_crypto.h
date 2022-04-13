/**
 * @file dukpt_aes_crypto.h
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

#ifndef DUKPT_AES_CRYPTO_H
#define DUKPT_AES_CRYPTO_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

#define AES_BLOCK_SIZE (16) ///< AES block size in bytes
#define AES128_KEY_SIZE (16) ///< AES-128 key size in bytes
#define AES192_KEY_SIZE (24) ///< AES-192 key size in bytes
#define AES256_KEY_SIZE (32) ///< AES-256 key size in bytes
#define HMAC_SHA256_LEN (32) ///< HMAC-SHA256 digest length

/**
 * Generate HMAC-SHA256
 * @remark See ISO 9797-2:2011 MAC algorithm 2
 * @remark NIST FIPS 198-1
 * @remark See IETF RFC 2104
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param buf Input data
 * @param buf_len Length of input data in bytes
 * @param hmac HMAC output of length @ref HMAC_SHA256_LEN
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_hmac_sha256(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* hmac
);

#endif
