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
#define AES_CMAC_LEN (16) ///< AES-CMAC length in bytes
#define HMAC_SHA256_LEN (32) ///< HMAC-SHA256 digest length

/**
 * Encrypt using AES
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector
 * @param plaintext Plaintext to encrypt
 * @param plen Length of plaintext in bytes. Must be a multiple of @ref AES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_aes_encrypt(const void* key, size_t key_len, const void* iv, const void* plaintext, size_t plen, void* ciphertext);

/**
 * Encrypt using AES-ECB
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param plaintext Plaintext to encrypt. Must be of length @ref AES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int dukpt_aes_encrypt_ecb(const void* key, size_t key_len, const void* plaintext, void* ciphertext)
{
	return dukpt_aes_encrypt(key, key_len, NULL, plaintext, AES_BLOCK_SIZE, ciphertext);
}

/**
 * Decrypt using AES
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param iv Initialization vector
 * @param ciphertext Ciphertext to decrypt
 * @param clen Length of ciphertext in bytes. Must be a multiple of @ref AES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_aes_decrypt(const void* key, size_t key_len, const void* iv, const void* ciphertext, size_t clen, void* plaintext);

/**
 * Decrypt using AES-ECB
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param ciphertext Ciphertext to decrypt. Must be of length @ref DES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int dukpt_aes_decrypt_ecb(const void* key, size_t key_len, const void* ciphertext, void* plaintext)
{
	return dukpt_aes_decrypt(key, key_len, NULL, ciphertext, AES_BLOCK_SIZE, plaintext);
}

/**
 * Generate AES-CMAC
 * @remark See ISO 9797-1:2011 MAC algorithm 5
 * @remark See NIST SP 800-38B
 * @remark See IETF RFC 4493
 *
 * @param key Key
 * @param key_len Length of key in bytes
 * @param buf Input data
 * @param buf_len Length of input data in bytes
 * @param cmac AES-CMAC output of length @ref AES_CMAC_LEN
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_aes_cmac(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* cmac
);

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
