/**
 * @file dukpt_tdes_crypto.h
 * @brief DES and TDES crypto helper functions
 *
 * Copyright (c) 2022 Leon Lynch
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

#ifndef DUKPT_TDES_CRYPTO_H
#define DUKPT_TDES_CRYPTO_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

#define DES_BLOCK_SIZE (8) ///< DES block size in bytes
#define DES_RETAIL_MAC_LEN (4) ///< ANSI X9.19 Retail MAC length in bytes

/**
 * Encrypt using single length DES
 *
 * @param key Key
 * @param iv Initialization vector
 * @param plaintext Plaintext to encrypt
 * @param plen Length of plaintext in bytes. Must be a multiple of @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_des_encrypt(const void* key, const void* iv, const void* plaintext, size_t plen, void* ciphertext);

/**
 * Encrypt using single length DES-ECB
 *
 * @param key Key
 * @param plaintext Plaintext to encrypt. Must be of length @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int dukpt_des_encrypt_ecb(const void* key, const void* plaintext, void* ciphertext)
{
	return dukpt_des_encrypt(key, NULL, plaintext, DES_BLOCK_SIZE, ciphertext);
}

/**
 * Encrypt using double length TDES
 *
 * @param key Key
 * @param iv Initialization vector
 * @param plaintext Plaintext to encrypt
 * @param plen Length of plaintext in bytes. Must be a multiple of @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_tdes2_encrypt(const void* key, const void* iv, const void* plaintext, size_t plen, void* ciphertext);

/**
 * Encrypt using double length TDES-ECB
 *
 * @param key Key
 * @param plaintext Plaintext to encrypt. Must be of length @ref DES_BLOCK_SIZE.
 * @param ciphertext Encrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int dukpt_tdes2_encrypt_ecb(const void* key, const void* plaintext, void* ciphertext)
{
	return dukpt_tdes2_encrypt(key, NULL, plaintext, DES_BLOCK_SIZE, ciphertext);
}

/**
 * Decrypt using double length TDES
 *
 * @param key Key
 * @param iv Initialization vector
 * @param ciphertext Ciphertext to decrypt
 * @param clen Length of ciphertext in bytes. Must be a multiple of @ref DES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_tdes2_decrypt(const void* key, const void* iv, const void* ciphertext, size_t clen, void* plaintext);

/**
 * Decrypt using double length TDES-ECB
 *
 * @param key Key
 * @param ciphertext Ciphertext to decrypt. Must be of length @ref DES_BLOCK_SIZE.
 * @param plaintext Decrypted output
 * @return Zero for success. Less than zero for internal error.
 */
static inline int dukpt_tdes2_decrypt_ecb(const void* key, const void* ciphertext, void* plaintext)
{
	return dukpt_tdes2_decrypt(key, NULL, ciphertext, DES_BLOCK_SIZE, plaintext);
}

/**
 * Generate ANSI X9.19 Retail MAC using double length TDES
 *
 * @param key Key
 * @param buf Input data
 * @param buf_len Length of input data in bytes
 * @param mac MAC output of length @ref DES_RETAIL_MAC_LEN
 * @return Zero for success. Less than zero for internal error.
 */
int dukpt_tdes2_retail_mac(const void* key, const void* buf, size_t buf_len, void* mac);

__END_DECLS

#endif
