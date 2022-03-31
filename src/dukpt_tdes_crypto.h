/**
 * @file dukpt_tdes_crypto.h
 * @brief DES and TDES crypto helper functions
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

#ifndef DUKPT_TDES_CRYPTO_H
#define DUKPT_TDES_CRYPTO_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

#define DES_BLOCK_SIZE (8) ///< DES block size in bytes
#define DES_RETAIL_MAC_LEN (4) ///< ANSI X9.19 Retail MAC length in bytes

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
