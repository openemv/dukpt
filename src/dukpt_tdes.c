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
static int dukpt_tdes2_encrypt_ecb(const void* key, const void* plaintext, void* ciphertext);
static void dukpt_memset_s(void* ptr, size_t len);

#ifdef MBEDTLS_FOUND

#include <mbedtls/des.h>

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
