/**
 * @file dukpt_aes_crypto.c
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

#include "dukpt_aes_crypto.h"
#include "dukpt_config.h"

#ifdef MBEDTLS_FOUND
#include <mbedtls/md.h>

int dukpt_hmac_sha256(
	const void* key,
	size_t key_len,
	const void* buf,
	size_t buf_len,
	void* hmac
)
{
	int r;
	mbedtls_md_context_t ctx;

	mbedtls_md_init(&ctx);
	r = mbedtls_md_setup(&ctx, mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), 1);
	if (r) {
		r = -1;
		goto exit;
	}

	r = mbedtls_md_hmac_starts(&ctx, key, key_len);
	if (r) {
		r = -2;
		goto exit;
	}

	r = mbedtls_md_hmac_update(&ctx, buf, buf_len);
	if (r) {
		r = -3;
		goto exit;
	}

	r = mbedtls_md_hmac_finish(&ctx, hmac);
	if (r) {
		r = -4;
		goto exit;
	}

	r = 0;
	goto exit;

exit:
	// Cleanup
	mbedtls_md_free(&ctx);

	return r;
}

#endif
