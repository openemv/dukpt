/**
 * @file dukpt_mem.c
 * @brief Memory-related crypto helper functions
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

#include "dukpt_mem.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

__attribute__((noinline))
void dukpt_cleanse(void* buf, size_t len)
{
	memset(buf, 0, len);

	// From GCC documentation:
	// If the function does not have side effects, there are optimizations
	// other than inlining that cause function calls to be optimized away,
	// although the function call is live. To keep such calls from being
	// optimized away, put...
	__asm__ ("");
}

__attribute__((noinline))
int dukpt_memcmp_s(const void* a, const void* b, size_t len)
{
	int r = 0;
	const volatile uint8_t* buf_a = a;
	const volatile uint8_t* buf_b = b;

	for (size_t i = 0; i < len; ++i) {
		r |= buf_a[i] ^ buf_b[i];
	}

	return !!r;
}
