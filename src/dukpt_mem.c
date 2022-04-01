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

int dukpt_lshift(void* buf, size_t len)
{
	uint8_t* ptr = buf;
	uint8_t lsb;

	ptr += (len - 1);
	lsb = 0x00;
	while (len--) {
		uint8_t msb;

		msb = *ptr & 0x80;
		*ptr <<= 1;
		*ptr |= lsb;
		--ptr;
		lsb = msb >> 7;
	}

	// Return carry bit
	return lsb;
}

void dukpt_xor(void* x, const void* y, size_t len)
{
	uint8_t* buf_x = x;
	const  uint8_t* buf_y = y;

	for (size_t i = 0; i < len; ++i) {
		*buf_x ^= *buf_y;
		++buf_x;
		++buf_y;
	}
}
