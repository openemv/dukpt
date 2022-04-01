/**
 * @file dukpt_mem.h
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

#ifndef DUKPT_MEM_H
#define DUKPT_MEM_H

#include <sys/cdefs.h>
#include <stddef.h>

__BEGIN_DECLS

/**
 * Left shift buffer
 *
 * @param buf Pointer to buffer
 * @param len Length of buffer in bytes
 * @return Carry bit after left shift
 */
int dukpt_lshift(void* buf, size_t len);

/**
 * XOR buffers. This function will perform the equivalent of <tt>x ^= y</tt>
 *
 * @param x Pointer to first buffer
 * @param y Pointer to second buffer
 * @param len Number of bytes to XOR
 */
void dukpt_xor(void* x, const void* y, size_t len);

__END_DECLS

#endif
