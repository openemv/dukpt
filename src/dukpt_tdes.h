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
#include <stdint.h>

__BEGIN_DECLS

#define DUKPT_TDES_KEY_LEN (16) ///< Key length for TDES DUKPT
#define DUKPT_TDES_KSN_LEN (10) ///< Key Serial Number length for TDES DUKPT

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

__END_DECLS

#endif
