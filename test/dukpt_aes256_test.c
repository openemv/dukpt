/**
 * @file dukpt_aes256_test.c
 *
 * Copyright (c) 2021, 2022 Leon Lynch
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "dukpt_aes.h"

#include "crypto_aes.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-256 BDK
static const uint8_t bdk[] = {
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1,
	0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1, 0xF1,
};
static const uint8_t ikid[] = { 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56 };
static const uint8_t ik_verify[] = {
	0xCE, 0x9C, 0xE0, 0xC1, 0x01, 0xD1, 0x13, 0x8F, 0x97, 0xFB, 0x6C, 0xAD, 0x4D, 0xF0, 0x45, 0xA7,
	0x08, 0x3D, 0x4E, 0xAE, 0x2D, 0x35, 0xA3, 0x17, 0x89, 0xD0, 0x1C, 0xCF, 0x09, 0x49, 0x55, 0x0F,
};

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-128 BDK (Calculation of AES PIN Block Format 4; top of page 31)
static const uint8_t pinblock[] = { 0x44, 0x12, 0x34, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0x2F, 0x69, 0xAD, 0xDE, 0x2E, 0x9E, 0x7A, 0xCE };
static const uint8_t panblock[] = { 0x44, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// Test data for MAC and encryption testing
static const char txn_data[] = "4012345678909D987";

// ANSI X9.24-3:2017 Supplement Test Vectors (first eight KSNs)
static const uint8_t ksn_verify[][DUKPT_AES_KSN_LEN] = {
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x01 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x02 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x03 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x04 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x05 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x06 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x07 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x00, 0x00, 0x08 },
};

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-256 BDK (first eight transaction/derivation keys; bottom of page 7)
static const uint8_t txn_key_verify[][DUKPT_AES_KEY_LEN(AES256)] = {
	{ 0x54, 0xAC, 0x2B, 0x32, 0xB1, 0x45, 0xEA, 0x4A, 0x55, 0x4C, 0xB8, 0xBC, 0x44, 0xB1, 0x74, 0x67, 0x06, 0x3A, 0x79, 0x98, 0x56, 0xB1, 0xCC, 0xC2, 0xA1, 0x38, 0xD3, 0x6E, 0x8D, 0xBF, 0x78, 0xB3 },
	{ 0x5D, 0xD5, 0xA0, 0x25, 0x38, 0x42, 0xBB, 0xBE, 0x1D, 0x7C, 0x0D, 0xA2, 0x70, 0x21, 0x41, 0x2C, 0x6F, 0x1F, 0xAB, 0x53, 0xFB, 0x92, 0x8D, 0xEA, 0xE5, 0x6D, 0xA0, 0x60, 0x90, 0xA9, 0xDE, 0x97 },
	{ 0x8E, 0xEE, 0xF7, 0xC4, 0x64, 0xAE, 0x41, 0x5B, 0xB1, 0xD7, 0x3F, 0xAE, 0xD2, 0x19, 0x93, 0xCD, 0x66, 0x9F, 0x79, 0x99, 0x09, 0x2A, 0x57, 0x9E, 0xC6, 0xDD, 0x3C, 0xC6, 0x80, 0xC6, 0x51, 0x71 },
	{ 0xC1, 0x8C, 0xBE, 0xD5, 0x70, 0xB3, 0xB8, 0x9E, 0xCA, 0xDA, 0x7C, 0xEC, 0x9C, 0x22, 0x4C, 0xD5, 0xA8, 0x6E, 0xCF, 0x3D, 0xE3, 0x77, 0xD3, 0xEF, 0xAB, 0x72, 0x0F, 0x8C, 0x4D, 0x76, 0xB9, 0xD0 },
	{ 0x6B, 0x3C, 0x3C, 0x93, 0x30, 0x71, 0x51, 0xC2, 0x5D, 0xC2, 0x30, 0x94, 0x56, 0xF0, 0x1C, 0x5C, 0x31, 0x08, 0xDA, 0xD5, 0x71, 0xC3, 0x21, 0x89, 0x9A, 0x9B, 0x7E, 0x0C, 0x00, 0x9F, 0xD2, 0xEB },
	{ 0xB8, 0xBB, 0x61, 0xAE, 0x3E, 0x2D, 0x5C, 0xD8, 0xC6, 0x99, 0xE0, 0xC5, 0x78, 0xFB, 0x2C, 0x7B, 0x89, 0xB0, 0xC0, 0xCF, 0x02, 0xDB, 0xAB, 0x60, 0x86, 0x4D, 0x80, 0x49, 0xC9, 0x86, 0xC8, 0x44 },
	{ 0x88, 0xD0, 0xAC, 0xA2, 0x87, 0xB3, 0x06, 0x6F, 0x5D, 0xE0, 0xC9, 0x33, 0x96, 0x33, 0x7D, 0x4C, 0x2D, 0xA8, 0xD9, 0x2C, 0x1F, 0x72, 0x0A, 0x57, 0x6D, 0x62, 0xCE, 0xB4, 0xC9, 0x79, 0xE0, 0x1E },
	{ 0x20, 0xA7, 0x96, 0xD5, 0x07, 0x7D, 0x51, 0xB8, 0xE7, 0x61, 0x38, 0x93, 0xA4, 0xF0, 0x95, 0xB1, 0x34, 0xE0, 0x29, 0x17, 0xDC, 0x84, 0xBD, 0x39, 0x1F, 0x36, 0x61, 0xD0, 0x87, 0x3F, 0xF3, 0x08 },
};

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-256 BDK (first eight PIN keys; bottom of page 7)
// AES-128 PIN encryption keys
static const uint8_t pin_key_aes128_verify[][DUKPT_AES_KEY_LEN(AES128)] = {
	{ 0x09, 0xC9, 0xC4, 0x32, 0x96, 0x68, 0x11, 0xD6, 0xB2, 0xC3, 0x33, 0x6B, 0xAC, 0x1B, 0x12, 0x02 },
	{ 0xD6, 0x32, 0x22, 0x6A, 0x80, 0x79, 0x5D, 0x13, 0xA8, 0x0A, 0xFE, 0x66, 0xA3, 0xE9, 0x7B, 0x01 },
	{ 0xC2, 0xCB, 0xD3, 0xD7, 0x66, 0xB1, 0x6F, 0x9F, 0x82, 0xF4, 0xEE, 0x3F, 0x74, 0x47, 0x89, 0x18 },
	{ 0x58, 0xA3, 0x77, 0x9C, 0x1E, 0x24, 0xB3, 0xED, 0xAF, 0x06, 0x86, 0x09, 0xE7, 0xE5, 0x6D, 0x59 },
	{ 0x97, 0x50, 0x4C, 0x8B, 0xB0, 0xFD, 0x4D, 0x4A, 0x88, 0xD6, 0x05, 0x14, 0x3B, 0xF0, 0x00, 0x25 },
	{ 0xBF, 0x28, 0x11, 0x41, 0x60, 0x9E, 0x6C, 0xAE, 0x7D, 0xF1, 0x0D, 0xFA, 0x47, 0xA8, 0xD0, 0x3D },
	{ 0xB7, 0xC6, 0xBB, 0x18, 0x71, 0x34, 0xE9, 0xD4, 0x29, 0xC3, 0xE8, 0xB7, 0xCC, 0xBD, 0x84, 0x77 },
	{ 0x53, 0xC1, 0xC6, 0x0A, 0x65, 0x53, 0x23, 0x13, 0x14, 0x1A, 0x10, 0x2A, 0xD7, 0x20, 0xE9, 0x67 },
};

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-256 BDK (first eight PIN keys; middle of page 13)
// AES-256 PIN encryption keys
static const uint8_t pin_key_aes256_verify[][DUKPT_AES_KEY_LEN(AES256)] = {
	{ 0x8C, 0x1A, 0xB7, 0xBE, 0xE9, 0x73, 0x82, 0x9E, 0x30, 0x24, 0x2E, 0x0B, 0xBB, 0xDD, 0x49, 0x46, 0xD5, 0x40, 0xC9, 0x8F, 0xC1, 0xB5, 0xBD, 0xCF, 0x94, 0x79, 0x00, 0x01, 0xA2, 0x3F, 0xD5, 0x02 },
	{ 0x35, 0x83, 0xD6, 0xCD, 0x02, 0xFC, 0x38, 0x82, 0x2C, 0xC7, 0x1A, 0x8D, 0x76, 0x78, 0xE0, 0x4F, 0x4A, 0x85, 0x56, 0x33, 0x5E, 0x6C, 0xC6, 0x68, 0x63, 0xD3, 0xDA, 0xDC, 0x5A, 0xEE, 0x2C, 0x62 },
	{ 0x96, 0xA1, 0xAB, 0x5D, 0x37, 0xCB, 0x7C, 0xF8, 0x1D, 0xDE, 0x64, 0xF6, 0x6C, 0x46, 0xE0, 0x38, 0x9B, 0x83, 0x3E, 0x7A, 0xD5, 0xF4, 0xE4, 0x4C, 0x79, 0x1F, 0x04, 0xFA, 0xFD, 0xA6, 0xDA, 0x0E },
	{ 0x42, 0x0A, 0xA5, 0x84, 0xBF, 0x21, 0x5C, 0x47, 0x77, 0xE9, 0x30, 0x09, 0xB5, 0x6D, 0x08, 0xDE, 0x80, 0x68, 0x70, 0x21, 0xD0, 0x7E, 0xD9, 0x63, 0x49, 0xFF, 0x71, 0x37, 0x9C, 0xE5, 0x63, 0x6D },
	{ 0xB1, 0xE9, 0xE3, 0xD9, 0x18, 0x95, 0x2E, 0x6E, 0x5F, 0x67, 0x91, 0x7F, 0x0F, 0xE7, 0x70, 0x60, 0xF8, 0x65, 0xAE, 0x27, 0xDC, 0xAD, 0x57, 0x42, 0xDD, 0xF9, 0x0F, 0x61, 0x45, 0x3B, 0x98, 0xBA },
	{ 0x87, 0x14, 0xEB, 0x94, 0xE3, 0xBF, 0xD3, 0x01, 0x8E, 0xC9, 0x9D, 0x04, 0x34, 0xD9, 0xC9, 0x4F, 0x07, 0x1A, 0xF2, 0xEE, 0xBF, 0x43, 0x32, 0xFB, 0x14, 0xF5, 0x17, 0x97, 0x93, 0xAA, 0x58, 0x2C },
	{ 0x69, 0x3C, 0x89, 0x3A, 0x1E, 0x81, 0xD2, 0x80, 0x30, 0x2E, 0x0A, 0x47, 0xE7, 0xE6, 0x34, 0x33, 0x7B, 0x9A, 0x9B, 0x26, 0xE7, 0xCC, 0x60, 0x64, 0xD8, 0x07, 0xE0, 0x8F, 0xF9, 0x11, 0xAF, 0xAC },
	{ 0x17, 0x3A, 0x45, 0x28, 0x42, 0x62, 0xA3, 0xE2, 0x92, 0xD8, 0x6D, 0x08, 0xFD, 0x6D, 0xE9, 0x16, 0x79, 0x63, 0x21, 0x44, 0x50, 0xD1, 0xD4, 0x8F, 0x61, 0x03, 0xBD, 0x2E, 0xB0, 0x8E, 0x61, 0xB5 },
};

// ANSI X9.24-1:2009 Supplement Test Vectors for AES-256 BDK (first eight MAC generation keys; bottom of page 7)
// CMAC-AES128 keys
static const uint8_t cmac_aes128_key_verify[][DUKPT_AES_KEY_LEN(AES128)] = {
	{ 0xF0, 0x4A, 0x1F, 0xAB, 0xD4, 0x17, 0x6E, 0x15, 0x49, 0x0C, 0xEC, 0x82, 0xE2, 0x17, 0xA9, 0x6D },
	{ 0xDD, 0x99, 0xD7, 0x7B, 0x4E, 0x2A, 0xB5, 0x38, 0xB2, 0x6B, 0xB6, 0xA8, 0xB3, 0xFB, 0x0B, 0xE3 },
	{ 0x5A, 0x74, 0x2A, 0x4A, 0x04, 0x03, 0xB3, 0xD7, 0xBB, 0x30, 0x84, 0x2D, 0xAF, 0xBB, 0x59, 0x72 },
	{ 0xC5, 0x31, 0xF7, 0xE0, 0x85, 0x14, 0x85, 0x8C, 0x44, 0x5D, 0x5F, 0x54, 0xBF, 0xE7, 0xDA, 0x8E },
	{ 0xE2, 0xE2, 0x5A, 0xA7, 0xFE, 0x6E, 0x5D, 0xD6, 0x04, 0x2C, 0x63, 0x2A, 0x5D, 0xFE, 0xD9, 0x45 },
	{ 0x07, 0xB2, 0x15, 0x92, 0x9C, 0x5D, 0xB4, 0x26, 0x2D, 0xEC, 0xEE, 0x4A, 0x03, 0x36, 0xDD, 0x4F },
	{ 0x3A, 0xC9, 0xCC, 0x51, 0x59, 0xF9, 0x6E, 0x10, 0xFC, 0xC5, 0xEB, 0x64, 0x01, 0x5A, 0xC7, 0x6A },
	{ 0x6E, 0x94, 0xA9, 0x28, 0x3E, 0xA9, 0xAE, 0xB7, 0xEA, 0xA7, 0x7C, 0x3F, 0xF5, 0x5F, 0xF2, 0xD1 },
};

// ANSI X9.24-1:2009 Supplement Test Vectors for AES-256 BDK (first eight MAC generation keys; middle of page 13)
// CMAC-AES256 keys
static const uint8_t cmac_aes256_key_verify[][DUKPT_AES_KEY_LEN(AES256)] = {
	{ 0x61, 0xDA, 0xBD, 0xF4, 0xB3, 0x40, 0xCF, 0x46, 0x1E, 0xE8, 0x60, 0xB1, 0xD1, 0xAB, 0x55, 0x35, 0x71, 0x42, 0xBD, 0x2D, 0x69, 0x77, 0x30, 0x68, 0x59, 0xCF, 0x49, 0xAE, 0xFE, 0x8F, 0x15, 0x49 },
	{ 0x44, 0x17, 0x35, 0x62, 0x19, 0xB2, 0xF9, 0x3C, 0xE3, 0xF2, 0x67, 0x16, 0x23, 0xDD, 0xCA, 0xB5, 0x8A, 0x8B, 0x85, 0xAD, 0x80, 0x66, 0x2A, 0x8D, 0x62, 0x80, 0x24, 0x00, 0x09, 0x56, 0xD4, 0x26 },
	{ 0x35, 0xBD, 0x00, 0xA4, 0x6F, 0x2A, 0x2B, 0xD1, 0x27, 0xF5, 0x65, 0xFB, 0xF2, 0x97, 0x4B, 0x73, 0x5A, 0xE3, 0xBB, 0x70, 0x24, 0x2C, 0x0A, 0x41, 0x58, 0x57, 0xCF, 0x69, 0xB2, 0xC2, 0x69, 0x1A },
	{ 0xD8, 0x06, 0x17, 0xC3, 0xC5, 0x86, 0x9A, 0x8D, 0xCF, 0x0D, 0xA5, 0x38, 0x3D, 0x03, 0x2A, 0x0D, 0x6E, 0x6C, 0x51, 0xC0, 0xBF, 0x64, 0x9B, 0xE9, 0x92, 0xBE, 0x84, 0xAA, 0x19, 0x1A, 0xE3, 0x26 },
	{ 0x8B, 0x04, 0x7E, 0x32, 0xC4, 0x76, 0xC0, 0xA0, 0xAF, 0x90, 0xA9, 0xB8, 0xD1, 0xC2, 0x47, 0xC4, 0x33, 0xE3, 0xD4, 0xC1, 0xDF, 0x1C, 0x7F, 0xC5, 0x2E, 0x8C, 0xB1, 0xDC, 0x4C, 0x8F, 0xB2, 0x75 },
	{ 0xA2, 0xFF, 0x6F, 0xFB, 0x37, 0xCB, 0x80, 0x42, 0xB8, 0xC9, 0xB2, 0xF9, 0x4C, 0x90, 0xC8, 0x3D, 0x94, 0xDD, 0x5B, 0xEC, 0xCD, 0x99, 0x51, 0xCF, 0xAB, 0x0B, 0xE7, 0xBD, 0x86, 0x5C, 0xA4, 0x03 },
	{ 0xE8, 0xA5, 0x70, 0x85, 0xDB, 0xE8, 0x04, 0xB8, 0xC2, 0x76, 0x7F, 0x9F, 0x77, 0xD5, 0x48, 0x54, 0x86, 0x1E, 0x99, 0x63, 0x3A, 0x06, 0x2C, 0x70, 0x0B, 0x4E, 0x50, 0xA8, 0x65, 0x15, 0x31, 0x50 },
	{ 0x94, 0x9A, 0x3F, 0xEF, 0x12, 0xDB, 0xD2, 0x73, 0xDD, 0x25, 0xBB, 0x60, 0xE2, 0x9B, 0xBE, 0x31, 0x3C, 0x87, 0x2A, 0x9D, 0xE3, 0xBE, 0x03, 0xA7, 0xE2, 0x96, 0x26, 0xAC, 0xA0, 0xA4, 0x28, 0x80 },
};

// ANSI X9.24-1:2009 Supplement Test Vectors for AES-256 BDK (first eight data encryption keys; bottom of page 7)
// AES128 data encryption keys
static const uint8_t data_aes128_key_verify[][DUKPT_AES_KEY_LEN(AES128)] = {
	{ 0x61, 0x6D, 0x59, 0xAE, 0x91, 0xF8, 0xCC, 0x70, 0x16, 0xF8, 0x9F, 0xDA, 0x29, 0x60, 0x5F, 0xA4 },
	{ 0x07, 0xB7, 0x9D, 0x9B, 0xFF, 0x36, 0x33, 0xC0, 0x7A, 0x9F, 0xDD, 0xF1, 0x32, 0x07, 0x0B, 0x30 },
	{ 0x70, 0x6E, 0x4E, 0x62, 0x9E, 0x46, 0x6B, 0xED, 0x95, 0x65, 0x48, 0xE7, 0xB0, 0xD9, 0x0C, 0x3D },
	{ 0xCF, 0x3A, 0x4D, 0x9C, 0xA7, 0xE9, 0x62, 0xE4, 0x02, 0x3A, 0x84, 0xA2, 0xFE, 0x47, 0xDC, 0x80 },
	{ 0x94, 0xC2, 0x84, 0x55, 0xAE, 0xAD, 0x97, 0x05, 0x55, 0xF3, 0x26, 0x29, 0x85, 0x57, 0xFA, 0x81 },
	{ 0x40, 0x8D, 0x3B, 0x9A, 0x7D, 0x1A, 0xF1, 0x09, 0xE2, 0xF6, 0x89, 0x51, 0x4B, 0xF7, 0x9A, 0xC7 },
	{ 0xDC, 0x29, 0x15, 0xBF, 0x42, 0x1D, 0x61, 0x7E, 0x77, 0x25, 0xE6, 0x3A, 0x7D, 0xAC, 0xB1, 0x8D },
	{ 0x89, 0x50, 0xDD, 0x50, 0xC2, 0x54, 0xC6, 0x0E, 0x26, 0x73, 0x7C, 0xA9, 0x22, 0x9F, 0x0F, 0x18 },
};

// ANSI X9.24-1:2009 Supplement Test Vectors for AES-256 BDK (first eight data encryption keys; middle of page 13)
// AES256 data encryption keys
static const uint8_t data_aes256_key_verify[][DUKPT_AES_KEY_LEN(AES256)] = {
	{ 0x71, 0xEB, 0x36, 0xC9, 0xA6, 0xB7, 0xF8, 0x01, 0xD1, 0xD1, 0x70, 0x0C, 0x29, 0x74, 0x1F, 0xC5, 0xA5, 0xC4, 0xE9, 0xB4, 0x5D, 0x74, 0x2D, 0xA7, 0xAF, 0x69, 0x92, 0xB8, 0xAA, 0x29, 0xAF, 0x58 },
	{ 0xD0, 0xAC, 0x9F, 0x71, 0xF8, 0x75, 0xFF, 0xFF, 0x3A, 0x83, 0x77, 0x8F, 0x72, 0xF3, 0x9E, 0xBB, 0x09, 0x24, 0xA5, 0xA5, 0x26, 0x61, 0x7A, 0xF6, 0x69, 0x66, 0x5E, 0x0A, 0x19, 0x72, 0x54, 0x65 },
	{ 0x8E, 0x70, 0xD5, 0xDF, 0x53, 0xF4, 0x8E, 0xD2, 0xF2, 0xA0, 0xB5, 0x4F, 0xC4, 0xF4, 0x5C, 0x84, 0x45, 0x79, 0xBE, 0x96, 0xF6, 0xF1, 0x61, 0x22, 0x2C, 0xDD, 0x50, 0x19, 0x3E, 0x2F, 0x73, 0x7F },
	{ 0x41, 0xD2, 0x3F, 0x7D, 0x78, 0xE2, 0x2A, 0x97, 0x8D, 0x72, 0x6B, 0xC7, 0x1D, 0x26, 0x63, 0x74, 0x26, 0x31, 0x20, 0xEE, 0x49, 0x14, 0x6C, 0xE5, 0xC1, 0x29, 0x1F, 0xD0, 0xEE, 0x7D, 0xDD, 0x31 },
	{ 0x81, 0x3D, 0x15, 0x6C, 0x14, 0x2E, 0x5B, 0xB8, 0xF1, 0x36, 0x42, 0x7E, 0xBD, 0x0A, 0x1A, 0xC4, 0xDC, 0x9B, 0x2B, 0x59, 0x63, 0xC4, 0x81, 0xF5, 0xE0, 0xA5, 0x8F, 0x4B, 0xF3, 0x3B, 0xD1, 0x85 },
	{ 0xF1, 0xFB, 0x05, 0x91, 0xAA, 0x2E, 0x45, 0xE1, 0xCE, 0x4C, 0x5D, 0x97, 0x0C, 0x73, 0x96, 0xC4, 0xA8, 0x7E, 0x53, 0xE5, 0x90, 0x0C, 0x4A, 0x6D, 0x95, 0xC1, 0x74, 0x14, 0x0C, 0xC0, 0xAC, 0x9C },
	{ 0x69, 0xBC, 0x5C, 0x9A, 0xFB, 0x2C, 0x93, 0xCC, 0x30, 0xC3, 0xF7, 0x52, 0x93, 0x60, 0xB3, 0x4D, 0x7B, 0x64, 0xB7, 0x20, 0x6E, 0x0F, 0x09, 0x40, 0xD8, 0x65, 0x43, 0x78, 0xC5, 0x48, 0x24, 0xF2 },
	{ 0x0B, 0xF8, 0x78, 0x9A, 0x21, 0xD0, 0x68, 0x41, 0x0A, 0x16, 0xC9, 0xF7, 0xFC, 0xBF, 0x65, 0xA7, 0xB4, 0xFF, 0x73, 0x20, 0x3A, 0xDC, 0x0F, 0x1B, 0x4B, 0x5E, 0x5B, 0xF8, 0x05, 0x0E, 0x42, 0x84 },
};

// ANSI X9.24-3:2017 Supplement Test Vectors (transaction counters 0x1fffe, 0x1ffff, 0x20000, 0x20001)
// NOTE: transaction counter 0x1ffff is commented out because it has more than the allowed 16 set bits
static const uint8_t ksn_verify2[][DUKPT_AES_KSN_LEN] = {
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x01, 0xFF, 0xFE },
	//{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x01, 0xFF, 0xFF },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x02, 0x00, 0x00 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0x00, 0x02, 0x00, 0x01 },
};

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-256 BDK (transaction keys for 0x1fffe, 0x1ffff, 0x20000, 0x20001; middle of page 10)
// NOTE: transaction counter 0x1ffff is commented out because it has more than the allowed 16 set bits
static const uint8_t txn_key_verify2[][DUKPT_AES_KEY_LEN(AES256)] = {
	{ 0xA2, 0x89, 0x50, 0x8C, 0xBF, 0x12, 0x28, 0x45, 0x2C, 0xD8, 0x6A, 0xB7, 0x7B, 0x15, 0xCB, 0x35, 0x57, 0x7A, 0xC8, 0x28, 0xC1, 0x8B, 0xB6, 0x66, 0x81, 0xE5, 0xA1, 0x6D, 0x6C, 0x9C, 0xCE, 0xD3 },
	//{ 0x7C, 0x1F, 0x24, 0xBC, 0x33, 0xC5, 0xB1, 0x46, 0xE1, 0xD3, 0x01, 0x51, 0x26, 0xF4, 0xAC, 0x2E, 0x0C, 0x48, 0xAC, 0x08, 0x0D, 0xC9, 0x23, 0x41, 0x37, 0xB8, 0x28, 0x90, 0xE8, 0xE9, 0x1F, 0xB8 },
	{ 0xD6, 0x2D, 0xDA, 0x94, 0xA4, 0x7D, 0x7D, 0xA5, 0xD7, 0x63, 0x44, 0x3B, 0x4E, 0xCB, 0x15, 0xEA, 0x8D, 0xD6, 0x2E, 0x0E, 0x4F, 0x91, 0x59, 0x58, 0xBA, 0x45, 0x95, 0x91, 0xF8, 0x31, 0x2E, 0x37 },
	{ 0x44, 0x11, 0x0A, 0x11, 0x02, 0x74, 0x8D, 0x4A, 0x3A, 0xC3, 0x26, 0xF5, 0x3D, 0x8C, 0xAC, 0x65, 0x02, 0x12, 0x59, 0x0C, 0xA7, 0x12, 0x6D, 0x54, 0x54, 0x6D, 0xDE, 0x0F, 0x20, 0xE8, 0x9C, 0xEE },
};

// ANSI X9.24-3:2017 Supplement Test Vectors (last four transaction counters)
static const uint8_t ksn_verify3[][DUKPT_AES_KSN_LEN] = {
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0xFF, 0xFE, 0x20, 0x00 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0xFF, 0xFE, 0x40, 0x00 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0xFF, 0xFE, 0x80, 0x00 },
	{ 0x12, 0x34, 0x56, 0x78, 0x90, 0x12, 0x34, 0x56, 0xFF, 0xFF, 0x00, 0x00 },
};

// ANSI X9.24-3:2017 Supplement Test Vectors for AES-256 BDK (last four transaction; page 12)
static const uint8_t txn_key_verify3[][DUKPT_AES_KEY_LEN(AES256)] = {
	{ 0x46, 0x25, 0xEB, 0x06, 0xE4, 0x88, 0x6D, 0x4A, 0xFC, 0xC9, 0xAE, 0x37, 0xED, 0x4F, 0x4E, 0x4E, 0x16, 0x53, 0xC9, 0xE6, 0x0E, 0x3F, 0x24, 0x74, 0x2A, 0x87, 0xA2, 0x6A, 0xA9, 0x6A, 0xB7, 0xA6 },
	{ 0xFF, 0x20, 0xE1, 0xBB, 0x57, 0x55, 0x39, 0xAC, 0xCB, 0x44, 0xE3, 0x11, 0x1B, 0xE8, 0x75, 0x7F, 0x83, 0xAE, 0x85, 0x49, 0xA2, 0xDD, 0x71, 0xB4, 0x41, 0xA4, 0xA4, 0x24, 0xF7, 0xFF, 0xD4, 0xB1 },
	{ 0x63, 0x05, 0x35, 0xC9, 0xC5, 0x3E, 0x1E, 0xC6, 0x52, 0x40, 0x16, 0x93, 0x0B, 0x56, 0xF6, 0x72, 0x89, 0x09, 0xC4, 0x54, 0x03, 0x53, 0x6B, 0x41, 0x9A, 0xEB, 0xCB, 0x25, 0xB7, 0x35, 0x1C, 0x07 },
	{ 0x6D, 0x6D, 0xB7, 0xAA, 0xAE, 0x8B, 0x3E, 0xA9, 0x0E, 0x57, 0xA3, 0x9E, 0x4B, 0xBA, 0x71, 0xE1, 0x73, 0xB2, 0x1B, 0x44, 0x6B, 0x30, 0xA7, 0x8D, 0x64, 0xBF, 0xC6, 0xA8, 0x80, 0x6C, 0x55, 0xEE },
};

static void print_buf(const char* buf_name, const void* buf, size_t length)
{
	const uint8_t* ptr = buf;
	printf("%s: ", buf_name);
	for (size_t i = 0; i < length; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}

static int verify_pin_block4(
	const void* pin_key,
	size_t pin_key_len,
	const void* encrypted_pinblock,
	const uint8_t* pinblock,
	const uint8_t* panblock
)
{
	int r;
	uint8_t decrypted_pinblock[DUKPT_AES_PINBLOCK_LEN];

	r = crypto_aes_decrypt(
		pin_key,
		pin_key_len,
		NULL,
		encrypted_pinblock,
		DUKPT_AES_PINBLOCK_LEN,
		decrypted_pinblock
	);
	if (r) {
		fprintf(stderr, "crypto_aes_decrypt() failed; r=%d\n", r);
		return r;
	}

	for (unsigned int i = 0; i < DUKPT_AES_PINBLOCK_LEN; ++i) {
		decrypted_pinblock[i] ^= panblock[i];
	}

	r = crypto_aes_decrypt(
		pin_key,
		pin_key_len,
		NULL,
		decrypted_pinblock,
		DUKPT_AES_PINBLOCK_LEN,
		decrypted_pinblock
	);
	if (r) {
		fprintf(stderr, "crypto_aes_decrypt() failed; r=%d\n", r);
		return r;
	}

	if (memcmp(decrypted_pinblock, pinblock, DUKPT_AES_PINBLOCK_LEN) != 0) {
		fprintf(stderr, "Decrypted PIN block is incorrect\n");
		print_buf("decrypted_pinblock", decrypted_pinblock, DUKPT_AES_PINBLOCK_LEN);
		print_buf("pinblock", pinblock, DUKPT_AES_PINBLOCK_LEN);
		return 1;
	}

	return 0;
}

static int verify_cmac(
	const void* cmac_key,
	size_t cmac_key_len,
	const void* buf,
	size_t buf_len,
	void* cmac
)
{
	int r;
	uint8_t cmac_verify[DUKPT_AES_CMAC_LEN];

	r = crypto_aes_cmac(cmac_key, cmac_key_len, buf, buf_len, cmac_verify);
	if (r) {
		fprintf(stderr, "crypto_aes_cmac() failed; r=%d\n", r);
		return r;
	}

	if (memcmp(cmac, cmac_verify, sizeof(cmac_verify)) != 0) {
		fprintf(stderr, "CMAC is incorrect\n");
		print_buf("cmac", cmac, DUKPT_AES_CMAC_LEN);
		print_buf("cmac_verify", cmac_verify, sizeof(cmac_verify));
		return 1;
	}

	return 0;
}

int main(void)
{
	int r;
	uint8_t ik[DUKPT_AES_KEY_LEN(AES256)];
	uint8_t ksn[DUKPT_AES_KSN_LEN];
	uint8_t txn_key[DUKPT_AES_KEY_LEN(AES256)];
	uint8_t encrypted_pinblock[DUKPT_AES_PINBLOCK_LEN];
	uint8_t decrypted_pinblock[DUKPT_AES_PINBLOCK_LEN];
	uint8_t cmac[DUKPT_AES_CMAC_LEN];
	uint8_t hmac[DUKPT_AES_HMAC_SHA256_LEN];
	uint8_t iv[DUKPT_AES_BLOCK_LEN];
	uint8_t txn_data_buf[DUKPT_AES_BLOCK_LEN * 2];
	uint8_t encrypted_txn_data[DUKPT_AES_BLOCK_LEN * 2];
	uint8_t decrypted_txn_data[DUKPT_AES_BLOCK_LEN * 2];

	// Test Initial Key (IK) derivation using AES256
	r = dukpt_aes_derive_ik(bdk, sizeof(bdk), ikid, ik);
	if (r) {
		fprintf(stderr, "dukpt_aes_derive_ik() failed; r=%d\n", r);
		goto exit;
	}
	if (memcmp(ik, ik_verify, sizeof(ik_verify)) != 0) {
		fprintf(stderr, "Initial key derivation is incorrect\n");
		print_buf("ik", ik, sizeof(ik));
		print_buf("ik_verify", ik_verify, sizeof(ik_verify));
		r = 1;
		goto exit;
	}

	// Advance to first KSN
	memcpy(ksn, ikid, DUKPT_AES_KSN_LEN);
	memset(ksn + DUKPT_AES_IK_ID_LEN, 0, DUKPT_AES_KSN_LEN - DUKPT_AES_IK_ID_LEN);
	r = dukpt_aes_ksn_advance(ksn);
	if (r) {
		fprintf(stderr, "dukpt_aes_ksn_advance() failed; r=%d\n", r);
		goto exit;
	}

	// Test transaction key derivation from Initial Key (IK) for initial KSNs
	for (size_t i = 0; i < sizeof(ksn_verify) / sizeof(ksn_verify[0]); ++i) {
		// Validate KSN
		if (!dukpt_aes_ksn_is_valid(ksn)) {
			fprintf(stderr, "KSN %zu is invalid\n", i);
			r = 1;
			goto exit;
		}
		if (memcmp(ksn, ksn_verify[i], DUKPT_AES_KSN_LEN) != 0) {
			fprintf(stderr, "KSN %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Test transaction key derivation from Initial Key (IK)
		r = dukpt_aes_derive_txn_key(ik, sizeof(ik), ksn, txn_key);
		if (r) {
			fprintf(stderr, "dukpt_aes_derive_txn_key() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(txn_key, txn_key_verify[i], sizeof(txn_key_verify[i])) != 0) {
			fprintf(stderr, "Transaction key derivation %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Test AES-128 PIN block encryption
		r = dukpt_aes_encrypt_pinblock(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			pinblock,
			panblock,
			encrypted_pinblock
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_encrypt_pinblock() failed; r=%d\n", r);
			goto exit;
		}
		r = verify_pin_block4(
			pin_key_aes128_verify[i],
			sizeof(pin_key_aes128_verify[i]),
			encrypted_pinblock,
			pinblock,
			panblock
		);
		if (r) {
			fprintf(stderr, "verify_pin_block4() failed; r=%d\n", r);
			goto exit;
		}

		// Test AES-128 PIN block decryption
		r = dukpt_aes_decrypt_pinblock(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			encrypted_pinblock,
			panblock,
			decrypted_pinblock
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_decrypt_pinblock() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(decrypted_pinblock, pinblock, sizeof(pinblock)) != 0) {
			fprintf(stderr, "Decrypted PIN block %zu is incorrect\n", i);
			print_buf("decrypted_pinblock", decrypted_pinblock, sizeof(decrypted_pinblock));
			print_buf("pinblock", pinblock, sizeof(pinblock));
			r = 1;
			goto exit;
		}

		// Test AES-256 PIN block encryption
		r = dukpt_aes_encrypt_pinblock(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES256,
			pinblock,
			panblock,
			encrypted_pinblock
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_encrypt_pinblock() failed; r=%d\n", r);
			goto exit;
		}
		r = verify_pin_block4(
			pin_key_aes256_verify[i],
			sizeof(pin_key_aes256_verify[i]),
			encrypted_pinblock,
			pinblock,
			panblock
		);
		if (r) {
			fprintf(stderr, "verify_pin_block4() failed; r=%d\n", r);
			goto exit;
		}

		// Test AES-256 PIN block decryption
		r = dukpt_aes_decrypt_pinblock(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES256,
			encrypted_pinblock,
			panblock,
			decrypted_pinblock
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_decrypt_pinblock() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(decrypted_pinblock, pinblock, sizeof(pinblock)) != 0) {
			fprintf(stderr, "Decrypted PIN block %zu is incorrect\n", i);
			print_buf("decrypted_pinblock", decrypted_pinblock, sizeof(decrypted_pinblock));
			print_buf("pinblock", pinblock, sizeof(pinblock));
			r = 1;
			goto exit;
		}

		// Test CMAC-AES128 for request
		r = dukpt_aes_generate_request_cmac(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			txn_data,
			sizeof(txn_data),
			cmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_generate_request_cmac() failed; r=%d\n", r);
			goto exit;
		}
		r = verify_cmac(
			cmac_aes128_key_verify[i],
			sizeof(cmac_aes128_key_verify[i]),
			txn_data,
			sizeof(txn_data),
			cmac
		);
		if (r) {
			fprintf(stderr, "verify_cmac() failed; r=%d\n", r);
			goto exit;
		}
		r = dukpt_aes_verify_request_cmac(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			txn_data,
			sizeof(txn_data),
			cmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_verify_request_cmac() failed; r=%d\n", r);
			goto exit;
		}

		// Test CMAC-AES128 for response
		// NOTE: Unfortunately X9.24-3:2017 does not provide test vectors for
		// the response MAC key
		r = dukpt_aes_generate_response_cmac(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			txn_data,
			sizeof(txn_data),
			cmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_generate_response_cmac() failed; r=%d\n", r);
			goto exit;
		}
		r = dukpt_aes_verify_response_cmac(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			txn_data,
			sizeof(txn_data),
			cmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_verify_response_cmac() failed; r=%d\n", r);
			goto exit;
		}

		// Test CMAC-AES256 for request
		r = dukpt_aes_generate_request_cmac(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES256,
			txn_data,
			sizeof(txn_data),
			cmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_generate_request_cmac() failed; r=%d\n", r);
			goto exit;
		}
		r = verify_cmac(
			cmac_aes256_key_verify[i],
			sizeof(cmac_aes256_key_verify[i]),
			txn_data,
			sizeof(txn_data),
			cmac
		);
		if (r) {
			fprintf(stderr, "verify_cmac() failed; r=%d\n", r);
			goto exit;
		}
		r = dukpt_aes_verify_request_cmac(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES256,
			txn_data,
			sizeof(txn_data),
			cmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_verify_request_cmac() failed; r=%d\n", r);
			goto exit;
		}

		// Test CMAC-AES256 for response
		// NOTE: Unfortunately X9.24-3:2017 does not provide test vectors for
		// the response MAC key
		r = dukpt_aes_generate_response_cmac(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES256,
			txn_data,
			sizeof(txn_data),
			cmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_generate_response_cmac() failed; r=%d\n", r);
			goto exit;
		}
		r = dukpt_aes_verify_response_cmac(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES256,
			txn_data,
			sizeof(txn_data),
			cmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_verify_response_cmac() failed; r=%d\n", r);
			goto exit;
		}

		// Test HMAC-SHA256 for request
		r = dukpt_aes_generate_request_hmac_sha256(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_HMAC256,
			txn_data,
			sizeof(txn_data),
			hmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_generate_request_hmac_sha256() failed; r=%d\n", r);
			goto exit;
		}
		// NOTE: Unfortunately X9.24-3:2017 does not provide test vectors for
		// the HMAC key
		r = dukpt_aes_verify_request_hmac_sha256(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_HMAC256,
			txn_data,
			sizeof(txn_data),
			hmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_verify_request_hmac_sha256() failed; r=%d\n", r);
			goto exit;
		}

		// Test HMAC-SHA256 for response
		r = dukpt_aes_generate_response_hmac_sha256(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_HMAC256,
			txn_data,
			sizeof(txn_data),
			hmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_generate_response_hmac_sha256() failed; r=%d\n", r);
			goto exit;
		}
		// NOTE: Unfortunately X9.24-3:2017 does not provide test vectors for
		// the HMAC key
		r = dukpt_aes_verify_response_hmac_sha256(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_HMAC256,
			txn_data,
			sizeof(txn_data),
			hmac
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_verify_response_hmac_sha256() failed; r=%d\n", r);
			goto exit;
		}

		// Test AES128 request encryption
		memset(iv, 0, sizeof(iv));
		memset(txn_data_buf, 0, sizeof(txn_data_buf));
		memcpy(txn_data_buf, txn_data, sizeof(txn_data));
		r = dukpt_aes_encrypt_request(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			iv,
			txn_data_buf,
			sizeof(txn_data_buf),
			encrypted_txn_data
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_encrypt_request() failed; r=%d\n", r);
			goto exit;
		}
		memset(decrypted_txn_data, 0, sizeof(decrypted_txn_data));
		r = crypto_aes_decrypt(
			data_aes128_key_verify[i],
			sizeof(data_aes128_key_verify[i]),
			iv,
			encrypted_txn_data,
			sizeof(encrypted_txn_data),
			decrypted_txn_data
		);
		if (r) {
			fprintf(stderr, "crypto_aes_decrypt() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(decrypted_txn_data, txn_data_buf, sizeof(txn_data_buf)) != 0) {
			fprintf(stderr, "Decrypted txn request %zu is incorrect\n", i);
			print_buf("decrypted_txn_data", decrypted_pinblock, sizeof(decrypted_pinblock));
			print_buf("txn_data_buf", txn_data_buf, sizeof(txn_data_buf));
			r = 1;
			goto exit;
		}

		// Test AES128 request decryption
		memset(decrypted_txn_data, 0, sizeof(decrypted_txn_data));
		r = dukpt_aes_decrypt_request(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			iv,
			encrypted_txn_data,
			sizeof(encrypted_txn_data),
			decrypted_txn_data
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_decrypt_request() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(decrypted_txn_data, txn_data_buf, sizeof(txn_data_buf)) != 0) {
			fprintf(stderr, "Decrypted txn request %zu is incorrect\n", i);
			print_buf("decrypted_txn_data", decrypted_pinblock, sizeof(decrypted_pinblock));
			print_buf("txn_data_buf", txn_data_buf, sizeof(txn_data_buf));
			r = 1;
			goto exit;
		}

		// Test AES128 response encryption
		// NOTE: Unfortunately X9.24-1:2017 does not provide test vectors for
		// the transaction response data encryption key nor samples of the
		// encrypted transaction response data
		memset(iv, 0, sizeof(iv));
		memset(txn_data_buf, 0, sizeof(txn_data_buf));
		memcpy(txn_data_buf, txn_data, sizeof(txn_data));
		r = dukpt_aes_encrypt_response(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			iv,
			txn_data_buf,
			sizeof(txn_data_buf),
			encrypted_txn_data
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_encrypt_response() failed; r=%d\n", r);
			goto exit;
		}

		// Test AES128 response decryption
		memset(decrypted_txn_data, 0, sizeof(decrypted_txn_data));
		r = dukpt_aes_decrypt_response(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES128,
			iv,
			encrypted_txn_data,
			sizeof(encrypted_txn_data),
			decrypted_txn_data
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_decrypt_response() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(decrypted_txn_data, txn_data_buf, sizeof(txn_data_buf)) != 0) {
			fprintf(stderr, "Decrypted txn response %zu is incorrect\n", i);
			print_buf("decrypted_txn_data", decrypted_pinblock, sizeof(decrypted_pinblock));
			print_buf("txn_data_buf", txn_data_buf, sizeof(txn_data_buf));
			r = 1;
			goto exit;
		}

		// Test AES256 request encryption
		memset(iv, 0, sizeof(iv));
		memset(txn_data_buf, 0, sizeof(txn_data_buf));
		memcpy(txn_data_buf, txn_data, sizeof(txn_data));
		r = dukpt_aes_encrypt_request(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES256,
			iv,
			txn_data_buf,
			sizeof(txn_data_buf),
			encrypted_txn_data
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_encrypt_request() failed; r=%d\n", r);
			goto exit;
		}
		memset(decrypted_txn_data, 0, sizeof(decrypted_txn_data));
		r = crypto_aes_decrypt(
			data_aes256_key_verify[i],
			sizeof(data_aes256_key_verify[i]),
			iv,
			encrypted_txn_data,
			sizeof(encrypted_txn_data),
			decrypted_txn_data
		);
		if (r) {
			fprintf(stderr, "crypto_aes_decrypt() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(decrypted_txn_data, txn_data_buf, sizeof(txn_data_buf)) != 0) {
			fprintf(stderr, "Decrypted txn request %zu is incorrect\n", i);
			print_buf("decrypted_txn_data", decrypted_pinblock, sizeof(decrypted_pinblock));
			print_buf("txn_data_buf", txn_data_buf, sizeof(txn_data_buf));
			r = 1;
			goto exit;
		}

		// Test AES256 request decryption
		memset(decrypted_txn_data, 0, sizeof(decrypted_txn_data));
		r = dukpt_aes_decrypt_request(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES256,
			iv,
			encrypted_txn_data,
			sizeof(encrypted_txn_data),
			decrypted_txn_data
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_decrypt_request() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(decrypted_txn_data, txn_data_buf, sizeof(txn_data_buf)) != 0) {
			fprintf(stderr, "Decrypted txn request %zu is incorrect\n", i);
			print_buf("decrypted_txn_data", decrypted_pinblock, sizeof(decrypted_pinblock));
			print_buf("txn_data_buf", txn_data_buf, sizeof(txn_data_buf));
			r = 1;
			goto exit;
		}

		// Test AES256 response encryption
		// NOTE: Unfortunately X9.24-1:2017 does not provide test vectors for
		// the transaction response data encryption key nor samples of the
		// encrypted transaction response data
		memset(iv, 0, sizeof(iv));
		memset(txn_data_buf, 0, sizeof(txn_data_buf));
		memcpy(txn_data_buf, txn_data, sizeof(txn_data));
		r = dukpt_aes_encrypt_response(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES256,
			iv,
			txn_data_buf,
			sizeof(txn_data_buf),
			encrypted_txn_data
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_encrypt_response() failed; r=%d\n", r);
			goto exit;
		}

		// Test AES256 response decryption
		memset(decrypted_txn_data, 0, sizeof(decrypted_txn_data));
		r = dukpt_aes_decrypt_response(
			txn_key,
			sizeof(txn_key),
			ksn,
			DUKPT_AES_KEY_TYPE_AES256,
			iv,
			encrypted_txn_data,
			sizeof(encrypted_txn_data),
			decrypted_txn_data
		);
		if (r) {
			fprintf(stderr, "dukpt_aes_decrypt_response() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(decrypted_txn_data, txn_data_buf, sizeof(txn_data_buf)) != 0) {
			fprintf(stderr, "Decrypted txn response %zu is incorrect\n", i);
			print_buf("decrypted_txn_data", decrypted_pinblock, sizeof(decrypted_pinblock));
			print_buf("txn_data_buf", txn_data_buf, sizeof(txn_data_buf));
			r = 1;
			goto exit;
		}

		// Advance KSN
		r = dukpt_aes_ksn_advance(ksn);
		if (r) {
			fprintf(stderr, "dukpt_aes_ksn_advance() failed; r=%d\n", r);
			goto exit;
		}
	}

	// Test transaction key derivation from Initial Key (IK) for rollover KSNs
	memcpy(ksn, ksn_verify2[0], DUKPT_AES_KSN_LEN);
	for (size_t i = 0; i < sizeof(ksn_verify2) / sizeof(ksn_verify2[0]); ++i) {
		// Validate KSN
		if (!dukpt_aes_ksn_is_valid(ksn)) {
			fprintf(stderr, "KSN %zu is invalid\n", i);
			r = 1;
			goto exit;
		}
		if (memcmp(ksn, ksn_verify2[i], DUKPT_AES_KSN_LEN) != 0) {
			fprintf(stderr, "KSN %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Test transaction key derivation from Initial Key (IK)
		r = dukpt_aes_derive_txn_key(ik, sizeof(ik), ksn, txn_key);
		if (r) {
			fprintf(stderr, "dukpt_aes_derive_txn_key() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(txn_key, txn_key_verify2[i], sizeof(txn_key_verify2[i])) != 0) {
			fprintf(stderr, "Transaction key derivation %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Advance KSN
		r = dukpt_aes_ksn_advance(ksn);
		if (r) {
			fprintf(stderr, "dukpt_aes_ksn_advance() failed; r=%d\n", r);
			goto exit;
		}
	}

	// Test transaction key derivation from Initial Key (IK) for last KSNs
	memcpy(ksn, ksn_verify3[0], DUKPT_AES_KSN_LEN);
	for (size_t i = 0; i < sizeof(ksn_verify3) / sizeof(ksn_verify3[0]); ++i) {
		// Validate KSN
		if (!dukpt_aes_ksn_is_valid(ksn)) {
			fprintf(stderr, "KSN %zu is invalid\n", i);
			r = 1;
			goto exit;
		}
		if (memcmp(ksn, ksn_verify3[i], DUKPT_AES_KSN_LEN) != 0) {
			fprintf(stderr, "KSN %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Test transaction key derivation from Initial Key (IK)
		r = dukpt_aes_derive_txn_key(ik, sizeof(ik), ksn, txn_key);
		if (r) {
			fprintf(stderr, "dukpt_aes_derive_txn_key() failed; r=%d\n", r);
			goto exit;
		}
		if (memcmp(txn_key, txn_key_verify3[i], sizeof(txn_key_verify3[i])) != 0) {
			fprintf(stderr, "Transaction key derivation %zu is incorrect\n", i);
			r = 1;
			goto exit;
		}

		// Advance KSN
		r = dukpt_aes_ksn_advance(ksn);
		if (i != (sizeof(ksn_verify3) / sizeof(ksn_verify3[0])) - 1) {
			// If not last KSN, it must advance
			if (r) {
				fprintf(stderr, "dukpt_aes_ksn_advance() failed; r=%d\n", r);
				goto exit;
			}
		}
	}

	printf("All tests passed.\n");
	r = 0;
	goto exit;

exit:
	return r;
}
