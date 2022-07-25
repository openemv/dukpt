/**
 * @file validators.cpp
 * @brief Various validators for for QWidgets
 *
 * Copyright (c) 2022 Leon Lynch
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

#include "validators.h"

#include <cctype>

QValidator::State HexStringValidator::validate(QString& input, int& pos) const
{
	// Ensure that hex string length is a multiple of 2
	if (input.length() & 0x1) {
		return Intermediate;
	}

	// Ensure that hex string contains only hex digits
	for (QChar c : qAsConst(input)) {
		if (!std::isxdigit(c.toLatin1())) {
			// Non-hex digit is not allowed
			return Intermediate;
		}
	}

	return Acceptable;
}

void CryptoValidator::setCipher(CryptoValidator::Cipher c)
{
	if (c != cipher) {
		cipher = c;
		emit cipherChanged(c);
		emit changed();
	}
}

void CryptoHexStringValidator::setMaxBlocks(unsigned int max)
{
	if (max != maxBlocks) {
		maxBlocks = max;
		emit maxBlocksChanged(max);
		emit changed();
	}
}

QValidator::State CryptoKeyStringValidator::validate(QString& input, int& pos) const
{
	State state;
	unsigned int dataLength;

	// Ensure that input is a hex string
	state = HexStringValidator::validate(input, pos);
	if (state != Acceptable) {
		return state;
	}

	dataLength = input.length() / 2;

	// Ensure that data length is a valid key size
	if (cipher == TDES) {
		if (dataLength && // Empty string is allowed
			dataLength != 16 // Double length TDES
		) {
			return Intermediate;
		}
	} else if (cipher == AES) {
		if (dataLength && // Empty string is allowed
			dataLength != 16 && // AES-128
			dataLength != 24 && // AES-192
			dataLength != 32 // AES-256
		) {
			return Intermediate;
		}
	}

	return Acceptable;
}

QValidator::State CryptoHexStringValidator::validate(QString& input, int& pos) const
{
	State state;
	unsigned int dataLength;
	unsigned int blockSize;

	// Ensure that input is a hex string
	state = HexStringValidator::validate(input, pos);
	if (state != Acceptable) {
		return state;
	}

	dataLength = input.length() / 2;

	// Ensure that data length is a multiple of block size
	if (cipher == TDES) {
		blockSize = 8;  // TDES has 8 byte block size
	} else if (cipher == AES) {
		blockSize = 16; // AES has 16 byte block size
	} else {
		blockSize = 1; // Ignore block size
	}
	if ((dataLength & (blockSize-1)) != 0) {
		return Intermediate;
	}

	if (maxBlocks) {
		// Ensure that data length does not exceed maximum number of blocks
		if (dataLength > blockSize * maxBlocks) {
			return Intermediate;
		}
	}

	return Acceptable;
}
