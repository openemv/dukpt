/**
 * @file validators.cpp
 * @brief Various validators for for QWidgets
 *
 * Copyright (c) 2022 Leon Lynch
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include "validators.h"

#include "dukpt_tdes.h"
#include "dukpt_aes.h"

#include <QtCore/QByteArray>

#include <cctype>

void DecStringValidator::setMinLength(unsigned int x)
{
	if (x != minLength) {
		minLength = x;
		emit minLengthChanged(x);
		emit changed();
	}
}

void DecStringValidator::setMaxLength(unsigned int x)
{
	if (x != maxLength) {
		maxLength = x;
		emit maxLengthChanged(x);
		emit changed();
	}
}

QValidator::State DecStringValidator::validate(QString& input, int& pos) const
{
	if (minLength) {
		// Ensure that decimal string length is at least minLength
		if (static_cast<unsigned int>(input.length()) < minLength) {
			return Intermediate;
		}
	}

	if (maxLength) {
		// Ensure that decimal string does not exceed maxLength
		if (static_cast<unsigned int>(input.length()) > maxLength) {
			return Intermediate;
		}
	}

	// Ensure that decimal string contains only decimal digits
	for (QChar c : qAsConst(input)) {
		if (!std::isdigit(c.toLatin1())) {
			// Non-decimal digit is not allowed
			return Intermediate;
		}
	}

	return Acceptable;
}

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

QValidator::State DukptKsnStringValidator::validate(QString& input, int& pos) const
{
	State state;
	QByteArray tmp;
	std::vector<std::uint8_t> ksn;

	// Ensure that input is a hex string
	state = HexStringValidator::validate(input, pos);
	if (state != Acceptable) {
		return state;
	}

	// Convert to std::vector. This is mostly because std::vector<>::resize()
	// adds zero bytes in contrast to QByteArray::resize() adding uninitialised
	// bytes.
	tmp = QByteArray::fromHex(input.toUtf8());
	ksn = std::vector<std::uint8_t>(tmp.constData(), tmp.constData() + tmp.size());

	if (cipher == TDES) {
		// Validate length
		if (ksn.size() && // Empty string is allowed
			ksn.size() != DUKPT_TDES_KSN_LEN - 2 &&
			ksn.size() != DUKPT_TDES_KSN_LEN
		) {
			return Intermediate;
		}

		// Validate transaction counter
		ksn.resize(DUKPT_TDES_KSN_LEN);
		if (dukpt_tdes_ksn_is_valid(ksn.data())) {
			return Acceptable;
		}

		// Allow IKSN (zero transaction counter)
		if (ksn[DUKPT_TDES_KSN_LEN - 1] == 0 &&
			ksn[DUKPT_TDES_KSN_LEN - 2] == 0 &&
			(ksn[DUKPT_TDES_KSN_LEN - 3] & 0x1f) == 0
		) {
			return Acceptable;
		}

		return Intermediate;

	} else if (cipher == AES) {
		// Validate length
		if (ksn.size() && // Empty string is allowed
			ksn.size() != DUKPT_AES_IK_ID_LEN &&
			ksn.size() != DUKPT_AES_KSN_LEN
		) {
			return Intermediate;
		}

		// Validate transaction counter
		ksn.resize(DUKPT_AES_KSN_LEN);
		if (dukpt_aes_ksn_is_valid(ksn.data())) {
			return Acceptable;
		}

		// Allow IKSN (zero transaction counter)
		if (ksn[DUKPT_AES_KSN_LEN - 1] == 0 &&
			ksn[DUKPT_AES_KSN_LEN - 2] == 0 &&
			ksn[DUKPT_AES_KSN_LEN - 3] == 0 &&
			ksn[DUKPT_AES_KSN_LEN - 4] == 0
		) {
			return Acceptable;
		}

		return Intermediate;
	}

	return Acceptable;
}

void CryptoKbpkStringValidator::setFormatVersion(FormatVersion fv)
{
	if (fv != formatVersion) {
		formatVersion = fv;
		emit formatVersionChanged(fv);
		emit changed();
	}
}

QValidator::State CryptoKbpkStringValidator::validate(QString& input, int& pos) const
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
	switch (formatVersion) {
		case B:
			// Format version B only allows TDES KBPKs
			if (dataLength && // Empty string is allowed
				dataLength != 16 && // Double length TDES
				dataLength != 24 // Triple length TDES
			) {
				return Intermediate;
			}
			break;

		case D:
		case E:
			// Format version D and E only allow AES KBPKs
			if (dataLength && // Empty string is allowed
				dataLength != 16 && // AES-128
				dataLength != 24 && // AES-192
				dataLength != 32 // AES-256
			) {
				return Intermediate;
			}
		break;
	}

	return Acceptable;
}
