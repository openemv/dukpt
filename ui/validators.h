/**
 * @file validators.h
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

#ifndef VALIDATORS_H
#define VALIDATORS_H

#include <QtGui/QValidator>

class HexStringValidator : public QValidator
{
	Q_OBJECT

public:
	explicit HexStringValidator(QObject* parent = nullptr)
	: QValidator(parent)
	{}
	Q_DISABLE_COPY(HexStringValidator)

public:
	State validate(QString& input, int& pos) const override;
};

class CryptoValidator : public HexStringValidator
{
	Q_OBJECT

public:
	enum Cipher {
		TDES,
		AES,
	};
	Q_ENUM(Cipher)

protected:
	Cipher cipher;

public:
	CryptoValidator(Cipher cipher, QObject* parent = nullptr)
	: HexStringValidator(parent),
	  cipher(cipher)
	{}
	Q_DISABLE_COPY(CryptoValidator)

public slots:
	void setCipher(Cipher c);

signals:
	void cipherChanged(Cipher cipher);
};

class CryptoKeyStringValidator : public CryptoValidator
{
	Q_OBJECT

public:
	CryptoKeyStringValidator(
		Cipher cipher,
		QObject* parent = nullptr
	)
	: CryptoValidator(cipher, parent)
	{}
	Q_DISABLE_COPY(CryptoKeyStringValidator)

public:
	State validate(QString& input, int& pos) const override;
};

class CryptoHexStringValidator : public CryptoValidator
{
	Q_OBJECT

protected:
	unsigned int maxBlocks;

public:
	CryptoHexStringValidator(
		Cipher cipher,
		unsigned int maxBlocks = 0,
		QObject* parent = nullptr
	)
	: CryptoValidator(cipher, parent),
	  maxBlocks(maxBlocks)
	{}
	Q_DISABLE_COPY(CryptoHexStringValidator)

public slots:
	void setMaxBlocks(unsigned int max);

signals:
	void maxBlocksChanged(unsigned int maxBlocks);

public:
	State validate(QString& input, int& pos) const override;
};

#endif
