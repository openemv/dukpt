/**
 * @file validators.h
 * @brief Various validators for for QWidgets
 *
 * Copyright 2022-2023 Leon Lynch
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

#ifndef VALIDATORS_H
#define VALIDATORS_H

#include <QtGui/QValidator>

class DecStringValidator : public QValidator
{
	Q_OBJECT

protected:
	unsigned int minLength;
	unsigned int maxLength;

public:
	DecStringValidator(
		unsigned int minLength,
		unsigned int maxLength,
		QObject* parent = nullptr
	)
	: QValidator(parent),
	  minLength(minLength),
	  maxLength(maxLength)
	{}
	Q_DISABLE_COPY(DecStringValidator)

public slots:
	void setMinLength(unsigned int x);
	void setMaxLength(unsigned int x);

signals:
	void minLengthChanged(unsigned int x);
	void maxLengthChanged(unsigned int x);

public:
	State validate(QString& input, int& pos) const override;
};

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

public:
	State validate(QString& input, int& pos) const = 0;
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

class DukptKsnStringValidator : public CryptoValidator
{
	Q_OBJECT

public:
	DukptKsnStringValidator(Cipher cipher, QObject* parent = nullptr)
	: CryptoValidator(cipher, parent)
	{}
	Q_DISABLE_COPY(DukptKsnStringValidator)

public:
	State validate(QString& input, int& pos) const override;
};

class CryptoKbpkStringValidator : public HexStringValidator
{
	Q_OBJECT

public:
	enum FormatVersion {
		B,
		D,
		E,
	};
	Q_ENUM(FormatVersion)

protected:
	FormatVersion formatVersion;

public:
	CryptoKbpkStringValidator(FormatVersion formatVersion, QObject* parent = nullptr)
	: HexStringValidator(parent),
	  formatVersion(formatVersion)
	{}
	Q_DISABLE_COPY(CryptoKbpkStringValidator)

public slots:
	void setFormatVersion(FormatVersion fv);

signals:
	void formatVersionChanged(FormatVersion FormatVersion);

public:
	State validate(QString& input, int& pos) const override;
};

#endif
