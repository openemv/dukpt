/**
 * @file mainwindow.cpp
 * @brief Main window of DUKPT User Interface
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

#include "mainwindow.h"
#include "validators.h"

#include "dukpt_tdes.h"
#include "dukpt_aes.h"
#include "tr31.h"

MainWindow::MainWindow(QWidget* parent)
: QMainWindow(parent)
{
	// Setup validators
	keyValidator = new CryptoKeyStringValidator(CryptoValidator::TDES, this);
	keyValidator->setObjectName("keyValidator");
	pinValidator = new DecStringValidator(4, 12, this);
	pinValidator->setObjectName("pinValidator");
	panValidator = new DecStringValidator(12, 19, this);
	panValidator->setObjectName("panValidator");
	dataValidator = new CryptoHexStringValidator(CryptoValidator::TDES, 0, this);
	dataValidator->setObjectName("dataValidator");
	ivValidator = new CryptoHexStringValidator(CryptoValidator::TDES, 1, this);
	ivValidator->setObjectName("ivValidator");
	macValidator = new HexStringValidator(this);
	macValidator->setObjectName("macValidator");

	// Setup UI widgets
	setupUi(this);
	inputKeyEdit->setValidator(keyValidator);
	kbpkEdit->setValidator(keyValidator);
	pinEdit->setValidator(pinValidator);
	panEdit->setValidator(panValidator);
	dataEdit->setValidator(dataValidator);
	ivEdit->setValidator(ivValidator);
	macEdit->setValidator(macValidator);

	// Populate combo boxes

	modeComboBox->addItem("TDES", DUKPT_UI_MODE_TDES);
	modeComboBox->addItem("AES", DUKPT_UI_MODE_AES);

	inputKeyTypeComboBox->addItem("Base Derivation Key (BDK)", DUKPT_UI_INPUT_KEY_TYPE_BDK);
	inputKeyTypeComboBox->addItem("Initial Key (IK/IPEK)", DUKPT_UI_INPUT_KEY_TYPE_IK);

	pinActionComboBox->addItem("Encrypt PIN", DUKPT_UI_PIN_ACTION_ENCRYPT);
	pinActionComboBox->addItem("Decrypt PIN", DUKPT_UI_PIN_ACTION_DECRYPT);

	dataActionComboBox->addItem("Encrypt request", DUKPT_UI_DATA_ACTION_ENCRYPT_REQUEST);
	dataActionComboBox->addItem("Decrypt request", DUKPT_UI_DATA_ACTION_DECRYPT_REQUEST);
	dataActionComboBox->addItem("Encrypt response", DUKPT_UI_DATA_ACTION_ENCRYPT_RESPONSE);
	dataActionComboBox->addItem("Decrypt response", DUKPT_UI_DATA_ACTION_DECRYPT_RESPONSE);
}

MainWindow::dukpt_ui_mode_t MainWindow::getMode() const
{
	unsigned int data;

	data = modeComboBox->currentData().toUInt();
	switch (data) {
		case DUKPT_UI_MODE_TDES:
		case DUKPT_UI_MODE_AES:
			return static_cast<dukpt_ui_mode_t>(data);

		default:
			return DUKPT_UI_MODE_UNKNOWN;
	}
}

MainWindow::dukpt_ui_input_key_type_t MainWindow::getInputKeyType() const
{
	unsigned int data;

	data = inputKeyTypeComboBox->currentData().toUInt();
	switch (data) {
		case DUKPT_UI_INPUT_KEY_TYPE_BDK:
		case DUKPT_UI_INPUT_KEY_TYPE_IK:
			return static_cast<dukpt_ui_input_key_type_t>(data);

		default:
			return DUKPT_UI_INPUT_KEY_TYPE_UNKNOWN;
	}
}

MainWindow::dukpt_ui_derivation_action_t MainWindow::getDerivationAction() const
{
	unsigned int data;

	data = derivationActionComboBox->currentData().toUInt();
	switch (data) {
		case DUKPT_UI_DERIVATION_ACTION_IK:
		case DUKPT_UI_DERIVATION_ACTION_TXN:
		case DUKPT_UI_DERIVATION_ACTION_UPDATE:
			return static_cast<dukpt_ui_derivation_action_t>(data);

		default:
			return DUKPT_UI_DERIVATION_ACTION_UNKNOWN;
	}
}

void MainWindow::selectDerivationAction(dukpt_ui_derivation_action_t derivationAction)
{
	int index;

	index = derivationActionComboBox->findData(derivationAction);
	if (index != -1) {
		derivationActionComboBox->setCurrentIndex(index);
	} else {
		on_derivationActionComboBox_currentIndexChanged(derivationActionComboBox->currentIndex());
	}
}

void MainWindow::updateDerivationActions(dukpt_ui_mode_t mode, dukpt_ui_input_key_type_t inputKeyType)
{
	dukpt_ui_derivation_action_t derivationAction;

	// Remember current derivation action
	derivationAction = getDerivationAction();

	// Build derivation action list based on input key type
	derivationActionComboBox->clear();
	switch (inputKeyType) {
		case DUKPT_UI_INPUT_KEY_TYPE_BDK:
			derivationActionComboBox->addItem("Derive Initial Key (IK/IPEK)", DUKPT_UI_DERIVATION_ACTION_IK);
			// Intentional fallthrough; use [[fallthrough]] in future

		case DUKPT_UI_INPUT_KEY_TYPE_IK:
			derivationActionComboBox->addItem("Derive Transaction Key", DUKPT_UI_DERIVATION_ACTION_TXN);
			break;

		default:
			// Unknown input key type
			return;
	}

	if (mode == DUKPT_UI_MODE_AES) {
		derivationActionComboBox->addItem("Derive Update Key", DUKPT_UI_DERIVATION_ACTION_UPDATE);
	}

	// Restore current derivation action (if possible)
	selectDerivationAction(derivationAction);
}

MainWindow::dukpt_ui_key_type_t MainWindow::getDerivedKeyType() const
{
	unsigned int data;

	data = derivedKeyTypeComboBox->currentData().toUInt();
	switch (data) {
		case DUKPT_UI_KEY_TYPE_AES128:
		case DUKPT_UI_KEY_TYPE_AES192:
		case DUKPT_UI_KEY_TYPE_AES256:
			return static_cast<dukpt_ui_key_type_t>(data);

		default:
			return DUKPT_UI_KEY_TYPE_UNKNOWN;
	}
}

void MainWindow::selectDerivedKeyType(dukpt_ui_key_type_t derivedKeyType)
{
	int index;

	index = derivedKeyTypeComboBox->findData(derivedKeyType);
	if (index != -1) {
		derivedKeyTypeComboBox->setCurrentIndex(index);
	}
}

void MainWindow::updateDerivedKeyTypes(dukpt_ui_derivation_action_t derivationAction)
{
	dukpt_ui_key_type_t derivedKeyType;

	// Remember current derived key type
	derivedKeyType = getDerivedKeyType();

	// Build derived key type list based on derivation action
	derivedKeyTypeComboBox->clear();
	if (derivationAction == DUKPT_UI_DERIVATION_ACTION_UPDATE) {
		// TODO: only show options that are <= input key length
		derivedKeyTypeComboBox->addItem("AES 128-bit", DUKPT_UI_KEY_TYPE_AES128);
		derivedKeyTypeComboBox->addItem("AES 192-bit", DUKPT_UI_KEY_TYPE_AES192);
		derivedKeyTypeComboBox->addItem("AES 256-bit", DUKPT_UI_KEY_TYPE_AES256);
		derivedKeyTypeComboBox->setEnabled(true);

		// TODO: default to same as input key length

		// Restore current derived key type (if possible)
		selectDerivedKeyType(derivedKeyType);
	} else {
		// TODO: set to the same as the input key length
		derivedKeyTypeComboBox->setEnabled(false);
	}
}

MainWindow::dukpt_ui_key_type_t MainWindow::getEncryptDecryptKeyType() const
{
	unsigned int data;

	data = encryptDecryptKeyTypeComboBox->currentData().toUInt();
	switch (data) {
		case DUKPT_UI_KEY_TYPE_AES128:
		case DUKPT_UI_KEY_TYPE_AES192:
		case DUKPT_UI_KEY_TYPE_AES256:
			return static_cast<dukpt_ui_key_type_t>(data);

		default:
			return DUKPT_UI_KEY_TYPE_UNKNOWN;
	}
}

void MainWindow::selectEncryptDecryptKeyType(dukpt_ui_key_type_t encryptDecryptKeyType)
{
	int index;

	index = encryptDecryptKeyTypeComboBox->findData(encryptDecryptKeyType);
	if (index != -1) {
		encryptDecryptKeyTypeComboBox->setCurrentIndex(index);
	}
}

void MainWindow::updateEncryptDecryptKeyTypes(dukpt_ui_mode_t mode)
{
	dukpt_ui_key_type_t encryptDecryptKeyType;

	// Remember current encrypt/decrypt key type
	encryptDecryptKeyType = getEncryptDecryptKeyType();

	// Build encrypt/decrypt key type based on mode
	encryptDecryptKeyTypeComboBox->clear();
	if (mode == DUKPT_UI_MODE_TDES) {
		encryptDecryptKeyTypeComboBox->addItem("Double length TDES (128-bit)");
		encryptDecryptKeyTypeComboBox->setEnabled(false);
	} else if (mode == DUKPT_UI_MODE_AES) {
		// TODO: only show options that are <= input key length
		encryptDecryptKeyTypeComboBox->addItem("AES 128-bit", DUKPT_UI_KEY_TYPE_AES128);
		encryptDecryptKeyTypeComboBox->addItem("AES 192-bit", DUKPT_UI_KEY_TYPE_AES192);
		encryptDecryptKeyTypeComboBox->addItem("AES 256-bit", DUKPT_UI_KEY_TYPE_AES256);
		encryptDecryptKeyTypeComboBox->setEnabled(true);

		// TODO: default to same as input key length

		// Restore current encrypt/decrypt key type (if possible)
		selectEncryptDecryptKeyType(encryptDecryptKeyType);
	} else {
		// Unknown mode
		return;
	}
}

MainWindow::dukpt_ui_output_format_t MainWindow::getOutputFormat() const
{
	unsigned int data;

	data = outputFormatComboBox->currentData().toUInt();
	switch (data) {
		case DUKPT_UI_OUTPUT_FORMAT_HEX:
		case DUKPT_UI_OUTPUT_FORMAT_TR31_B:
		case DUKPT_UI_OUTPUT_FORMAT_TR31_D:
		case DUKPT_UI_OUTPUT_FORMAT_TR31_E:
			return static_cast<dukpt_ui_output_format_t>(data);

		default:
			return DUKPT_UI_OUTPUT_FORMAT_UNKNOWN;
	}
}

void MainWindow::selectOutputFormat(dukpt_ui_output_format_t outputFormat)
{
	int index;

	index = outputFormatComboBox->findData(outputFormat);
	if (index != -1) {
		outputFormatComboBox->setCurrentIndex(index);
	} else {
		on_outputFormatComboBox_currentIndexChanged(outputFormatComboBox->currentIndex());
	}
}

void MainWindow::updateOutputFormats(dukpt_ui_mode_t mode)
{
	dukpt_ui_output_format_t outputFormat;

	// Remember current output format
	outputFormat = getOutputFormat();

	// Build output format list based on mode
	outputFormatComboBox->clear();
	outputFormatComboBox->addItem("ASCII-HEX", DUKPT_UI_OUTPUT_FORMAT_HEX);
	if (mode == DUKPT_UI_MODE_TDES) {
		outputFormatComboBox->addItem("TR-31 format version B", DUKPT_UI_OUTPUT_FORMAT_TR31_B);
	} else if (mode == DUKPT_UI_MODE_AES) {
		outputFormatComboBox->addItem("TR-31 format version D", DUKPT_UI_OUTPUT_FORMAT_TR31_D);
		outputFormatComboBox->addItem("ISO 20038 format version E", DUKPT_UI_OUTPUT_FORMAT_TR31_E);
	} else {
		// Unknown mode
		outputFormatComboBox->clear();
		return;
	}

	// Restore current output format (if possible)
	selectOutputFormat(outputFormat);
}

MainWindow::dukpt_ui_pin_action_t MainWindow::getPinAction() const
{
	unsigned int data;

	data = pinActionComboBox->currentData().toUInt();
	switch (data) {
		case DUKPT_UI_PIN_ACTION_ENCRYPT:
		case DUKPT_UI_PIN_ACTION_DECRYPT:
			return static_cast<dukpt_ui_pin_action_t>(data);

		default:
			return DUKPT_UI_PIN_ACTION_UNKNOWN;
	}
}

MainWindow::dukpt_ui_data_action_t MainWindow::getDataAction() const
{
	unsigned int data;

	data = dataActionComboBox->currentData().toUInt();
	switch (data) {
		case DUKPT_UI_DATA_ACTION_ENCRYPT_REQUEST:
		case DUKPT_UI_DATA_ACTION_DECRYPT_REQUEST:
		case DUKPT_UI_DATA_ACTION_ENCRYPT_RESPONSE:
		case DUKPT_UI_DATA_ACTION_DECRYPT_RESPONSE:
			return static_cast<dukpt_ui_data_action_t>(data);

		default:
			return DUKPT_UI_DATA_ACTION_UNKNOWN;
	}
}

MainWindow::dukpt_ui_mac_action_t MainWindow::getMacAction() const
{
	unsigned int data;

	data = macActionComboBox->currentData().toUInt();
	switch (data) {
		case DUKPT_UI_MAC_ACTION_RETAIL_MAC:
		case DUKPT_UI_MAC_ACTION_AES128_CMAC:
		case DUKPT_UI_MAC_ACTION_AES192_CMAC:
		case DUKPT_UI_MAC_ACTION_AES256_CMAC:
		case DUKPT_UI_MAC_ACTION_HMAC128_SHA256:
		case DUKPT_UI_MAC_ACTION_HMAC192_SHA256:
		case DUKPT_UI_MAC_ACTION_HMAC256_SHA256:
			return static_cast<dukpt_ui_mac_action_t>(data);

		default:
			return DUKPT_UI_MAC_ACTION_UNKNOWN;
	}
}

void MainWindow::selectMacAction(dukpt_ui_mac_action_t macAction)
{
	int index;

	index = macActionComboBox->findData(macAction);
	if (index != -1) {
		macActionComboBox->setCurrentIndex(index);
	}
}

void MainWindow::updateMacActions(dukpt_ui_mode_t mode)
{
	dukpt_ui_mac_action_t macAction;

	// Remember current MAC action
	macAction = getMacAction();

	// Build MAC action list based on mode
	macActionComboBox->clear();
	if (mode == DUKPT_UI_MODE_TDES) {
		macActionComboBox->addItem("ANSI X9.19 Retail MAC", DUKPT_UI_MAC_ACTION_RETAIL_MAC);
		macActionComboBox->setEnabled(false);
	} else if (mode == DUKPT_UI_MODE_AES) {
		// TODO: only show options that are <= input key length
		macActionComboBox->addItem("AES 128-bit CMAC", DUKPT_UI_MAC_ACTION_AES128_CMAC);
		macActionComboBox->addItem("AES 192-bit CMAC", DUKPT_UI_MAC_ACTION_AES192_CMAC);
		macActionComboBox->addItem("AES 256-bit CMAC", DUKPT_UI_MAC_ACTION_AES256_CMAC);
		macActionComboBox->addItem("HMAC-SHA256 (128-bit key)", DUKPT_UI_MAC_ACTION_HMAC128_SHA256);
		macActionComboBox->addItem("HMAC-SHA256 (192-bit key)", DUKPT_UI_MAC_ACTION_HMAC192_SHA256);
		macActionComboBox->addItem("HMAC-SHA256 (256-bit key)", DUKPT_UI_MAC_ACTION_HMAC256_SHA256);
		macActionComboBox->setEnabled(true);

		// TODO: default to same as input key length

		// Restore current MAC action (if possible)
		selectMacAction(macAction);
	} else {
		// Unknown mode
		return;
	}
}

void MainWindow::updateValidationStyleSheet(QLineEdit* edit)
{
	if (edit->hasAcceptableInput()) {
		edit->setStyleSheet("");
	} else {
		edit->setStyleSheet("color: red");
	}
}

void MainWindow::on_modeComboBox_currentIndexChanged(int index)
{
	dukpt_ui_mode_t mode;
	CryptoValidator::Cipher cipher;

	// Current state
	mode = getMode();

	// Update validators
	if (mode == DUKPT_UI_MODE_TDES) {
		cipher = CryptoValidator::TDES;
	} else if (mode == DUKPT_UI_MODE_AES) {
		cipher = CryptoValidator::AES;
	} else {
		// Unknown mode
		return;
	}
	keyValidator->setCipher(cipher);
	dataValidator->setCipher(cipher);
	ivValidator->setCipher(cipher);

	// Update combo boxes
	on_inputKeyTypeComboBox_currentIndexChanged(inputKeyTypeComboBox->currentIndex());
	updateOutputFormats(mode);
	updateEncryptDecryptKeyTypes(mode);
	updateMacActions(mode);
}

void MainWindow::on_inputKeyTypeComboBox_currentIndexChanged(int index)
{
	dukpt_ui_mode_t mode;
	dukpt_ui_input_key_type_t inputKeyType;

	// Current state
	mode = getMode();
	inputKeyType = getInputKeyType();

	updateDerivationActions(mode, inputKeyType);
}

void MainWindow::on_derivationActionComboBox_currentIndexChanged(int index)
{
	dukpt_ui_derivation_action_t derivationAction;

	// Current state
	derivationAction = getDerivationAction();

	updateDerivedKeyTypes(derivationAction);
}

void MainWindow::on_outputFormatComboBox_currentIndexChanged(int index)
{
	unsigned int outputFormat;

	outputFormat = outputFormatComboBox->itemData(index).toUInt();

	// Enable Key Block Protection Key input based on output format
	if (outputFormat > DUKPT_UI_OUTPUT_FORMAT_HEX) {
		kbpkEdit->setEnabled(true);
	} else {
		kbpkEdit->clear();
		kbpkEdit->setEnabled(false);
	}
}

void MainWindow::on_keyDerivationPushButton_clicked()
{
	// TODO: implement
}

void MainWindow::on_encryptDecryptPushButton_clicked()
{
	// TODO: implement
}

void MainWindow::on_macPushButton_clicked()
{
	// TODO: implement
}
