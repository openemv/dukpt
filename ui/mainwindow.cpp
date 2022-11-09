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
#include "dukpt_ui_config.h"

#include "dukpt_tdes.h"
#include "dukpt_aes.h"
#include "tr31.h"

#include <QtCore/QByteArray>
#include <QtCore/QSettings>
#include <QtWidgets/QScrollBar>

#include <cstddef>

MainWindow::MainWindow(QWidget* parent)
: QMainWindow(parent)
{
	// Setup validators
	keyValidator = new CryptoKeyStringValidator(CryptoValidator::TDES, this);
	keyValidator->setObjectName("keyValidator");
	ksnValidator = new DukptKsnStringValidator(CryptoValidator::TDES, this);
	ksnValidator->setObjectName("ksnValidator");
	blockValidator = new CryptoHexStringValidator(CryptoValidator::TDES, 1, this);
	blockValidator->setObjectName("blockValidator");
	pinValidator = new DecStringValidator(4, 12, this);
	pinValidator->setObjectName("pinValidator");
	panValidator = new DecStringValidator(12, 19, this);
	panValidator->setObjectName("panValidator");
	dataValidator = new CryptoHexStringValidator(CryptoValidator::TDES, 0, this);
	dataValidator->setObjectName("dataValidator");
	macValidator = new HexStringValidator(this);
	macValidator->setObjectName("macValidator");

	// Setup UI widgets
	setupUi(this);
	setWindowTitle(windowTitle().append(QString(" (" DUKPT_UI_VERSION_STRING ")")));
	inputKeyEdit->setValidator(keyValidator);
	ksnEdit->setValidator(ksnValidator);
	kbpkEdit->setValidator(keyValidator);
	pinEdit->setValidator(pinValidator);
	panEdit->setValidator(panValidator);
	// dataEdit->setValidator(dataValidator); // see updateValidationStyleSheet()
	ivEdit->setValidator(blockValidator);
	// macEdit->setValidator(macValidator); // see updateValidationStyleSheet()

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

	// Display copyright, license and disclaimer notice
	outputText->appendHtml(
		"Copyright &copy; 2021, 2022 <a href='https://github.com/leonlynch'>Leon Lynch</a><br/><br/>"
		"<a href='https://github.com/openemv/dukpt'>This program</a> is free software; you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License as published by the Free Software Foundation.<br/>"
		"<a href='https://github.com/openemv/dukpt'>This program</a> is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.<br/>"
		"See <a href='https://raw.githubusercontent.com/openemv/dukpt/master/LICENSE'>LICENSE</a> file for more details.<br/><br/>"
		"<a href='https://github.com/openemv/dukpt'>This program</a> uses various libraries including:<br/>"
		"- <a href='https://github.com/Mbed-TLS/mbedtls'>MbedTLS</a> (licensed under <a href='http://www.apache.org/licenses/LICENSE-2.0'>Apache License v2</a>)<br/>"
		"- <a href='https://github.com/openemv/tr31'>tr31</a> (licensed under <a href='https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html'>LGPL v2.1</a>)<br/>"
		"- <a href='https://www.qt.io'>Qt</a> (licensed under <a href='https://www.gnu.org/licenses/lgpl-3.0.html'>LGPL v3</a>)<br/>"
		"<br/>"
	);

	// Load previous UI values
	loadSettings();
}

void MainWindow::closeEvent(QCloseEvent* event)
{
	// Save current UI values
	saveSettings();
}

void MainWindow::loadSettings()
{
	QSettings settings;
	QList<QComboBox*> combo_box_list = findChildren<QComboBox*>();
	QList<QCheckBox*> check_box_list = findChildren<QCheckBox*>();
	QList<QLineEdit*> line_edit_list = findChildren<QLineEdit*>();
	QList<QPlainTextEdit*> plain_text_edit_list = findChildren<QPlainTextEdit*>();

	settings.beginGroup("inputs");

	// Iterate over inputs and load from settings
	for (auto combo_box : combo_box_list) {
		int index;

		if (!settings.contains(combo_box->objectName())) {
			// No value to load
			continue;
		}

		index = combo_box->findData(settings.value(combo_box->objectName()).toUInt());
		if (index != -1) {
			combo_box->setCurrentIndex(index);
		}
	}
	for (auto check_box : check_box_list) {
		Qt::CheckState state;

		if (!settings.contains(check_box->objectName())) {
			// No value to load
			continue;
		}

		state = static_cast<Qt::CheckState>(settings.value(check_box->objectName()).toUInt());
		check_box->setCheckState(state);
	}
	for (auto line_edit : line_edit_list) {
		if (!settings.contains(line_edit->objectName())) {
			// No value to load
			continue;
		}
		line_edit->setText(settings.value(line_edit->objectName()).toString());
	}
	for (auto plain_text_edit : plain_text_edit_list) {
		if (!settings.contains(plain_text_edit->objectName())) {
			// No value to load
			continue;
		}
		plain_text_edit->setPlainText(settings.value(plain_text_edit->objectName()).toString());
	}
}

void MainWindow::saveSettings() const
{
	QSettings settings;
	QList<QComboBox*> combo_box_list = findChildren<QComboBox*>();
	QList<QCheckBox*> check_box_list = findChildren<QCheckBox*>();
	QList<QLineEdit*> line_edit_list = findChildren<QLineEdit*>();
	QList<QPlainTextEdit*> plain_text_edit_list = findChildren<QPlainTextEdit*>();

	// Start with blank settings
	settings.clear();
	settings.beginGroup("inputs");

	// Iterate over inputs and save to settings
	for (auto combo_box : combo_box_list) {
		if (combo_box->currentData().isNull()) {
			// Don't save empty values
			continue;
		}

		settings.setValue(combo_box->objectName(), combo_box->currentData());
	}
	for (auto line_edit : line_edit_list) {
		if (line_edit->text().isEmpty()) {
			// Don't save empty values
			continue;
		}

		settings.setValue(line_edit->objectName(), line_edit->text());
	}
	for (auto check_box : check_box_list) {
		if (!check_box->isChecked()) {
			// Don't save unchecked checkboxes
			continue;
		}

		settings.setValue(check_box->objectName(), check_box->checkState());
	}
	for (auto plain_text_edit : plain_text_edit_list) {
		if (plain_text_edit->objectName() == "outputText") {
			// Don't save output text
			continue;
		}
		if (plain_text_edit->toPlainText().isEmpty()) {
			// Don't save empty values
			continue;
		}

		settings.setValue(plain_text_edit->objectName(), plain_text_edit->toPlainText());
	}

	settings.sync();
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

MainWindow::dukpt_ui_key_type_t MainWindow::getMacKeyType() const
{
	unsigned int data;

	data = macKeyTypeComboBox->currentData().toUInt();
	switch (data) {
		case DUKPT_UI_KEY_TYPE_AES128:
		case DUKPT_UI_KEY_TYPE_AES192:
		case DUKPT_UI_KEY_TYPE_AES256:
		case DUKPT_UI_KEY_TYPE_HMAC128:
		case DUKPT_UI_KEY_TYPE_HMAC192:
		case DUKPT_UI_KEY_TYPE_HMAC256:
			return static_cast<dukpt_ui_key_type_t>(data);

		default:
			return DUKPT_UI_KEY_TYPE_UNKNOWN;
	}
}

void MainWindow::selectMacKeyType(dukpt_ui_key_type_t macKeyType)
{
	int index;

	index = macKeyTypeComboBox->findData(macKeyType);
	if (index != -1) {
		macKeyTypeComboBox->setCurrentIndex(index);
	}
}

void MainWindow::updateMacKeyTypes(dukpt_ui_mode_t mode)
{
	dukpt_ui_key_type_t macKeyType;

	// Remember current MAC key type
	macKeyType = getMacKeyType();

	// Build MAC key type based on mode
	macKeyTypeComboBox->clear();
	if (mode == DUKPT_UI_MODE_TDES) {
		macKeyTypeComboBox->addItem("ANSI X9.19 Retail MAC (128-bit)");
		macKeyTypeComboBox->setEnabled(false);
	} else if (mode == DUKPT_UI_MODE_AES) {
		// TODO: only show options that are <= input key length
		macKeyTypeComboBox->addItem("AES 128-bit", DUKPT_UI_KEY_TYPE_AES128);
		macKeyTypeComboBox->addItem("AES 192-bit", DUKPT_UI_KEY_TYPE_AES192);
		macKeyTypeComboBox->addItem("AES 256-bit", DUKPT_UI_KEY_TYPE_AES256);
		macKeyTypeComboBox->addItem("HMAC 128-bit", DUKPT_UI_KEY_TYPE_HMAC128);
		macKeyTypeComboBox->addItem("HMAC 192-bit", DUKPT_UI_KEY_TYPE_HMAC192);
		macKeyTypeComboBox->addItem("HMAC 256-bit", DUKPT_UI_KEY_TYPE_HMAC256);
		macKeyTypeComboBox->setEnabled(true);

		// TODO: default to same as input key length

		// Restore current MAC key type (if possible)
		selectMacKeyType(macKeyType);
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
	dukpt_ui_derivation_action_t derivationAction;

	// Remember current output format
	outputFormat = getOutputFormat();

	// Build output format list based on mode
	outputFormatComboBox->clear();
	outputFormatComboBox->addItem("ASCII-HEX", DUKPT_UI_OUTPUT_FORMAT_HEX);
	derivationAction = getDerivationAction();
	if (derivationAction == DUKPT_UI_DERIVATION_ACTION_IK) {
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
		case DUKPT_UI_MAC_ACTION_RETAIL_MAC_REQUEST:
		case DUKPT_UI_MAC_ACTION_RETAIL_MAC_RESPONSE:
		case DUKPT_UI_MAC_ACTION_CMAC_REQUEST:
		case DUKPT_UI_MAC_ACTION_CMAC_RESPONSE:
		case DUKPT_UI_MAC_ACTION_HMAC_SHA256_REQUEST:
		case DUKPT_UI_MAC_ACTION_HMAC_SHA256_RESPONSE:
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
		macActionComboBox->addItem("MAC request", DUKPT_UI_MAC_ACTION_RETAIL_MAC_REQUEST);
		macActionComboBox->addItem("MAC response", DUKPT_UI_MAC_ACTION_RETAIL_MAC_RESPONSE);
	} else if (mode == DUKPT_UI_MODE_AES) {
		macActionComboBox->addItem("CMAC request", DUKPT_UI_MAC_ACTION_CMAC_REQUEST);
		macActionComboBox->addItem("CMAC response", DUKPT_UI_MAC_ACTION_CMAC_RESPONSE);
		macActionComboBox->addItem("HMAC-SHA256 request", DUKPT_UI_MAC_ACTION_HMAC_SHA256_REQUEST);
		macActionComboBox->addItem("HMAC-SHA256 response", DUKPT_UI_MAC_ACTION_HMAC_SHA256_RESPONSE);

		// Restore current MAC action (if possible)
		selectMacAction(macAction);
	} else {
		// Unknown mode
		return;
	}
}

void MainWindow::log(dukpt_ui_log_level_t level, QString&& str)
{
	switch (level) {
		case DUKPT_LOG_INFO:
			outputText->appendPlainText(str);
			break;

		case DUKPT_LOG_SUCCESS:
			outputText->appendHtml(QString("<span style='color: green'>") + str + QString("</span><p></p>"));
			break;

		case DUKPT_LOG_FAILURE:
			outputText->appendHtml(QString("<span style='color: red'>") + str + QString("</span><p></p>"));
			break;

		case DUKPT_LOG_ERROR:
		default:
			outputText->appendHtml(QString("<span style='color: red'>") + str + QString("</span>"));
			break;
	}

	outputText->verticalScrollBar()->setValue(outputText->verticalScrollBar()->maximum());
}

void MainWindow::logVector(QString&& str, const std::vector<std::uint8_t>& v)
{
	// Abuse QByteArray to convert binary data to ASCII-HEX
	QByteArray data(reinterpret_cast<const char*>(v.data()), v.size());
	str += data.toHex().toUpper();
	log(DUKPT_LOG_INFO, qUtf8Printable(str));
}

void MainWindow::logDigitVector(QString&& str, std::vector<std::uint8_t> v)
{
	for (auto&& digit : v) {
		if (digit <= 9) {
			str += '0' + digit;
		} else {
			str += '?';
		}
	}
	log(DUKPT_LOG_INFO, qUtf8Printable(str));
}

void MainWindow::updateValidationStyleSheet(QLineEdit* edit)
{
	if (edit->hasAcceptableInput()) {
		edit->setStyleSheet("");
	} else {
		edit->setStyleSheet("color: red");
	}
}

void MainWindow::updateValidationStyleSheet(const QValidator* validator, QPlainTextEdit* edit)
{
	QString str;
	int pos;

	str = edit->toPlainText();
	pos = 0;
	if (validator->validate(str, pos) == QValidator::Acceptable) {
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
	ksnValidator->setCipher(cipher);
	blockValidator->setCipher(cipher);
	dataValidator->setCipher(cipher);

	// Update combo boxes
	on_inputKeyTypeComboBox_currentIndexChanged(inputKeyTypeComboBox->currentIndex());
	updateOutputFormats(mode);
	updateEncryptDecryptKeyTypes(mode);
	updateMacKeyTypes(mode);
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
	dukpt_ui_mode_t mode;
	dukpt_ui_derivation_action_t derivationAction;

	// Current state
	mode = getMode();
	derivationAction = getDerivationAction();

	updateDerivedKeyTypes(derivationAction);
	updateOutputFormats(mode);
}

void MainWindow::on_outputFormatComboBox_currentIndexChanged(int index)
{
	unsigned int outputFormat;

	outputFormat = outputFormatComboBox->itemData(index).toUInt();

	// Enable Key Block Protection Key input based on output format
	if (outputFormat > DUKPT_UI_OUTPUT_FORMAT_HEX) {
		kbpkEdit->setEnabled(true);
		tr31KsnCheckBox->setEnabled(true);
		tr31KcCheckBox->setEnabled(true);
		tr31KpCheckBox->setEnabled(true);
	} else {
		kbpkEdit->clear();
		kbpkEdit->setEnabled(false);
		tr31KsnCheckBox->setCheckState(Qt::Unchecked);
		tr31KsnCheckBox->setEnabled(false);
		tr31KcCheckBox->setCheckState(Qt::Unchecked);
		tr31KcCheckBox->setEnabled(false);
		tr31KpCheckBox->setCheckState(Qt::Unchecked);
		tr31KpCheckBox->setEnabled(false);
	}
}

void MainWindow::on_pinActionComboBox_currentIndexChanged(int index)
{
	dukpt_ui_pin_action_t action;

	// Current state
	action = getPinAction();

	switch (action) {
		case DUKPT_UI_PIN_ACTION_ENCRYPT:
			pinEdit->setValidator(pinValidator);
			break;

		case DUKPT_UI_PIN_ACTION_DECRYPT:
			pinEdit->setValidator(blockValidator);
			break;

		default:
			// Unknown action
			return;
	}

	on_pinEdit_textChanged(pinEdit->text());
}

static std::vector<std::uint8_t> HexStringToVector(const QString& s)
{
	QByteArray data;
	data = QByteArray::fromHex(s.toUtf8());
	return std::vector<std::uint8_t>(data.constData(), data.constData() + data.size());
}

static std::vector<std::uint8_t> PinStringToVector(const QString& s)
{
	QByteArray data;
	data = s.toUtf8();
	for (auto&& digit : data) {
		digit -= '0';
	}
	return std::vector<std::uint8_t>(data.constData(), data.constData() + data.size());
}

static std::vector<std::uint8_t> PanStringToVector(QString pan)
{
	if (pan.length() % 2 == 1) {
		// Pad uneven number of PAN digits with trailing 'F'
		pan += "F";
	}

	return HexStringToVector(pan);
}

void MainWindow::on_ksnAdvancePushButton_clicked()
{
	int r;
	std::vector<std::uint8_t> prevKsn;

	// Current state
	mode = getMode();
	ksn = HexStringToVector(ksnEdit->text());
	prevKsn = ksn;

	// Attempt to advance KSN
	r = advanceKSN();
	if (r < 0) {
		logFailure("Invalid KSN");
		return;
	}
	if (r > 0) {
		logFailure("KSN exhausted");
		return;
	}

	// Convert KSN back to ASCII-HEX
	QByteArray ksnByteArray(reinterpret_cast<const char*>(ksn.data()), ksn.size());
	ksnEdit->setText(ksnByteArray.toHex().toUpper());

	logVector("Prev KSN: ", prevKsn);
	logVector("Next KSN: ", ksn);
	logSuccess("KSN advance successful");
}

void MainWindow::on_keyDerivationPushButton_clicked()
{
	// Current state
	mode = getMode();
	inputKeyType = getInputKeyType();
	inputKey = HexStringToVector(inputKeyEdit->text());
	ksn = HexStringToVector(ksnEdit->text());
	derivationAction = getDerivationAction();
	derivedKeyType = getDerivedKeyType();
	outputFormat = getOutputFormat();
	kbpk = HexStringToVector(kbpkEdit->text());
	tr31WithKsn = tr31KsnCheckBox->isChecked();
	tr31WithKc = tr31KcCheckBox->isChecked();
	tr31WithKp = tr31KpCheckBox->isChecked();

	if (mode == DUKPT_UI_MODE_TDES) {
		logInfo("TDES mode");
		if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_BDK) {
			logVector("BDK: ", inputKey);
		} else if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_IK) {
			logVector("IK: ", inputKey);
		}
		logVector("KSN: ", ksn);

		if (derivationAction == DUKPT_UI_DERIVATION_ACTION_IK) {
			std::vector<std::uint8_t> ik;

			ik = prepareTdesInitialKey(false);
			if (ik.empty()) {
				logFailure("Action failed");
				return;
			}

			if (outputFormat == DUKPT_UI_OUTPUT_FORMAT_TR31_B) {
				QString keyBlock = outputTr31InitialKey(ik);
				if (keyBlock.isEmpty()) {
					logFailure("Action failed");
					return;
				}
				keyBlock.prepend("TR-31: ");
				logInfo(std::move(keyBlock));
			} else {
				logVector("IK: ", ik);
			}

			logSuccess("Key derivation successful");
			return;
		}

		if (derivationAction == DUKPT_UI_DERIVATION_ACTION_TXN) {
			std::vector<std::uint8_t> txnKey;

			txnKey = prepareTdesTxnKey();
			if (txnKey.empty()) {
				logFailure("Action failed");
				return;
			}

			logVector("TXN: ", txnKey);
			logSuccess("Key derivation successful");
			return;
		}

		logFailure("Unknown derivation action");
		return;

	} else if (mode == DUKPT_UI_MODE_AES) {
		logInfo("AES mode");
		if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_BDK) {
			logVector("BDK: ", inputKey);
		} else if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_IK) {
			logVector("IK: ", inputKey);
		}
		logVector("KSN: ", ksn);

		if (derivationAction == DUKPT_UI_DERIVATION_ACTION_IK) {
			std::vector<std::uint8_t> ik;

			ik = prepareAesInitialKey(false);
			if (ik.empty()) {
				logFailure("Action failed");
				return;
			}

			if (outputFormat == DUKPT_UI_OUTPUT_FORMAT_TR31_D ||
				outputFormat == DUKPT_UI_OUTPUT_FORMAT_TR31_E
			) {
				QString keyBlock = outputTr31InitialKey(ik);
				if (keyBlock.isEmpty()) {
					logFailure("Action failed");
					return;
				}
				keyBlock.prepend("TR-31: ");
				logInfo(std::move(keyBlock));
			} else {
				logVector("IK: ", ik);
			}

			logSuccess("Key derivation successful");
			return;
		}

		if (derivationAction == DUKPT_UI_DERIVATION_ACTION_TXN) {
			std::vector<std::uint8_t> txnKey;

			txnKey = prepareAesTxnKey();
			if (txnKey.empty()) {
				logFailure("Action failed");
				return;
			}

			logVector("TXN: ", txnKey);
			logSuccess("Key derivation successful");
			return;
		}

		if (derivationAction == DUKPT_UI_DERIVATION_ACTION_UPDATE) {
			std::vector<std::uint8_t> updateKey;

			updateKey = prepareAesUpdateKey();
			if (updateKey.empty()) {
				logFailure("Action failed");
				return;
			}

			logVector("Update key: ", updateKey);
			logSuccess("Key derivation successful");
			return;
		}

		logFailure("Unknown derivation action");
		return;

	} else {
		logFailure("Unknown mode");
		return;
	}

	logFailure("Unimplemented");
}

void MainWindow::on_encryptDecryptPushButton_clicked()
{
	std::vector<std::uint8_t> txnKey;

	// Current state
	mode = getMode();
	inputKeyType = getInputKeyType();
	inputKey = HexStringToVector(inputKeyEdit->text());
	ksn = HexStringToVector(ksnEdit->text());
	encryptDecryptKeyType = getEncryptDecryptKeyType();
	pinAction = getPinAction();
	pan = PanStringToVector(panEdit->text());
	dataAction = getDataAction();
	encDecData = HexStringToVector(dataEdit->toPlainText());
	iv = HexStringToVector(ivEdit->text());

	// Derive transaction key
	if (mode == DUKPT_UI_MODE_TDES) {
		logInfo("TDES mode");
		if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_BDK) {
			logVector("BDK: ", inputKey);
		} else if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_IK) {
			logVector("IK: ", inputKey);
		}
		logVector("KSN: ", ksn);

		txnKey = prepareTdesTxnKey();
		if (txnKey.empty()) {
			logFailure("Action failed");
			return;
		}

	} else if (mode == DUKPT_UI_MODE_AES) {
		logInfo("AES mode");
		if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_BDK) {
			logVector("BDK: ", inputKey);
		} else if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_IK) {
			logVector("IK: ", inputKey);
		}
		logVector("KSN: ", ksn);

		txnKey = prepareAesTxnKey();
		if (txnKey.empty()) {
			logFailure("Action failed");
			return;
		}

	} else {
		logFailure("Unknown mode");
		return;
	}

	// Perform PIN action
	if (pinAction == DUKPT_UI_PIN_ACTION_ENCRYPT &&
		!pinEdit->text().trimmed().isEmpty() &&
		!pan.empty()
	) {
		std::vector<std::uint8_t> pin;
		std::vector<std::uint8_t> encryptedPin;

		pin = PinStringToVector(pinEdit->text());
		logDigitVector("PIN: ", pin);
		logVector("PAN: ", pan);

		encryptedPin = encryptPin(txnKey, pin);
		if (encryptedPin.empty()) {
			logFailure("Action failed");
			return;
		}
		logVector("Encrypted PIN: ", encryptedPin);
		logSuccess("PIN encryption successful");

	} else if (pinAction == DUKPT_UI_PIN_ACTION_DECRYPT &&
		!pinEdit->text().trimmed().isEmpty() &&
		!pan.empty()
	) {
		std::vector<std::uint8_t> encryptedPin;
		std::vector<std::uint8_t> pin;

		encryptedPin = HexStringToVector(pinEdit->text());
		logVector("PAN: ", pan);

		pin = decryptPin(txnKey, encryptedPin);
		if (pin.empty()) {
			logFailure("Action failed");
			return;
		}
		logDigitVector("Decrypted PIN: ", pin);
		logSuccess("PIN decryption successful");

	} else {
		logInfo("Skipping PIN action");
	}

	if (!encDecData.empty()) {
		std::vector<std::uint8_t> outputData;

		if (!iv.empty()) {
			logVector("IV: ", iv);
		}

		// Perform data action
		switch (dataAction) {
			case DUKPT_UI_DATA_ACTION_ENCRYPT_REQUEST:
				outputData = encryptRequest(txnKey);
				if (outputData.empty()) {
					logFailure("Action failed");
					return;
				}

				logVector("Encrypted request: ", outputData);
				logSuccess("Request encryption successful");
				return;

			case DUKPT_UI_DATA_ACTION_DECRYPT_REQUEST:
				outputData = decryptRequest(txnKey);
				if (outputData.empty()) {
					logFailure("Action failed");
					return;
				}

				logVector("Decrypted request: ", outputData);
				logSuccess("Request decryption successful");
				return;

			case DUKPT_UI_DATA_ACTION_ENCRYPT_RESPONSE:
				outputData = encryptResponse(txnKey);
				if (outputData.empty()) {
					logFailure("Action failed");
					return;
				}

				logVector("Encrypted response: ", outputData);
				logSuccess("Response encryption successful");
				return;

			case DUKPT_UI_DATA_ACTION_DECRYPT_RESPONSE:
				outputData = decryptResponse(txnKey);
				if (outputData.empty()) {
					logFailure("Action failed");
					return;
				}

				logVector("Decrypted response: ", outputData);
				logSuccess("Response decryption successful");
				return;

			default:
				logFailure("Invalid data action");
				return;
		}
	}
}

void MainWindow::on_macPushButton_clicked()
{
	std::vector<std::uint8_t> txnKey;
	std::vector<std::uint8_t> output;

	// Current state
	mode = getMode();
	inputKeyType = getInputKeyType();
	inputKey = HexStringToVector(inputKeyEdit->text());
	ksn = HexStringToVector(ksnEdit->text());
	macKeyType = getMacKeyType();
	macAction = getMacAction();
	macData = HexStringToVector(macEdit->toPlainText());

	// Derive transaction key
	if (mode == DUKPT_UI_MODE_TDES) {
		logInfo("TDES mode");
		if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_BDK) {
			logVector("BDK: ", inputKey);
		} else if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_IK) {
			logVector("IK: ", inputKey);
		}
		logVector("KSN: ", ksn);

		txnKey = prepareTdesTxnKey();
		if (txnKey.empty()) {
			logFailure("Action failed");
			return;
		}

		switch (macAction) {
			case DUKPT_UI_MAC_ACTION_RETAIL_MAC_REQUEST:
				output = macRequest(txnKey);
				if (output.empty()) {
					logFailure("Action failed");
					return;
				}

				logVector("Request MAC: ", output);
				logSuccess("Request MAC successful");
				return;

			case DUKPT_UI_MAC_ACTION_RETAIL_MAC_RESPONSE:
				output = macResponse(txnKey);
				if (output.empty()) {
					logFailure("Action failed");
					return;
				}

				logVector("Response MAC: ", output);
				logSuccess("Response MAC successful");
				return;

			default:
				logFailure("Invalid MAC action");
				return;
		}

	} else if (mode == DUKPT_UI_MODE_AES) {
		logInfo("AES mode");
		if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_BDK) {
			logVector("BDK: ", inputKey);
		} else if (inputKeyType == DUKPT_UI_INPUT_KEY_TYPE_IK) {
			logVector("IK: ", inputKey);
		}
		logVector("KSN: ", ksn);

		txnKey = prepareAesTxnKey();
		if (txnKey.empty()) {
			logFailure("Action failed");
			return;
		}

		switch (macAction) {
			case DUKPT_UI_MAC_ACTION_CMAC_REQUEST:
				output = cmacRequest(txnKey);
				if (output.empty()) {
					logFailure("Action failed");
					return;
				}

				logVector("Request CMAC: ", output);
				logSuccess("Request CMAC successful");
				return;

			case DUKPT_UI_MAC_ACTION_CMAC_RESPONSE:
				output = cmacResponse(txnKey);
				if (output.empty()) {
					logFailure("Action failed");
					return;
				}

				logVector("Response CMAC: ", output);
				logSuccess("Response CMAC successful");
				return;

			case DUKPT_UI_MAC_ACTION_HMAC_SHA256_REQUEST:
				output = hmacRequest(txnKey);
				if (output.empty()) {
					logFailure("Action failed");
					return;
				}

				logVector("Request HMAC-SHA256: ", output);
				logSuccess("Request HMAC-SHA256 successful");
				return;

			case DUKPT_UI_MAC_ACTION_HMAC_SHA256_RESPONSE:
				output = hmacResponse(txnKey);
				if (output.empty()) {
					logFailure("Action failed");
					return;
				}

				logVector("Response HMAC-SHA256: ", output);
				logSuccess("Response HMAC-SHA256 successful");
				return;

			default:
				logFailure("Invalid MAC action");
				return;
		}

	} else {
		logFailure("Unknown mode");
		return;
	}
}

int MainWindow::advanceKSN()
{
	if (mode == DUKPT_UI_MODE_TDES) {
		// Validate KSN length
		if (ksn.size() != DUKPT_TDES_KSN_LEN - 2 &&
			ksn.size() != DUKPT_TDES_KSN_LEN
		) {
			logError(QString::asprintf("TDES: KSN must be either %u (for IKSN) or %u (for full KSN) bytes (thus %u or %u hex digits)\n",
				DUKPT_TDES_KSN_LEN - 2, DUKPT_TDES_KSN_LEN,
				(DUKPT_TDES_KSN_LEN - 2) * 2, DUKPT_TDES_KSN_LEN * 2
			));
			return -1;
		}

		ksn.resize(DUKPT_TDES_KSN_LEN);
		return dukpt_tdes_ksn_advance(ksn.data());

	} else if (mode == DUKPT_UI_MODE_AES) {
		// Validate KSN length
		if (ksn.size() != DUKPT_AES_IK_ID_LEN &&
			ksn.size() != DUKPT_AES_KSN_LEN
		) {
			logError(QString::asprintf("AES: KSN must be either %u (for IK ID) or %u (for full KSN) bytes (thus %u or %u hex digits)\n",
				DUKPT_AES_IK_ID_LEN, DUKPT_AES_KSN_LEN,
				DUKPT_AES_IK_ID_LEN * 2, DUKPT_AES_KSN_LEN * 2
			));
			return {};
		}

		ksn.resize(DUKPT_AES_KSN_LEN);
		return dukpt_aes_ksn_advance(ksn.data());

	} else {
		logFailure("Unknown mode");
		return -1;
	}
}

std::vector<std::uint8_t> MainWindow::prepareTdesInitialKey(bool full_ksn)
{
	int r;
	std::vector<std::uint8_t> ik;

	if (full_ksn) {
		// Validate KSN length
		if (ksn.size() != DUKPT_TDES_KSN_LEN) {
			logError(QString::asprintf("TDES: KSN must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KSN_LEN, DUKPT_TDES_KSN_LEN * 2));
			return {};
		}
	} else {
		// Validate KSN length
		if (ksn.size() != DUKPT_TDES_KSN_LEN - 2 &&
			ksn.size() != DUKPT_TDES_KSN_LEN
		) {
			logError(QString::asprintf("TDES: KSN must be either %u (for IKSN) or %u (for full KSN) bytes (thus %u or %u hex digits)\n",
				DUKPT_TDES_KSN_LEN - 2, DUKPT_TDES_KSN_LEN,
				(DUKPT_TDES_KSN_LEN - 2) * 2, DUKPT_TDES_KSN_LEN * 2
			));
			return {};
		}
	}

	switch (inputKeyType) {
		case DUKPT_UI_INPUT_KEY_TYPE_BDK:
			// Validate BDK length
			if (inputKey.size() != DUKPT_TDES_KEY_LEN) {
				logError(QString::asprintf("TDES: BDK must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KEY_LEN, DUKPT_TDES_KEY_LEN * 2));
				return {};
			}

			// Derive initial key
			ik.resize(DUKPT_TDES_KEY_LEN);
			r = dukpt_tdes_derive_ik(inputKey.data(), ksn.data(), ik.data());
			if (r) {
				logError(QString::asprintf("dukpt_tdes_derive_ik() failed; r=%d\n", r));
				return {};
			}
			return ik;

		case DUKPT_UI_INPUT_KEY_TYPE_IK:
			// Validate IK length
			if (inputKey.size() != DUKPT_TDES_KEY_LEN) {
				logError(QString::asprintf("TDES: IK/IPEK must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KEY_LEN, DUKPT_TDES_KEY_LEN * 2));
				return {};
			}
			return inputKey;

		default:
			logError("Unknown input key type");
			return {};
	}
}

std::vector<std::uint8_t> MainWindow::prepareTdesTxnKey()
{
	int r;
	std::vector<std::uint8_t> ik;
	std::vector<std::uint8_t> txnKey;

	ik = prepareTdesInitialKey(true);
	if (ik.empty()) {
		return {};
	}

	txnKey.resize(DUKPT_TDES_KEY_LEN);
	r = dukpt_tdes_derive_txn_key(ik.data(), ksn.data(), txnKey.data());
	if (r) {
		logError(QString::asprintf("dukpt_tdes_derive_txn_key() failed; r=%d\n", r));
		return {};
	}

	return txnKey;
}

std::vector<std::uint8_t> MainWindow::prepareAesInitialKey(bool full_ksn)
{
	int r;
	std::vector<std::uint8_t> ik;

	if (full_ksn) {
		// Validate KSN length
		if (ksn.size() != DUKPT_AES_KSN_LEN) {
			logError(QString::asprintf("AES: KSN must be %u bytes (thus %u hex digits)\n", DUKPT_AES_KSN_LEN, DUKPT_AES_KSN_LEN * 2));
			return {};
		}
	} else {
		// Validate KSN length
		if (ksn.size() != DUKPT_AES_IK_ID_LEN &&
			ksn.size() != DUKPT_AES_KSN_LEN
		) {
			logError(QString::asprintf("AES: KSN must be either %u (for IK ID) or %u (for full KSN) bytes (thus %u or %u hex digits)\n",
				DUKPT_AES_IK_ID_LEN, DUKPT_AES_KSN_LEN,
				DUKPT_AES_IK_ID_LEN * 2, DUKPT_AES_KSN_LEN * 2
			));
			return {};
		}
	}

	switch (inputKeyType) {
		case DUKPT_UI_INPUT_KEY_TYPE_BDK:
			// Validate BDK length
			if (inputKey.size() != DUKPT_AES_KEY_LEN(AES128) &&
				inputKey.size() != DUKPT_AES_KEY_LEN(AES192) &&
				inputKey.size() != DUKPT_AES_KEY_LEN(AES256)
			) {
				logError(QString::asprintf("AES: BDK must be %u|%u|%u bytes (thus %u|%u|%u hex digits)\n",
					DUKPT_AES_KEY_LEN(AES128), DUKPT_AES_KEY_LEN(AES192), DUKPT_AES_KEY_LEN(AES256),
					DUKPT_AES_KEY_LEN(AES128) * 2, DUKPT_AES_KEY_LEN(AES192) * 2, DUKPT_AES_KEY_LEN(AES256) * 2
				));
				return {};
			}

			// Derive initial key
			ik.resize(inputKey.size());
			r = dukpt_aes_derive_ik(inputKey.data(), inputKey.size(), ksn.data(), ik.data());
			if (r) {
				logError(QString::asprintf("dukpt_aes_derive_ik() failed; r=%d\n", r));
				return {};
			}
			return ik;

		case DUKPT_UI_INPUT_KEY_TYPE_IK:
			// Validate IK length
			if (inputKey.size() != DUKPT_AES_KEY_LEN(AES128) &&
				inputKey.size() != DUKPT_AES_KEY_LEN(AES192) &&
				inputKey.size() != DUKPT_AES_KEY_LEN(AES256)
			) {
				logError(QString::asprintf("AES: IK/IPEK must be %u|%u|%u bytes (thus %u|%u|%u hex digits)\n",
					DUKPT_AES_KEY_LEN(AES128), DUKPT_AES_KEY_LEN(AES192), DUKPT_AES_KEY_LEN(AES256),
					DUKPT_AES_KEY_LEN(AES128) * 2, DUKPT_AES_KEY_LEN(AES192) * 2, DUKPT_AES_KEY_LEN(AES256) * 2
				));
				return {};
			}
			return inputKey;

		default:
			logError("Unknown input key type");
			return {};
	}
}

std::vector<std::uint8_t> MainWindow::prepareAesTxnKey()
{
	int r;
	std::vector<std::uint8_t> ik;
	std::vector<std::uint8_t> txnKey;

	ik = prepareAesInitialKey(true);
	if (ik.empty()) {
		return {};
	}

	txnKey.resize(ik.size());
	r = dukpt_aes_derive_txn_key(ik.data(), ik.size(), ksn.data(), txnKey.data());
	if (r) {
		logError(QString::asprintf("dukpt_aes_derive_txn_key() failed; r=%d\n", r));
		return {};
	}

	return txnKey;
}

std::vector<std::uint8_t> MainWindow::prepareAesUpdateKey()
{
	int r;
	dukpt_aes_key_type_t key_type;
	std::vector<std::uint8_t> ik;
	std::vector<std::uint8_t> updateKey;

	ik = prepareAesInitialKey(true);
	if (ik.empty()) {
		return {};
	}

	switch (derivedKeyType) {
		case DUKPT_UI_KEY_TYPE_AES128:
			key_type = DUKPT_AES_KEY_TYPE_AES128;
			updateKey.resize(DUKPT_AES_KEY_LEN(AES128));
			break;

		case DUKPT_UI_KEY_TYPE_AES192:
			key_type = DUKPT_AES_KEY_TYPE_AES192;
			updateKey.resize(DUKPT_AES_KEY_LEN(AES192));
			break;

		case DUKPT_UI_KEY_TYPE_AES256:
			key_type = DUKPT_AES_KEY_TYPE_AES256;
			updateKey.resize(DUKPT_AES_KEY_LEN(AES256));
			break;

		default:
			logError("Invalid derived key type");
			return {};
	}

	r = dukpt_aes_derive_update_key(ik.data(), ik.size(), ksn.data(), key_type, updateKey.data());
	if (r) {
		logError(QString::asprintf("dukpt_aes_derive_update_key() failed; r=%d\n", r));
		return {};
	}

	return updateKey;
}

int MainWindow::prepareAesKeyType(dukpt_ui_key_type_t uiKeyType)
{
	switch (uiKeyType) {
		case DUKPT_UI_KEY_TYPE_AES128:
			return DUKPT_AES_KEY_TYPE_AES128;

		case DUKPT_UI_KEY_TYPE_AES192:
			return DUKPT_AES_KEY_TYPE_AES192;

		case DUKPT_UI_KEY_TYPE_AES256:
			return DUKPT_AES_KEY_TYPE_AES256;

		default:
			logError("Invalid AES key type");
			return -1;
	}
}

int MainWindow::prepareCmacKeyType(dukpt_ui_key_type_t uiKeyType)
{
	switch (uiKeyType) {
		case DUKPT_UI_KEY_TYPE_AES128:
			return DUKPT_AES_KEY_TYPE_AES128;

		case DUKPT_UI_KEY_TYPE_AES192:
			return DUKPT_AES_KEY_TYPE_AES192;

		case DUKPT_UI_KEY_TYPE_AES256:
			return DUKPT_AES_KEY_TYPE_AES256;

		default:
			logError("Invalid CMAC key type");
			return -1;
	}
}

int MainWindow::prepareHmacKeyType(dukpt_ui_key_type_t uiKeyType)
{
	switch (uiKeyType) {
		case DUKPT_UI_KEY_TYPE_HMAC128:
			return DUKPT_AES_KEY_TYPE_HMAC128;

		case DUKPT_UI_KEY_TYPE_HMAC192:
			return DUKPT_AES_KEY_TYPE_HMAC192;

		case DUKPT_UI_KEY_TYPE_HMAC256:
			return DUKPT_AES_KEY_TYPE_HMAC256;

		default:
			logError("Invalid HMAC key type");
			return -1;
	}
}

bool MainWindow::validateTxnData(const std::vector<std::uint8_t>& txnData)
{
	if (mode == DUKPT_UI_MODE_TDES) {
		if ((txnData.size() & (DUKPT_TDES_BLOCK_LEN-1)) != 0) {
			logError(QString::asprintf("TDES: Transaction data length must be a multiple of %u bytes\n", DUKPT_TDES_BLOCK_LEN));
			return false;
		}

		return true;

	} else if (mode == DUKPT_UI_MODE_AES) {
		if ((txnData.size() & (DUKPT_AES_BLOCK_LEN-1)) != 0) {
			logError(QString::asprintf("AES: Transaction data length must be a multiple of %u bytes\n", DUKPT_AES_BLOCK_LEN));
			return false;
		}

		return true;
	}

	return false;
}

bool MainWindow::prepareIv()
{
	if (mode == DUKPT_UI_MODE_TDES) {
		if (iv.empty()) {
			iv.resize(DUKPT_TDES_BLOCK_LEN, 0);
			return true;
		}

		if (iv.size() != DUKPT_TDES_BLOCK_LEN) {
			logError(QString::asprintf("TDES: IV length must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_BLOCK_LEN, DUKPT_TDES_BLOCK_LEN * 2));
			return false;
		}

		return true;

	} else if (mode == DUKPT_UI_MODE_AES) {
		if (iv.empty()) {
			iv.resize(DUKPT_AES_BLOCK_LEN, 0);
			return true;
		}

		if (iv.size() != DUKPT_AES_BLOCK_LEN) {
			logError(QString::asprintf("AES: IV length must be %u bytes (thus %u hex digits)\n", DUKPT_AES_BLOCK_LEN, DUKPT_AES_BLOCK_LEN * 2));
			return false;
		}

		return true;
	}

	return false;
}

QString MainWindow::outputTr31InitialKey(const std::vector<std::uint8_t>& ik)
{
	int r;
	std::uint8_t tr31_version;
	struct tr31_key_t key;
	struct tr31_ctx_t tr31_ctx;
	unsigned int kbpk_algorithm;
	struct tr31_key_t kbpk_obj;
	char key_block[1024];

	// Populate key attributes for ANSI X9.24 Initial Key
	// See ANSI X9.24-3:2017, 6.5.3 "Update Initial Key"
	key.usage = TR31_KEY_USAGE_DUKPT_IK;
	key.mode_of_use = TR31_KEY_MODE_OF_USE_DERIVE;
	key.key_version = TR31_KEY_VERSION_IS_UNUSED;
	key.exportability = TR31_KEY_EXPORT_NONE;

	// Populate key algorithm
	if (mode == DUKPT_UI_MODE_TDES) {
		key.algorithm = TR31_KEY_ALGORITHM_TDES;
	} else if (mode == DUKPT_UI_MODE_AES) {
		key.algorithm = TR31_KEY_ALGORITHM_AES;
	} else {
		logError(QString::asprintf("TR-31: %s\n", tr31_get_error_string(TR31_ERROR_UNSUPPORTED_ALGORITHM)));
		return QString();
	}

	// Populate key data
	// Avoid tr31_key_set_data() here to avoid tr31_key_release() later
	key.length = ik.size();
	key.data = const_cast<std::uint8_t*>(ik.data());

	// Populate TR-31 context object
	switch (outputFormat) {
		case DUKPT_UI_OUTPUT_FORMAT_TR31_B: tr31_version = TR31_VERSION_B; break;
		case DUKPT_UI_OUTPUT_FORMAT_TR31_D: tr31_version = TR31_VERSION_D; break;
		case DUKPT_UI_OUTPUT_FORMAT_TR31_E: tr31_version = TR31_VERSION_E; break;
		default:
			logError("Unknown input key type");
			return QString();
	}
	r = tr31_init(tr31_version, &key, &tr31_ctx);
	if (r) {
		logError(QString::asprintf("tr31_init() failed; r=%d\n", r));
		return QString();
	}

	// Populate optional blocks for KSN
	if (tr31WithKsn) {
		if (mode == DUKPT_UI_MODE_TDES) {
			uint8_t iksn[DUKPT_TDES_KSN_LEN];

			// Sanitise Initial Key Serial Number (IKSN)
			memcpy(iksn, ksn.data(), DUKPT_TDES_KSN_LEN - 2);
			iksn[7] &= 0xE0;
			iksn[8] = 0;
			iksn[9] = 0;

			// Add optional block using the provided length. This allows
			// the user to add either 8 or 10 byte KSNs, depending on their
			// needs.
			r = tr31_opt_block_add(
				&tr31_ctx,
				TR31_OPT_BLOCK_KS,
				iksn,
				ksn.size()
			);
			if (r) {
				logError(QString::asprintf("TR-31 optional block error %d: %s\n", r, tr31_get_error_string(static_cast<tr31_error_t>(r))));
				return QString();
			}

		} else if (mode == DUKPT_UI_MODE_AES) {
			// Add optional block. For AES DUKPT, this will always be the
			// initial key ID and not the whole KSN.
			// See TR-31:2018, A.5.6, table 11
			r = tr31_opt_block_add(
				&tr31_ctx,
				TR31_OPT_BLOCK_IK,
				ksn.data(),
				DUKPT_AES_IK_ID_LEN
			);
			if (r) {
				logError(QString::asprintf("TR-31 optional block error %d: %s\n", r, tr31_get_error_string(static_cast<tr31_error_t>(r))));
				return QString();
			}
		}
	}

	// Populate optional block KC
	if (tr31WithKc) {
		r = tr31_opt_block_add_KC(&tr31_ctx);
		if (r) {
			logError(QString::asprintf("TR-31 optional block error %d: %s\n", r, tr31_get_error_string(static_cast<tr31_error_t>(r))));
			return QString();
		}
	}

	// Populate optional block KP
	if (tr31WithKp) {
		r = tr31_opt_block_add_KP(&tr31_ctx);
		if (r) {
			logError(QString::asprintf("TR-31 optional block error %d: %s\n", r, tr31_get_error_string(static_cast<tr31_error_t>(r))));
			return QString();
		}
	}

	// Determine key block protection key algorithm from keyblock format version
	switch (tr31_version) {
		case TR31_VERSION_B:
			kbpk_algorithm = TR31_KEY_ALGORITHM_TDES;
			break;

		case TR31_VERSION_D:
		case TR31_VERSION_E:
			kbpk_algorithm = TR31_KEY_ALGORITHM_AES;
			break;

		default:
			logError(QString::asprintf("%s\n", tr31_get_error_string(TR31_ERROR_UNSUPPORTED_VERSION)));
			return QString();
	}

	// Populate key block protection key
	r = tr31_key_init(
		TR31_KEY_USAGE_TR31_KBPK,
		kbpk_algorithm,
		TR31_KEY_MODE_OF_USE_ENC_DEC,
		"00",
		TR31_KEY_EXPORT_NONE,
		kbpk.data(),
		kbpk.size(),
		&kbpk_obj
	);
	if (r) {
		logError(QString::asprintf("TR-31 KBPK error %d: %s\n", r, tr31_get_error_string(static_cast<tr31_error_t>(r))));
		return QString();
	}

	// Export TR-31 key block
	r = tr31_export(&tr31_ctx, &kbpk_obj, key_block, sizeof(key_block));
	if (r) {
		logError(QString::asprintf("TR-31 export error %d: %s\n", r, tr31_get_error_string(static_cast<tr31_error_t>(r))));
		return QString();
	}

	// Cleanup
	tr31_key_release(&kbpk_obj);
	tr31_release(&tr31_ctx);

	return key_block;
}

std::vector<std::uint8_t> MainWindow::encryptPin(const std::vector<std::uint8_t>& txnKey, const std::vector<std::uint8_t>& pin)
{
	int r;
	std::vector<std::uint8_t> encryptedPin;

	// Validate PIN length
	if (pin.size() < 4 || pin.size() > 12) {
		logError(QString::asprintf("TDES: PIN must be 4 to 12 digits\n"));
		return {};
	}

	// Validate PAN length
	if (pan.size() < 5 || pan.size() > 10) {
		logError(QString::asprintf("TDES: PAN must be 10 to 19 digits\n"));
		return {};
	}

	if (mode == DUKPT_UI_MODE_TDES) {
		// Do it
		encryptedPin.resize(DUKPT_TDES_PINBLOCK_LEN);
		r = dukpt_tdes_encrypt_pin(
			txnKey.data(),
			0,
			pin.data(),
			pin.size(),
			pan.data(),
			pan.size(),
			encryptedPin.data()
		);
		if (r) {
			logError(QString::asprintf("dukpt_tdes_encrypt_pin() failed; r=%d\n", r));
			return {};
		}

		return encryptedPin;

	} else if (mode == DUKPT_UI_MODE_AES) {
		dukpt_aes_key_type_t key_type;

		r = prepareAesKeyType(encryptDecryptKeyType);
		if (r < 0) {
			return {};
		}
		key_type = static_cast<dukpt_aes_key_type_t>(r);

		// Do it
		encryptedPin.resize(DUKPT_AES_PINBLOCK_LEN);
		r = dukpt_aes_encrypt_pin(
			txnKey.data(),
			txnKey.size(),
			ksn.data(),
			key_type,
			pin.data(),
			pin.size(),
			pan.data(),
			pan.size(),
			encryptedPin.data()
		);
		if (r) {
			logError(QString::asprintf("dukpt_aes_encrypt_pin() failed; r=%d\n", r));
			return {};
		}

		return encryptedPin;
	}

	return {};
}

std::vector<std::uint8_t> MainWindow::decryptPin(const std::vector<std::uint8_t>& txnKey, const std::vector<std::uint8_t>& encryptedPin)
{
	int r;
	std::uint8_t pin[12];
	std::size_t pin_len;

	// Validate PAN length
	if (pan.size() < 5 || pan.size() > 10) {
		logError(QString::asprintf("TDES: PAN must be 10 to 19 digits\n"));
		return {};
	}

	if (mode == DUKPT_UI_MODE_TDES) {
		// Validate PIN block length
		if (encryptedPin.size() != DUKPT_TDES_PINBLOCK_LEN) {
			logError(QString::asprintf("TDES: PIN block must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_PINBLOCK_LEN, DUKPT_TDES_PINBLOCK_LEN * 2));
			return {};
		}

		// Do it
		pin_len = 0;
		r = dukpt_tdes_decrypt_pin(
			txnKey.data(),
			encryptedPin.data(),
			pan.data(),
			pan.size(),
			pin,
			&pin_len
		);
		if (r) {
			logError(QString::asprintf("dukpt_tdes_decrypt_pin() failed; r=%d\n", r));
			return {};
		}

		return std::vector<std::uint8_t>(pin, pin + pin_len);

	} else if (mode == DUKPT_UI_MODE_AES) {
		dukpt_aes_key_type_t key_type;

		// Validate PIN block length
		if (encryptedPin.size() != DUKPT_AES_PINBLOCK_LEN) {
			logError(QString::asprintf( "AES: PIN block must be %u bytes (thus %u hex digits)\n", DUKPT_AES_PINBLOCK_LEN, DUKPT_AES_PINBLOCK_LEN * 2));
			return {};
		}

		r = prepareAesKeyType(encryptDecryptKeyType);
		if (r < 0) {
			return {};
		}
		key_type = static_cast<dukpt_aes_key_type_t>(r);

		// Do it
		pin_len = 0;
		r = dukpt_aes_decrypt_pin(
			txnKey.data(),
			txnKey.size(),
			ksn.data(),
			key_type,
			encryptedPin.data(),
			pan.data(),
			pan.size(),
			pin,
			&pin_len
		);
		if (r) {
			logError(QString::asprintf("dukpt_aes_decrypt_pin() failed; r=%d\n", r));
			return {};
		}

		return std::vector<std::uint8_t>(pin, pin + pin_len);
	}

	return {};
}

std::vector<std::uint8_t> MainWindow::encryptRequest(const std::vector<std::uint8_t>& txnKey)
{
	int r;
	std::vector<std::uint8_t> outputData;

	// Validate transaction data
	if (!validateTxnData(encDecData)) {
		return {};
	}

	// Ensure that IV is non-empty and valid
	if (!prepareIv()) {
		return {};
	}

	// Output data will always be the same length as input data
	outputData.resize(encDecData.size());

	if (mode == DUKPT_UI_MODE_TDES) {
		r = dukpt_tdes_encrypt_request(
			txnKey.data(),
			iv.data(),
			encDecData.data(),
			encDecData.size(),
			outputData.data()
		);
		if (r) {
			logError(QString::asprintf("dukpt_tdes_encrypt_request() failed; r=%d\n", r));
			return {};
		}

		return outputData;

	} else if (mode == DUKPT_UI_MODE_AES) {
		dukpt_aes_key_type_t key_type;

		r = prepareAesKeyType(encryptDecryptKeyType);
		if (r < 0) {
			return {};
		}
		key_type = static_cast<dukpt_aes_key_type_t>(r);

		r = dukpt_aes_encrypt_request(
			txnKey.data(),
			txnKey.size(),
			ksn.data(),
			key_type,
			iv.data(),
			encDecData.data(),
			encDecData.size(),
			outputData.data()
		);
		if (r) {
			logError(QString::asprintf("dukpt_aes_encrypt_request() failed; r=%d\n", r));
			return {};
		}

		return outputData;
	}

	return {};
}

std::vector<std::uint8_t> MainWindow::decryptRequest(const std::vector<std::uint8_t>& txnKey)
{
	int r;
	std::vector<std::uint8_t> outputData;

	// Validate transaction data
	if (!validateTxnData(encDecData)) {
		return {};
	}

	// Ensure that IV is non-empty and valid
	if (!prepareIv()) {
		return {};
	}

	// Output data will always be the same length as input data
	outputData.resize(encDecData.size());

	if (mode == DUKPT_UI_MODE_TDES) {
		r = dukpt_tdes_decrypt_request(
			txnKey.data(),
			iv.data(),
			encDecData.data(),
			encDecData.size(),
			outputData.data()
		);
		if (r) {
			logError(QString::asprintf("dukpt_tdes_decrypt_request() failed; r=%d\n", r));
			return {};
		}

		return outputData;

	} else if (mode == DUKPT_UI_MODE_AES) {
		dukpt_aes_key_type_t key_type;

		r = prepareAesKeyType(encryptDecryptKeyType);
		if (r < 0) {
			return {};
		}
		key_type = static_cast<dukpt_aes_key_type_t>(r);

		r = dukpt_aes_decrypt_request(
			txnKey.data(),
			txnKey.size(),
			ksn.data(),
			key_type,
			iv.data(),
			encDecData.data(),
			encDecData.size(),
			outputData.data()
		);
		if (r) {
			logError(QString::asprintf("dukpt_aes_decrypt_request() failed; r=%d\n", r));
			return {};
		}

		return outputData;
	}

	return {};
}

std::vector<std::uint8_t> MainWindow::encryptResponse(const std::vector<std::uint8_t>& txnKey)
{
	int r;
	std::vector<std::uint8_t> outputData;

	// Validate transaction data
	if (!validateTxnData(encDecData)) {
		return {};
	}

	// Ensure that IV is non-empty and valid
	if (!prepareIv()) {
		return {};
	}

	// Output data will always be the same length as input data
	outputData.resize(encDecData.size());

	if (mode == DUKPT_UI_MODE_TDES) {
		r = dukpt_tdes_encrypt_response(
			txnKey.data(),
			iv.data(),
			encDecData.data(),
			encDecData.size(),
			outputData.data()
		);
		if (r) {
			logError(QString::asprintf("dukpt_tdes_encrypt_response() failed; r=%d\n", r));
			return {};
		}

		return outputData;

	} else if (mode == DUKPT_UI_MODE_AES) {
		dukpt_aes_key_type_t key_type;

		r = prepareAesKeyType(encryptDecryptKeyType);
		if (r < 0) {
			return {};
		}
		key_type = static_cast<dukpt_aes_key_type_t>(r);

		r = dukpt_aes_encrypt_response(
			txnKey.data(),
			txnKey.size(),
			ksn.data(),
			key_type,
			iv.data(),
			encDecData.data(),
			encDecData.size(),
			outputData.data()
		);
		if (r) {
			logError(QString::asprintf("dukpt_aes_encrypt_response() failed; r=%d\n", r));
			return {};
		}

		return outputData;
	}

	return {};
}

std::vector<std::uint8_t> MainWindow::decryptResponse(const std::vector<std::uint8_t>& txnKey)
{
	int r;
	std::vector<std::uint8_t> outputData;

	// Validate transaction data
	if (!validateTxnData(encDecData)) {
		return {};
	}

	// Ensure that IV is non-empty and valid
	if (!prepareIv()) {
		return {};
	}

	// Output data will always be the same length as input data
	outputData.resize(encDecData.size());

	if (mode == DUKPT_UI_MODE_TDES) {
		r = dukpt_tdes_decrypt_response(
			txnKey.data(),
			iv.data(),
			encDecData.data(),
			encDecData.size(),
			outputData.data()
		);
		if (r) {
			logError(QString::asprintf("dukpt_tdes_decrypt_response() failed; r=%d\n", r));
			return {};
		}

		return outputData;

	} else if (mode == DUKPT_UI_MODE_AES) {
		dukpt_aes_key_type_t key_type;

		r = prepareAesKeyType(encryptDecryptKeyType);
		if (r < 0) {
			return {};
		}
		key_type = static_cast<dukpt_aes_key_type_t>(r);

		r = dukpt_aes_decrypt_response(
			txnKey.data(),
			txnKey.size(),
			ksn.data(),
			key_type,
			iv.data(),
			encDecData.data(),
			encDecData.size(),
			outputData.data()
		);
		if (r) {
			logError(QString::asprintf("dukpt_aes_decrypt_response() failed; r=%d\n", r));
			return {};
		}

		return outputData;
	}

	return {};
}

std::vector<std::uint8_t> MainWindow::macRequest(const std::vector<std::uint8_t>& txnKey)
{
	int r;
	std::vector<std::uint8_t> mac;

	if (mode != DUKPT_UI_MODE_TDES) {
		logError("ANSI X9.19 Retail MAC only allowed for TDES mode");
		return {};
	}

	// ANSI X9.19 Retail MAC length
	mac.resize(DUKPT_TDES_MAC_LEN);

	// Do it
	r = dukpt_tdes_generate_request_mac(
		txnKey.data(),
		macData.data(),
		macData.size(),
		mac.data()
	);
	if (r) {
		logError(QString::asprintf("dukpt_tdes_generate_request_mac() failed; r=%d\n", r));
		return {};
	}

	return mac;
}

std::vector<std::uint8_t> MainWindow::macResponse(const std::vector<std::uint8_t>& txnKey)
{
	int r;
	std::vector<std::uint8_t> mac;

	if (mode != DUKPT_UI_MODE_TDES) {
		logError("ANSI X9.19 Retail MAC is only allowed for TDES mode");
		return {};
	}

	// ANSI X9.19 Retail MAC length
	mac.resize(DUKPT_TDES_MAC_LEN);

	// Do it
	r = dukpt_tdes_generate_response_mac(
		txnKey.data(),
		macData.data(),
		macData.size(),
		mac.data()
	);
	if (r) {
		logError(QString::asprintf("dukpt_tdes_generate_response_mac() failed; r=%d\n", r));
		return {};
	}

	return mac;
}

std::vector<std::uint8_t> MainWindow::cmacRequest(const std::vector<std::uint8_t>& txnKey)
{
	int r;
	dukpt_aes_key_type_t key_type;
	std::vector<std::uint8_t> cmac;

	if (macKeyType != DUKPT_UI_KEY_TYPE_AES128 &&
		macKeyType != DUKPT_UI_KEY_TYPE_AES192 &&
		macKeyType != DUKPT_UI_KEY_TYPE_AES256
	) {
		logError("CMAC computation is only allowed for AES working keys");
		return {};
	}

	r = prepareCmacKeyType(macKeyType);
	if (r < 0) {
		return {};
	}
	key_type = static_cast<dukpt_aes_key_type_t>(r);

	// AES-CMAC length
	cmac.resize(DUKPT_AES_CMAC_LEN);

	// Do it
	r = dukpt_aes_generate_request_cmac(
		txnKey.data(),
		txnKey.size(),
		ksn.data(),
		key_type,
		macData.data(),
		macData.size(),
		cmac.data()
	);
	if (r) {
		logError(QString::asprintf("dukpt_aes_generate_request_cmac() failed; r=%d\n", r));
		return {};
	}

	return cmac;
}

std::vector<std::uint8_t> MainWindow::cmacResponse(const std::vector<std::uint8_t>& txnKey)
{
	int r;
	dukpt_aes_key_type_t key_type;
	std::vector<std::uint8_t> cmac;

	if (macKeyType != DUKPT_UI_KEY_TYPE_AES128 &&
		macKeyType != DUKPT_UI_KEY_TYPE_AES192 &&
		macKeyType != DUKPT_UI_KEY_TYPE_AES256
	) {
		logError("CMAC computation is only allowed for AES working keys");
		return {};
	}

	r = prepareCmacKeyType(macKeyType);
	if (r < 0) {
		return {};
	}
	key_type = static_cast<dukpt_aes_key_type_t>(r);

	// AES-CMAC length
	cmac.resize(DUKPT_AES_CMAC_LEN);

	// Do it
	r = dukpt_aes_generate_response_cmac(
		txnKey.data(),
		txnKey.size(),
		ksn.data(),
		key_type,
		macData.data(),
		macData.size(),
		cmac.data()
	);
	if (r) {
		logError(QString::asprintf("dukpt_aes_generate_response_cmac() failed; r=%d\n", r));
		return {};
	}

	return cmac;
}

std::vector<std::uint8_t> MainWindow::hmacRequest(const std::vector<std::uint8_t>& txnKey)
{
	int r;
	dukpt_aes_key_type_t key_type;
	std::vector<std::uint8_t> hmac;

	if (macKeyType != DUKPT_UI_KEY_TYPE_HMAC128 &&
		macKeyType != DUKPT_UI_KEY_TYPE_HMAC192 &&
		macKeyType != DUKPT_UI_KEY_TYPE_HMAC256
	) {
		logError("HMAC computation is only allowed for HMAC working keys");
		return {};
	}

	r = prepareHmacKeyType(macKeyType);
	if (r < 0) {
		return {};
	}
	key_type = static_cast<dukpt_aes_key_type_t>(r);

	// HMAC-SHA256 length
	hmac.resize(DUKPT_AES_HMAC_SHA256_LEN);

	// Do it
	r = dukpt_aes_generate_request_hmac_sha256(
		txnKey.data(),
		txnKey.size(),
		ksn.data(),
		key_type,
		macData.data(),
		macData.size(),
		hmac.data()
	);
	if (r) {
		logError(QString::asprintf("dukpt_aes_generate_request_hmac_sha256() failed; r=%d\n", r));
		return {};
	}

	return hmac;
}

std::vector<std::uint8_t> MainWindow::hmacResponse(const std::vector<std::uint8_t>& txnKey)
{
	int r;
	dukpt_aes_key_type_t key_type;
	std::vector<std::uint8_t> hmac;

	if (macKeyType != DUKPT_UI_KEY_TYPE_HMAC128 &&
		macKeyType != DUKPT_UI_KEY_TYPE_HMAC192 &&
		macKeyType != DUKPT_UI_KEY_TYPE_HMAC256
	) {
		logError("HMAC computation is only allowed for HMAC working keys");
		return {};
	}

	r = prepareHmacKeyType(macKeyType);
	if (r < 0) {
		return {};
	}
	key_type = static_cast<dukpt_aes_key_type_t>(r);

	// HMAC-SHA256 length
	hmac.resize(DUKPT_AES_HMAC_SHA256_LEN);

	// Do it
	r = dukpt_aes_generate_response_hmac_sha256(
		txnKey.data(),
		txnKey.size(),
		ksn.data(),
		key_type,
		macData.data(),
		macData.size(),
		hmac.data()
	);
	if (r) {
		logError(QString::asprintf("dukpt_aes_generate_response_hmac_sha256() failed; r=%d\n", r));
		return {};
	}

	return hmac;
}
