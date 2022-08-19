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

#include <QtCore/QByteArray>
#include <QtCore/QSettings>
#include <QtWidgets/QScrollBar>

MainWindow::MainWindow(QWidget* parent)
: QMainWindow(parent)
{
	// Setup validators
	keyValidator = new CryptoKeyStringValidator(CryptoValidator::TDES, this);
	keyValidator->setObjectName("keyValidator");
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
	inputKeyEdit->setValidator(keyValidator);
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
	blockValidator->setCipher(cipher);
	dataValidator->setCipher(cipher);

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

			logVector("IK: ", ik);
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

			logVector("IK: ", ik);
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
	// TODO: implement
}

void MainWindow::on_macPushButton_clicked()
{
	// TODO: implement
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
