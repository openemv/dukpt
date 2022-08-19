/**
 * @file mainwindow.h
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

#ifndef DUKPT_UI_MAINWINDOW_H
#define DUKPT_UI_MAINWINDOW_H

#include <QtWidgets/QMainWindow>

#include "ui_mainwindow.h"
#include "validators.h"

#include <cstdint>
#include <utility>
#include <vector>

class MainWindow : public QMainWindow, private Ui::MainWindow
{
	Q_OBJECT

private:
	CryptoKeyStringValidator* keyValidator;
	CryptoHexStringValidator* blockValidator;
	DecStringValidator* pinValidator;
	DecStringValidator* panValidator;
	CryptoHexStringValidator* dataValidator;
	HexStringValidator* macValidator;

public:
	explicit MainWindow(QWidget* parent = nullptr);

protected:
	void closeEvent(QCloseEvent* event) override;

private:
	void loadSettings();
	void saveSettings() const;

private: // helper enums and helper functions for inputs
	enum dukpt_ui_mode_t {
		DUKPT_UI_MODE_UNKNOWN = -1,
		DUKPT_UI_MODE_TDES = 1,
		DUKPT_UI_MODE_AES,
	};
	dukpt_ui_mode_t getMode() const;

	enum dukpt_ui_input_key_type_t {
		DUKPT_UI_INPUT_KEY_TYPE_UNKNOWN = -1,
		DUKPT_UI_INPUT_KEY_TYPE_BDK = 1,
		DUKPT_UI_INPUT_KEY_TYPE_IK,
	};
	dukpt_ui_input_key_type_t getInputKeyType() const;

	enum dukpt_ui_derivation_action_t {
		DUKPT_UI_DERIVATION_ACTION_UNKNOWN = -1,
		DUKPT_UI_DERIVATION_ACTION_IK = 1,
		DUKPT_UI_DERIVATION_ACTION_TXN,
		DUKPT_UI_DERIVATION_ACTION_UPDATE,
	};
	dukpt_ui_derivation_action_t getDerivationAction() const;
	void selectDerivationAction(dukpt_ui_derivation_action_t derivationAction);
	void updateDerivationActions(dukpt_ui_mode_t mode, dukpt_ui_input_key_type_t inputKeyType);

	enum dukpt_ui_key_type_t {
		DUKPT_UI_KEY_TYPE_UNKNOWN = -1,
		DUKPT_UI_KEY_TYPE_AES128 = 1,
		DUKPT_UI_KEY_TYPE_AES192,
		DUKPT_UI_KEY_TYPE_AES256,
	};
	dukpt_ui_key_type_t getDerivedKeyType() const;
	void selectDerivedKeyType(dukpt_ui_key_type_t derivedKeyType);
	void updateDerivedKeyTypes(dukpt_ui_derivation_action_t derivationAction);
	dukpt_ui_key_type_t getEncryptDecryptKeyType() const;
	void selectEncryptDecryptKeyType(dukpt_ui_key_type_t encryptDecryptKeyType);
	void updateEncryptDecryptKeyTypes(dukpt_ui_mode_t mode);

	enum dukpt_ui_output_format_t {
		DUKPT_UI_OUTPUT_FORMAT_UNKNOWN = -1,
		DUKPT_UI_OUTPUT_FORMAT_HEX = 1,
		DUKPT_UI_OUTPUT_FORMAT_TR31_B,
		DUKPT_UI_OUTPUT_FORMAT_TR31_D,
		DUKPT_UI_OUTPUT_FORMAT_TR31_E,
	};
	dukpt_ui_output_format_t getOutputFormat() const;
	void selectOutputFormat(dukpt_ui_output_format_t outputFormat);
	void updateOutputFormats(dukpt_ui_mode_t mode);

	enum dukpt_ui_pin_action_t {
		DUKPT_UI_PIN_ACTION_UNKNOWN = -1,
		DUKPT_UI_PIN_ACTION_ENCRYPT = 1,
		DUKPT_UI_PIN_ACTION_DECRYPT,
	};
	dukpt_ui_pin_action_t getPinAction() const;

	enum dukpt_ui_data_action_t {
		DUKPT_UI_DATA_ACTION_UNKNOWN = -1,
		DUKPT_UI_DATA_ACTION_ENCRYPT_REQUEST = 1,
		DUKPT_UI_DATA_ACTION_DECRYPT_REQUEST,
		DUKPT_UI_DATA_ACTION_ENCRYPT_RESPONSE,
		DUKPT_UI_DATA_ACTION_DECRYPT_RESPONSE,
	};
	dukpt_ui_data_action_t getDataAction() const;

	enum dukpt_ui_mac_action_t {
		DUKPT_UI_MAC_ACTION_UNKNOWN = -1,
		DUKPT_UI_MAC_ACTION_RETAIL_MAC = 1,
		DUKPT_UI_MAC_ACTION_AES128_CMAC,
		DUKPT_UI_MAC_ACTION_AES192_CMAC,
		DUKPT_UI_MAC_ACTION_AES256_CMAC,
		DUKPT_UI_MAC_ACTION_HMAC128_SHA256,
		DUKPT_UI_MAC_ACTION_HMAC192_SHA256,
		DUKPT_UI_MAC_ACTION_HMAC256_SHA256,
	};
	dukpt_ui_mac_action_t getMacAction() const;
	void selectMacAction(dukpt_ui_mac_action_t macAction);
	void updateMacActions(dukpt_ui_mode_t mode);

	enum dukpt_ui_log_level_t {
		DUKPT_LOG_INFO = 1,
		DUKPT_LOG_SUCCESS,
		DUKPT_LOG_ERROR,
		DUKPT_LOG_FAILURE,
	};
	void log(dukpt_ui_log_level_t level, QString&& str);
	inline void logInfo(QString&& str) { log(DUKPT_LOG_INFO, std::move(str)); }
	inline void logSuccess(QString&& str) { log(DUKPT_LOG_SUCCESS, std::move(str)); }
	inline void logError(QString&& str) { log(DUKPT_LOG_ERROR, std::move(str)); }
	inline void logFailure(QString&& str) { log(DUKPT_LOG_FAILURE, std::move(str)); }
	void logVector(QString&& str, const std::vector<std::uint8_t>& v);

private slots: // connect-by-name helper functions for validation
	void updateValidationStyleSheet(QLineEdit* edit);
	void updateValidationStyleSheet(const QValidator* validator, QPlainTextEdit* edit);
	void on_inputKeyEdit_textChanged(const QString&) { updateValidationStyleSheet(inputKeyEdit); }
	void on_kbpkEdit_textChanged(const QString&) { updateValidationStyleSheet(kbpkEdit); }
	void on_pinEdit_textChanged(const QString&) { updateValidationStyleSheet(pinEdit); }
	void on_panEdit_textChanged(const QString&) { updateValidationStyleSheet(panEdit); }
	void on_dataEdit_textChanged() { updateValidationStyleSheet(dataValidator, dataEdit); }
	void on_ivEdit_textChanged(const QString&) { updateValidationStyleSheet(ivEdit); }
	void on_macEdit_textChanged() { updateValidationStyleSheet(macValidator, macEdit); }
	void on_keyValidator_changed() { updateValidationStyleSheet(inputKeyEdit); updateValidationStyleSheet(kbpkEdit); }
	void on_blockValidator_changed() { updateValidationStyleSheet(pinEdit); updateValidationStyleSheet(ivEdit); }
	void on_dataValidator_changed() { updateValidationStyleSheet(dataValidator, dataEdit); }

private slots: // connect-by-name helper functions for combo boxes
	void on_modeComboBox_currentIndexChanged(int index);
	void on_inputKeyTypeComboBox_currentIndexChanged(int index);
	void on_derivationActionComboBox_currentIndexChanged(int index);
	void on_outputFormatComboBox_currentIndexChanged(int index);
	void on_pinActionComboBox_currentIndexChanged(int index);

private slots: // connect-by-name helper functions for push buttons
	void on_keyDerivationPushButton_clicked();
	void on_encryptDecryptPushButton_clicked();
	void on_macPushButton_clicked();

private:
	// DUKPT state populated when any button is clicked
	dukpt_ui_mode_t mode;
	dukpt_ui_input_key_type_t inputKeyType;
	std::vector<std::uint8_t> inputKey;
	std::vector<std::uint8_t> ksn;

	// Derivation state populated when derivation button is clicked
	dukpt_ui_derivation_action_t derivationAction;
	dukpt_ui_key_type_t derivedKeyType;
	dukpt_ui_output_format_t outputFormat;
	std::vector<std::uint8_t> kbpk;

	// Validation and preparation functions for TDES DUKPT
	std::vector<std::uint8_t> prepareTdesInitialKey(bool full_ksn);
	std::vector<std::uint8_t> prepareTdesTxnKey();

	// Validation and preparation functions for AES DUKPT
	std::vector<std::uint8_t> prepareAesInitialKey(bool full_ksn);
	std::vector<std::uint8_t> prepareAesTxnKey();
	std::vector<std::uint8_t> prepareAesUpdateKey();
};

#endif