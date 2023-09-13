/**
 * @file mainwindow.h
 * @brief Main window of DUKPT User Interface
 *
 * Copyright (c) 2022, 2023 Leon Lynch
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
	DukptKsnStringValidator* ksnValidator;
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
		DUKPT_UI_DERIVATION_ACTION_NONE = 1,
		DUKPT_UI_DERIVATION_ACTION_IK,
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
		DUKPT_UI_KEY_TYPE_HMAC128,
		DUKPT_UI_KEY_TYPE_HMAC192,
		DUKPT_UI_KEY_TYPE_HMAC256,
	};
	dukpt_ui_key_type_t getDerivedKeyType() const;
	void selectDerivedKeyType(dukpt_ui_key_type_t derivedKeyType);
	void updateDerivedKeyTypes(dukpt_ui_derivation_action_t derivationAction);
	dukpt_ui_key_type_t getEncryptDecryptKeyType() const;
	void selectEncryptDecryptKeyType(dukpt_ui_key_type_t encryptDecryptKeyType);
	void updateEncryptDecryptKeyTypes(dukpt_ui_mode_t mode);
	dukpt_ui_key_type_t getMacKeyType() const;
	void selectMacKeyType(dukpt_ui_key_type_t macKeyType);
	void updateMacKeyTypes(dukpt_ui_mode_t mode);

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
		DUKPT_UI_MAC_ACTION_RETAIL_MAC_REQUEST = 1,
		DUKPT_UI_MAC_ACTION_RETAIL_MAC_RESPONSE,
		DUKPT_UI_MAC_ACTION_CMAC_REQUEST,
		DUKPT_UI_MAC_ACTION_CMAC_RESPONSE,
		DUKPT_UI_MAC_ACTION_HMAC_SHA256_REQUEST,
		DUKPT_UI_MAC_ACTION_HMAC_SHA256_RESPONSE,
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
	void logDigitVector(QString&& str, std::vector<std::uint8_t> v);

	struct Tr31Settings {
		std::vector<std::uint8_t> kbpk;
		bool tr31WithKsn;
		bool tr31WithKc;
		bool tr31WithKp;
		bool tr31WithLb;
		QString label;
		bool tr31WithTs;

		void capture(const MainWindow* mw);
		void restore(MainWindow* mw) const;
	};

private slots: // connect-by-name helper functions for validation
	void updateValidationStyleSheet(QLineEdit* edit);
	void updateValidationStyleSheet(const QValidator* validator, QPlainTextEdit* edit);
	void on_inputKeyEdit_textChanged(const QString&) { updateValidationStyleSheet(inputKeyEdit); }
	void on_ksnEdit_textChanged(const QString&) { updateValidationStyleSheet(ksnEdit); }
	void on_kbpkEdit_textChanged(const QString&) { updateValidationStyleSheet(kbpkEdit); }
	void on_pinEdit_textChanged(const QString&) { updateValidationStyleSheet(pinEdit); }
	void on_panEdit_textChanged(const QString&) { updateValidationStyleSheet(panEdit); }
	void on_dataEdit_textChanged() { updateValidationStyleSheet(dataValidator, dataEdit); }
	void on_ivEdit_textChanged(const QString&) { updateValidationStyleSheet(ivEdit); }
	void on_macEdit_textChanged() { updateValidationStyleSheet(macValidator, macEdit); }
	void on_keyValidator_changed() { updateValidationStyleSheet(inputKeyEdit); updateValidationStyleSheet(kbpkEdit); }
	void on_ksnValidator_changed() { updateValidationStyleSheet(ksnEdit); }
	void on_blockValidator_changed() { updateValidationStyleSheet(pinEdit); updateValidationStyleSheet(ivEdit); }
	void on_dataValidator_changed() { updateValidationStyleSheet(dataValidator, dataEdit); }

private slots: // connect-by-name helper functions for combo boxes
	void on_modeComboBox_currentIndexChanged(int index);
	void on_inputKeyTypeComboBox_currentIndexChanged(int index);
	void on_derivationActionComboBox_currentIndexChanged(int index);
	void on_outputFormatComboBox_currentIndexChanged(int index);
	void on_pinActionComboBox_currentIndexChanged(int index);

private slots: // connect-by-name helper functions for check boxes
	void on_tr31LbCheckBox_stateChanged(int state);
	void on_tr31TsCheckBox_stateChanged(int state);

private slots: // connect-by-name helper functions for push buttons
	void on_ksnAdvancePushButton_clicked();
	void on_tr31TsNowPushButton_clicked();
	void on_keyDerivationPushButton_clicked();
	void on_encryptDecryptPushButton_clicked();
	void on_macPushButton_clicked();

private slots: // connect-by-name helper functions for output
	void on_outputText_linkActivated(const QString& link);

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

	// Encrypt/decrypt state populated when encrypt/decrypt button is clicked
	dukpt_ui_key_type_t encryptDecryptKeyType;
	dukpt_ui_pin_action_t pinAction;
	std::vector<std::uint8_t> pan;
	dukpt_ui_data_action_t dataAction;
	std::vector<std::uint8_t> encDecData;
	std::vector<std::uint8_t> iv;

	// MAC state populated when MAC button is clicked
	dukpt_ui_key_type_t macKeyType;
	dukpt_ui_mac_action_t macAction;
	std::vector<std::uint8_t> macData;

	// KSN helper function
	int advanceKSN();

	// Validation and preparation functions for TDES DUKPT
	std::vector<std::uint8_t> prepareTdesInitialKey(bool full_ksn);
	std::vector<std::uint8_t> prepareTdesTxnKey();

	// Validation and preparation functions for AES DUKPT
	std::vector<std::uint8_t> prepareAesInitialKey(bool full_ksn);
	std::vector<std::uint8_t> prepareAesTxnKey();
	std::vector<std::uint8_t> prepareAesUpdateKey();
	int prepareAesKeyType(dukpt_ui_key_type_t uiKeyType);
	int prepareCmacKeyType(dukpt_ui_key_type_t uiKeyType);
	int prepareHmacKeyType(dukpt_ui_key_type_t uiKeyType);

	// Other validation and preparation functions
	bool validateTxnData(const std::vector<std::uint8_t>& txnData);
	bool prepareIv();

	// TR-31 helper functions
	bool outputTr31InputKey(const Tr31Settings& settings);
	QString exportTr31(unsigned int key_usage, const std::vector<std::uint8_t>& keyData, const Tr31Settings& settings);

	// Encrypt/decrypt helper functions
	std::vector<std::uint8_t> encryptPin(const std::vector<std::uint8_t>& txnKey, const std::vector<std::uint8_t>& pin);
	std::vector<std::uint8_t> decryptPin(const std::vector<std::uint8_t>& txnKey, const std::vector<std::uint8_t>& encryptedPin);
	std::vector<std::uint8_t> encryptRequest(const std::vector<std::uint8_t>& txnKey);
	std::vector<std::uint8_t> decryptRequest(const std::vector<std::uint8_t>& txnKey);
	std::vector<std::uint8_t> encryptResponse(const std::vector<std::uint8_t>& txnKey);
	std::vector<std::uint8_t> decryptResponse(const std::vector<std::uint8_t>& txnKey);

	// MAC helper functions
	std::vector<std::uint8_t> macRequest(const std::vector<std::uint8_t>& txnKey);
	std::vector<std::uint8_t> macResponse(const std::vector<std::uint8_t>& txnKey);
	std::vector<std::uint8_t> cmacRequest(const std::vector<std::uint8_t>& txnKey);
	std::vector<std::uint8_t> cmacResponse(const std::vector<std::uint8_t>& txnKey);
	std::vector<std::uint8_t> hmacRequest(const std::vector<std::uint8_t>& txnKey);
	std::vector<std::uint8_t> hmacResponse(const std::vector<std::uint8_t>& txnKey);
};

#endif
