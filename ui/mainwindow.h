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

class MainWindow : public QMainWindow, private Ui::MainWindow
{
	Q_OBJECT

public:
	explicit MainWindow(QWidget* parent = nullptr);

private: // helper enums and getter functions
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

private slots: // connect-by-name
	void on_keyDerivationPushButton_clicked();
	void on_encryptDecryptPushButton_clicked();
	void on_macPushButton_clicked();
};

#endif
