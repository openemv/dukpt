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

#include "dukpt_tdes.h"
#include "dukpt_aes.h"

MainWindow::MainWindow(QWidget* parent)
: QMainWindow(parent)
{
	setupUi(this);

	modeComboBox->addItem("TDES", DUKPT_UI_MODE_TDES);
	modeComboBox->addItem("AES", DUKPT_UI_MODE_AES);

	inputKeyTypeComboBox->addItem("Base Derivation Key (BDK)", DUKPT_UI_INPUT_KEY_TYPE_BDK);
	inputKeyTypeComboBox->addItem("Initial Key (IK/IPEK)", DUKPT_UI_INPUT_KEY_TYPE_IK);
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
