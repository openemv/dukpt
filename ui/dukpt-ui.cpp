/**
 * @file dukpt-ui.cpp
 * @brief Simple DUKPT User Interface using Qt
 *
 * Copyright 2022 Leon Lynch
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

#include <QtWidgets/QApplication>

#include "dukpt_ui_config.h"
#include "mainwindow.h"

int main(int argc, char** argv)
{
	QApplication app(argc, argv);
	app.setOrganizationName("OpenEMV");
	app.setOrganizationDomain("openemv.org");
	app.setApplicationName("dukpt-ui");
	app.setApplicationVersion(DUKPT_UI_VERSION_STRING);
	app.setWindowIcon(QIcon(":icons/openemv_dukpt_512x512.png"));

	MainWindow mainwindow;
	mainwindow.show();

	return app.exec();
}
