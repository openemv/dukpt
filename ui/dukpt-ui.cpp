/**
 * @file dukpt-ui.cpp
 * @brief Simple DUKPT User Interface using Qt
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

#include <QtWidgets/QApplication>

int main(int argc, char** argv)
{
	QApplication app(argc, argv);
	app.setOrganizationName("OpenEMV");
	app.setOrganizationDomain("openemv.org");
	app.setApplicationName("dukpt-ui");

	return app.exec();
}
