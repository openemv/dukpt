# Copyright 1999-2023 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=8

inherit cmake

DESCRIPTION="DUKPT libraries and tools"
HOMEPAGE="https://github.com/openemv/dukpt"
if [[ "${PV}" == *9999 ]] ; then
	inherit git-r3
	EGIT_REPO_URI="https://github.com/openemv/dukpt.git"
	EGIT_BRANCH="master"
else
	SRC_URI="https://github.com/openemv/dukpt/releases/download/${PV}/${P}-src.tar.gz -> ${P}.tar.gz"
fi

LICENSE="LGPL-2.1+ GPL-3"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="+mbedtls openssl qt5 qt6 +tr31 doc test"
REQUIRED_USE="
	^^ ( mbedtls openssl )
	qt5? ( tr31 )
	qt6? ( tr31 )
"
RESTRICT="!test? ( test )"

BDEPEND="
	doc? ( app-doc/doxygen )
"

RDEPEND="
	mbedtls? ( net-libs/mbedtls )
	openssl? ( dev-libs/openssl )
	qt5? (
		dev-qt/qtcore:5
		dev-qt/qtgui:5
		dev-qt/qtwidgets:5
	)
	qt6? (
		dev-qt/qtbase:6[gui,widgets]
	)
	tr31? ( >=dev-libs/tr31-0.5.1 )
"
DEPEND="
	${RDEPEND}
"

src_prepare() {
	cmake_src_prepare
}

src_configure() {
	# NOTE:
	# https://wiki.gentoo.org/wiki/Project:Qt/Policies states that when an
	# application optionally supports one of two Qt versions, it is allowed for
	# both qt5 and qt6 to be enabled and, if so, qt5 should be preferred.

	local mycmakeargs=(
		$(cmake_use_find_package mbedtls MbedTLS)
		$(cmake_use_find_package openssl OpenSSL)
		$(cmake_use_find_package qt5 Qt5)
		$(cmake_use_find_package qt6 Qt6)
		$(cmake_use_find_package tr31 tr31)
		-DBUILD_DOCS=$(usex doc)
		-DBUILD_TESTING=$(usex test)
	)
	if use qt5 || use qt6; then
		mycmakeargs+=( -DBUILD_DUKPT_UI=YES )
	fi

	cmake_src_configure
}

src_test() {
	cmake_src_test
}

DOCS=( README.md LICENSE ui/LICENSE.gpl )
