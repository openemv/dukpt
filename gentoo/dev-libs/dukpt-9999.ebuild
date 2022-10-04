# Copyright 1999-2022 Gentoo Authors
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

LICENSE="LGPL-2.1"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="+mbedtls openssl qt5 +tr31 doc test"
REQUIRED_USE="
	^^ ( mbedtls openssl )
	qt5? ( tr31 )
"

BDEPEND="
	doc? ( app-doc/doxygen )
"

RDEPEND="
	mbedtls? ( net-libs/mbedtls )
	openssl? ( dev-libs/openssl:0/1.1 )
	qt5? (
		dev-qt/qtcore:5
		dev-qt/qtgui:5
		dev-qt/qtwidgets:5
	)
	tr31? ( >=dev-libs/tr31-0.4.3 )
"
DEPEND="
	${RDEPEND}
"

src_prepare() {
	cmake_src_prepare
}

src_configure() {
	local mycmakeargs=(
		$(cmake_use_find_package mbedtls MbedTLS)
		$(cmake_use_find_package openssl OpenSSL)
		$(cmake_use_find_package qt5 Qt5)
		$(cmake_use_find_package tr31 tr31)
		-DBUILD_DOCS=$(usex doc)
		-DBUILD_DUKPT_UI=$(usex qt5)
		-DBUILD_TESTING=$(usex test)
	)

	cmake_src_configure
}

src_test() {
	cmake_src_test
}

DOCS=( README.md LICENSE )
