# Copyright 1999-2026 Gentoo Authors
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

LICENSE="LGPL-2.1+ tools? ( GPL-3+ ) gui? ( GPL-3+ )"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="+mbedtls openssl +tools +tr31 gui doc test"
REQUIRED_USE="
	^^ ( mbedtls openssl )
	gui? ( tr31 )
"
RESTRICT="!test? ( test )"

BDEPEND="
	doc? ( app-text/doxygen )
"

RDEPEND="
	mbedtls? ( net-libs/mbedtls )
	openssl? ( dev-libs/openssl )
	gui? ( dev-qt/qtbase:6[gui,widgets] )
	tr31? ( >=dev-libs/tr31-0.6.0 )
"
DEPEND="
	${RDEPEND}
"

src_prepare() {
	cmake_src_prepare

	# Remove dirty suffix because Gentoo modifies CMakeLists.txt
	sed -i -e 's/--dirty//' CMakeLists.txt || die "Failed to remove dirty suffix"
}

src_configure() {
	# NOTE:
	# https://wiki.gentoo.org/wiki/Project:Qt/Policies recommends that Qt5
	# support should be dropped and that USE=gui should be used instead.

	local mycmakeargs=(
		$(cmake_use_find_package mbedtls MbedTLS)
		$(cmake_use_find_package openssl OpenSSL)
		-DBUILD_DUKPT_TOOL=$(usex tools)
		$(cmake_use_find_package tr31 tr31)
		-DCMAKE_DISABLE_FIND_PACKAGE_Qt5=YES
		$(cmake_use_find_package gui Qt6)
		-DBUILD_DUKPT_UI=$(usex gui)
		-DBUILD_DOCS=$(usex doc)
		-DBUILD_TESTING=$(usex test)
	)

	cmake_src_configure
}

src_test() {
	cmake_src_test
}

DOCS=( README.md LICENSE ui/LICENSE.gpl )
