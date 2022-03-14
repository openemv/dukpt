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
	SRC_URI="https://github.com/openemv/dukpt/archive/${PV}.tar.gz -> ${P}.tar.gz"
fi

LICENSE="LGPL-2.1"
SLOT="0"
KEYWORDS="~amd64 ~x86"
IUSE="doc test"

BDEPEND="
	doc? ( app-doc/doxygen )
"

RDEPEND="
	net-libs/mbedtls
"
DEPEND="
	${RDEPEND}
"

src_prepare() {
	cmake_src_prepare
}

src_configure() {
	local mycmakeargs=(
		-DBUILD_DOCS=$(usex doc)
		-DBUILD_TESTING=$(usex test)
	)

	cmake_src_configure
}

src_test() {
	cmake_src_test
}

DOCS=( README.md LICENSE )
