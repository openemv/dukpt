DUKPT libraries and tools
=========================

[![License: LGPL-2.1](https://img.shields.io/github/license/openemv/dukpt)](https://www.gnu.org/licenses/old-licenses/lgpl-2.1.html)<br/>
[![Ubuntu build](https://github.com/openemv/dukpt/actions/workflows/ubuntu-build.yaml/badge.svg)](https://github.com/openemv/dukpt/actions/workflows/ubuntu-build.yaml)<br/>
[![Fedora build](https://github.com/openemv/dukpt/actions/workflows/fedora-build.yaml/badge.svg)](https://github.com/openemv/dukpt/actions/workflows/fedora-build.yaml)<br/>
[![MacOS build](https://github.com/openemv/dukpt/actions/workflows/macos-build.yaml/badge.svg)](https://github.com/openemv/dukpt/actions/workflows/macos-build.yaml)<br/>
[![Windows build](https://github.com/openemv/dukpt/actions/workflows/windows-build.yaml/badge.svg)](https://github.com/openemv/dukpt/actions/workflows/windows-build.yaml)<br/>

This project is an implementation of the ANSI X9.24-3:2017 standard for both
TDES and AES Derived Unique Key Per Transaction (DUKPT) key management. Given
that most uses of this standard involve dedicated security hardware, this
implementation is mostly for validation and debugging purposes.

If you wish to use these libraries for a project that is not compatible with
the terms of the LGPL v2.1 license, please contact the author for alternative
licensing options.

Features
--------

These libraries implement the host (direct) key derivation algorithms as well
as the transaction-originating device's key derivation algorithms for both
TDES and AES DUKPT. In addition to key derivation, these libraries also
implement the usage of the various working keys to ensure that the derivation
data used for the working key derivation match the usage of the derived
working key.

Example output
--------------
![Example of dukpt-tool usage](/dukpt-tool-example.png)
![Example of dukpt-ui using TDES](/dukpt-ui-example.png)
![Example of dukpt-ui using AES](/dukpt-ui-example2.png)
See [usage](#usage) for more examples.

Installation
------------

* For Ubuntu 20.04 LTS (Focal), 22.04 LTS (Jammy), or 24.04 LTS (Noble) install
  the appropriate [release package](https://github.com/openemv/dukpt/releases)
* For Fedora 41 or Fedora 42, install the appropriate
  [release package](https://github.com/openemv/dukpt/releases)
* For Gentoo, use the
  [OpenEMV overlay](https://github.com/openemv/openemv-overlay), set the
  keywords and useflags as needed, and install using
  `emerge --verbose --ask dukpt`
* For MacOS with [Homebrew](https://brew.sh/), use the
  [OpenEMV tap](https://github.com/openemv/homebrew-tap) and install using
  `brew install openemv/tap/dukpt`. After installation, the `Dukpt` application
  can be made available in Launchpad via a symlink using
  `ln -s $(brew --prefix dukpt)/Dukpt.app /Applications/`.
* For Windows, use the [installer](https://github.com/openemv/dukpt/releases).
* For other platforms, architectures or configurations, follow the build
  instructions below

Dependencies
------------

* C11 compiler such as GCC or Clang
* [CMake](https://cmake.org/)
* DUKPT libraries require [MbedTLS](https://github.com/Mbed-TLS/mbedtls)
  (preferred), or [OpenSSL](https://www.openssl.org/)
* `dukpt-tool` will be built by default and requires `argp` (either via Glibc,
  a system-provided standalone, or downloaded during the build from
  [libargp](https://github.com/leonlynch/libargp); see
  [MacOS / Windows](#macos--windows)). Use the `BUILD_DUKPT_TOOL` option to
  prevent `dukpt-tool` from being built and avoid the dependency on `argp`.
* `dukpt-tool` can _optionally_ use [tr31](https://github.com/openemv/tr31) if
  available at build-time (either install a release build or use `tr31_DIR` to
  find a local build)
* `dukpt-ui` can _optionally_ be built if [Qt](https://www.qt.io/) (see
  [Qt](#qt) for details) as well as [tr31](https://github.com/openemv/tr31) are
  available at build-time. If either are not available, `dukpt-ui` will not be
  built. Use the `BUILD_DUKPT_UI` option to ensure that `dukpt-ui` will be
  built.
* [Doxygen](https://github.com/doxygen/doxygen) can _optionally_ be used to
  generate API documentation if it is available; see
  [Documentation](#documentation)
* [bash-completion](https://github.com/scop/bash-completion) can _optionally_
  be used to generate bash completion for `dukpt-tool`
* [NSIS](https://nsis.sourceforge.io) can _optionally_ be used to generate a
  Windows installer for this project

This project also makes use of sub-projects that can either be provided as
git submodules using `git clone --recurse-submodules`, or provided as CMake
targets by a parent project:
* [OpenEMV common crypto abstraction](https://github.com/openemv/crypto)
* [OpenEMV PIN block library](https://github.com/openemv/pinblock)

Build
-----

This project uses CMake and can be built using the usual CMake steps.

To generate the build system in the `build` directory, use:
```shell
cmake -B build
```

To build the project, use:
```shell
cmake --build build
```

Consult the CMake documentation regarding additional options that can be
specified in the above steps.

Testing
-------

The tests can be run using the `test` target of the generated build system.

To run the tests using CMake, do:
```shell
cmake --build build --target test
```

Alternatively, [ctest](https://cmake.org/cmake/help/latest/manual/ctest.1.html)
can be used directly which also allows actions such as `MemCheck` to be
performed or the number of jobs to be set, for example:
```shell
ctest --test-dir build -T MemCheck -j 10
```

Documentation
-------------

If Doxygen was found by CMake, then HTML documentation can be generated using
the `docs` target of the generated build system.

To generate the documentation using CMake, do:
```shell
cmake --build build --target docs
```

Alternatively, the `BUILD_DOCS` option can be specified when generating the
build system by adding `-DBUILD_DOCS=YES`.

Packaging
---------

If the required packaging tools were found (`dpkg` and/or `rpmbuild` on Linux)
by CMake, packages can be created using the `package` target of the generated
build system.

To generate the packages using CMake, do:
```shell
cmake --build build --target package
```

Alternatively, [cpack](https://cmake.org/cmake/help/latest/manual/cpack.1.html)
can be used directly from within the build directory (`build` in the above
[Build](#build) steps).

This is an example of how monolithic release packages can be built from
scratch on Ubuntu or Fedora:
```shell
rm -Rf build &&
cmake -B build -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=YES -DBUILD_DOCS=YES -DCPACK_COMPONENTS_GROUPING=ALL_COMPONENTS_IN_ONE &&
cmake --build build &&
cmake --build build --target package
```

Qt
--

This project supports Qt 5.12.x, Qt 5.15.x, Qt 6.5.x and Qt 6.8.x (although it
may be possible to use other versions of Qt) when building the `dukpt-ui`
application. However, on some platforms it may be necessary to use the `QT_DIR`
option (and not the `Qt5_DIR` nor `Qt6_DIR` options) or `CMAKE_PREFIX_PATH`
option to specify the exact Qt installation to be used. For Qt6 it may also be
necessary for the Qt tools to be available in the executable PATH regardless of
the `QT_DIR` option.

If the Qt installation does not provide universal binaries for MacOS, it will
not be possible to build `dukpt-ui` as a universal binary for MacOS.

MacOS / Windows
---------------

On platforms such as MacOS or Windows where static linking is desirable and
dependencies such as MbedTLS or `argp` may be unavailable, the `FETCH_MBEDTLS`
and `FETCH_ARGP` options can be specified when generating the build system.

In addition, MacOS universal binaries can be built by specifying the desired
architectures using the `CMAKE_OSX_ARCHITECTURES` option.

This is an example of how a self-contained, static, universal binary can be
built from scratch for MacOS:
```shell
rm -Rf build &&
cmake -B build -DCMAKE_OSX_ARCHITECTURES="x86_64;arm64" -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DFETCH_MBEDTLS=YES -DFETCH_ARGP=YES &&
cmake --build build
```

On MacOS, a bundle can also be built using the `BUILD_MACOSX_BUNDLE` option and
packaged as a DMG installer. Assuming `tr31_DIR` and `QT_DIR` are already
appropriately set, this is an example of how a self-contained, static, native
bundle and installer can be built from scratch for MacOS:
```shell
rm -Rf build &&
cmake -B build -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DFETCH_MBEDTLS=YES -DFETCH_ARGP=YES -DBUILD_DUKPT_UI=YES -DBUILD_MACOSX_BUNDLE=YES &&
cmake --build build --target package
```

Usage
-----

The available command line options of the `dukpt-tool` application can be
displayed using:
```shell
dukpt-tool --help
```

To derive an initial key, specify the base derivation key using the `--bdk`
option, specify the initial key serial number using the `--ksn` option, and
use the `--derive-ik` option. For example (using test data examples from
ANSI X9.24-1:2009 Annex A.4 or ANSI X9.24-3:2017 Annex C.5):
```shell
dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00000 --derive-ik
```

To advance a key serial number, specify it using the `--ksn` option and use
the `--advance-ksn` option. For example (using test data examples from
ANSI X9.24-1:2009 Annex A.4 or ANSI X9.24-3:2017 Annex C.5):
```shell
dukpt-tool --ksn=FFFF9876543210EFFC00 --advance-ksn
```

To decrypt a TDES transaction request, specify the relevant key using either
the `--bdk` or `--ik` options, specify the key serial number using the `--ksn`
option, and specify the provide the encrypted transaction request using the
`--decrypt-request` option. For example (using test data examples from
ANSI X9.24-1:2009 Annex A.4 or ANSI X9.24-3:2017 Annex C.5):
```shell
dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00002 --decrypt-request A2B4E70F846E63D68775B7215EB4563DFD3037244C61CC13
```

To output raw bytes instead of hex digits to stdout, add the `--output-raw`
option. This can then be piped to another tool. For example (using test data
examples from ANSI X9.24-1:2009 Annex A.4 or ANSI X9.24-3:2017 Annex C.5):
```shell
dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00002 --decrypt-request A2B4E70F846E63D68775B7215EB4563DFD3037244C61CC13 --output-raw | strings
```

To output a key block (and if [tr31](https://github.com/openemv/tr31) support
was enabled at build-time), specify the Key Block Protection Key (KBPK) using
the `--output-tr31` option and the desired key block format version using the
`--output-tr31-format-version` option. In addition, a few optional header
blocks can also be added using options such as `--output-tr31-with-ksn` and
others. For example:
```shell
dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00000 --derive-ik --output-tr31 1D22BF32387C600AD97F9B97A51311AC --output-tr31-format-version B --output-tr31-with-ksn --output-tr31-with-kc --output-tr31-with-kp --output-tr31-with-ts
```

Roadmap
-------

* Test on various ARM architectures

License
-------

Copyright 2021-2025 [Leon Lynch](https://github.com/leonlynch).

This project is licensed under the terms of the LGPL v2.1 license with the
exception of `dukpt-tool` and `dukpt-ui` which are licensed under the terms of
the GPL v3 license.
See [LICENSE](https://github.com/openemv/dukpt/blob/master/LICENSE) and
[LICENSE.gpl](https://github.com/openemv/dukpt/blob/master/ui/LICENSE.gpl)
files.

This project includes [crypto](https://github.com/openemv/crypto) as a git
submodule and it is licensed under the terms of the MIT license. See
[LICENSE](https://github.com/openemv/crypto/blob/master/LICENSE) file.

This project includes [pinblock](https://github.com/openemv/pinblock) as a git
submodule and it is licensed under the terms of the LGPL v2.1 license. See
[LICENSE](https://github.com/openemv/pinblock/blob/master/LICENSE) file.

This project may download [libargp](https://github.com/leonlynch/libargp)
during the build and it is licensed under the terms of the LGPL v3 license. See
[LICENSE](https://github.com/leonlynch/libargp/blob/master/LICENSE) file.
