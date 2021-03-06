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

Currently these libraries only implement the host (direct) key derivations for
TDES and AES DUKPT. In addition to key derivation, these libraries also
implement the usage of the various working keys to ensure that the derivation
data used for the working key derivation match the usage of the derived
working key.

Dependencies
------------

* C11 compiler such as GCC or Clang
* [CMake](https://cmake.org/)
* DUKPT libraries require [MbedTLS](https://github.com/Mbed-TLS/mbedtls)
  (preferred), or [OpenSSL](https://www.openssl.org/)
* DUKPT tool requires `argp` (either via Glibc, a system-provided standalone
  implementation, or a downloaded implementation;
  see [MacOS / Windows](#macos--windows))
* DUKPT tool can _optionally_ use [tr31](https://github.com/openemv/tr31) if
  available at build-time (either install a release build or use `tr31_DIR` to
  find a local build)

This project also makes use of sub-projects that can either be provided as
git submodules using `git clone --recurse-submodules`, or provided as CMake
targets by a parent project:
* [OpenEMV common crypto abstraction](https://github.com/openemv/crypto)
* [OpenEMV PIN block library](https://github.com/openemv/pinblock)

Build
-----

This project uses CMake and can be built using the usual CMake steps.

To generate the build system in the `build` directory, use:
```
cmake -B build
```

To build the project, use:
```
cmake --build build
```

Consult the CMake documentation regarding additional options that can be
specified in the above steps.

Testing
-------

The tests can be run using the `test` target of the generated build system.

To run the tests using CMake, do:
```
cmake --build build --target test
```

If the CMake generator was `Unix Makefiles` (default on Linux), the tests can
can be run from within the build directory (`build` in the above
[Build](#build) steps) using:
```
make test
```

Documentation
-------------

If Doxygen was found by CMake, then HTML documentation can be generated using
the `docs` target of the generated build system.

To generate the documentation using CMake, do:
```
cmake --build build --target docs
```

If the CMake generator was `Unix Makefiles` (default on Linux), the
documentation can be generated from within the build directory (`build` in
the above [Build](#build) steps) using:
```
make docs
```

Alternatively, the `BUILD_DOCS` option can be specified when generating the
build system by adding `-DBUILD_DOCS=ON`.

Packaging
---------

If the required packaging tools were found (`dpkg` and/or `rpmbuild` on Linux)
by CMake, packages can be created using the `package` target of the generated
build system.

To generate the packages using CMake, do:
```
cmake --build build --target package
```

If the CMake generator was `Unix Makefiles` (default on Linux), the packages
can be generated from within the build directory (`build` in the above
[Build](#build) steps) using:
```
make package
```

This is an example of how monolithic release packages can be built from
scratch on Ubuntu or Fedora:
```
rm -Rf build &&
cmake -B build -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DCMAKE_INSTALL_PREFIX=/usr -DBUILD_SHARED_LIBS=YES -DBUILD_DOCS=YES -DCPACK_COMPONENTS_GROUPING=ALL_COMPONENTS_IN_ONE &&
cmake --build build &&
cmake --build build --target package
```

MacOS / Windows
---------------

On platforms such as MacOS or Windows where static linking is desirable and
dependencies such as MbedTLS or `argp` may be unavailable, the `FETCH_MBEDTLS`
and `FETCH_ARGP` options can be specified when generating the build system.

In addition, MacOS universal binaries can be built by specifying the desired
architectures using the `CMAKE_OSX_ARCHITECTURES` option.

This is an example of how a self-contained, static, universal binary can be
built from scratch for MacOS:
```
rm -Rf build &&
cmake -B build -DCMAKE_OSX_ARCHITECTURES="x86_64;arm64" -DCMAKE_BUILD_TYPE="RelWithDebInfo" -DFETCH_MBEDTLS=YES -DFETCH_ARGP=YES &&
cmake --build build
```

Usage
-----

The available command line options of the `dukpt-tool` application can be
displayed using:
```
dukpt-tool --help
```

To derive an initial key, specify the base derivation key using the `--bdk`
option, specify the initial key serial number using the `--ksn` option, and
use the `--derive-ik` option. For example (using test data examples from
ANSI X9.24-1:2009 Annex A.4 or ANSI X9.24-3:2017 Annex C.5):
```
dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00000 --derive-ik
```

To advance a key serial number, specify it using the `--ksn` option and use
the `--advance-ksn` option. For example (using test data examples from
ANSI X9.24-1:2009 Annex A.4 or ANSI X9.24-3:2017 Annex C.5):
```
dukpt-tool --ksn=FFFF9876543210EFFC00 --advance-ksn
```

To decrypt a TDES transaction request, specify the relevant key using either
the `--bdk` or `--ik` options, specify the key serial number using the `--ksn`
option, and specify the provide the encrypted transaction request using the
`--decrypt-request` option. For example (using test data examples from
ANSI X9.24-1:2009 Annex A.4 or ANSI X9.24-3:2017 Annex C.5):
```
dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00002 --decrypt-request A2B4E70F846E63D68775B7215EB4563DFD3037244C61CC13
```

To output raw bytes instead of hex digits to stdout, add the `--output-raw`
option. This can then be piped to another tool. For example (using test data
examples from ANSI X9.24-1:2009 Annex A.4 or ANSI X9.24-3:2017 Annex C.5):
```
dukpt-tool --bdk 0123456789ABCDEFFEDCBA9876543210 --ksn FFFF9876543210E00002 --decrypt-request A2B4E70F846E63D68775B7215EB4563DFD3037244C61CC13 --output-raw | strings
```

Roadmap
-------

* Implement transaction-originating algorithms (ANSI X9.24-3:2017, 6.5)
* Add CPack packaging for Windows and MacOS
* Test on various ARM architectures

License
-------

Copyright (c) 2021, 2022 [Leon Lynch](https://github.com/leonlynch).

This project is licensed under the terms of the LGPL v2.1 license. See LICENSE file.
