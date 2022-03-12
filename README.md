DUKPT library and tools
=======================

This library is an implementation of the ANSI X9.24-3:2017 standard for both
TDES and AES Derived Unique Key Per Transaction (DUKPT) key management. Given
that most uses of this standard involve dedicated security hardware, this
implementation is mostly for validation and debugging purposes.

If you wish to use this library for a project that is not compatible with the
terms of the LGPL v2.1 license, please contact the author for alternative
licensing options.

Features
========

Currently this library only implements the host (direct) key derivations for
TDES and AES DUKPT. In addition to key derivation, this library also
implements the usage of the various working keys to ensure that the derivation
data used for the working key derivation match the usage of the derived
working key.

Dependencies
============

* C11 compiler such as GCC or Clang
* CMake
* DUKPT libraries require MbedTLS
* DUKPT tool requires argp (either via Glibc or a standalone implementation)

Build
=====

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
=======

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
=============

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

Usage:
======

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
=======

* Implement transaction-originating algorithms (ANSI X9.24-3:2017, 6.5)

License
=======

Copyright (c) 2021, 2022 Leon Lynch.

This project is licensed under the terms of the LGPL v2.1 license. See LICENSE file.
