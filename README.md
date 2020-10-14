# The Cryptokit library

## Overview

The Cryptokit library for OCaml provides a variety of cryptographic primitives that can be used to implement cryptographic protocols in security-sensitive applications.  The primitives provided include:

* Symmetric-key ciphers: AES, Chacha20, DES, Triple-DES, Blowfish, ARCfour, in ECB, CBC, CFB, OFB and counter modes.
* Public-key cryptography: RSA encryption and signature, Diffie-Hellman key agreement.
* Hash functions and MACs: SHA-3, SHA-2, BLAKE2b, RIPEMD-160, and MACs based on AES and DES.  (SHA-1 and MD5, despite being broken, are also provided for historical value.)
* Random number generation.
* Encodings and compression: base 64, hexadecimal, Zlib compression.

Additional ciphers and hashes can easily be used in conjunction with the library.  In particular, basic mechanisms such as chaining modes, output buffering, and padding are provided by generic classes that can easily be composed with user-provided ciphers.  More generally, the library promotes a "Lego"-like style of constructing and composing transformations over character streams.

This library is distributed under the conditions of the GNU Library General Public license version 2, with the special OCaml exception on linking described in file LICENSE.

## Requirements

* OCaml 4.02 or more recent.
* The Dune build system, version 2.0 or more recent.
* The Zarith library, version 1.4 or more recent.
* The Zlib C library, version 1.1.3 or up is recommended. If it is not installed on your system (look for libz.a or libz.so), get it from http://www.gzip.org/, or indicate in the Makefile that you do not have it.  If you are running Linux or BSD or MacOS, your distribution provides precompiled binaries for this library.
* If the operating system does not provide the `/dev/random` device for random number generation, consider installing the [EGD](http://egd.sourceforge.net/) entropy gathering daemon.  Without `/dev/random` nor EGD, this library cannot generate cryptographically-strong random data nor RSA keys.  The remainder of the library still works, though.

## Build, test and install

* To configure, run `./configure`.  There are options to disable or enable some features (run `./configure --help` for a list), but the default configuration is fine most of the time.

* To build, run `dune build`.

* To execute a test, run `dune exec test/<name>.exe` where `<name>` can be `test`,
  `prngtest` or `speedtest`, supplying additional command line arguments if needed.
  The main test file `test/test.ml` is also included into the `runtest` alias, so it
  can be executed simply by `dune test`.

* To install, run `dune install`.

## Using the library

The package name is `cryptokit`.  With Dune, use `(library cryptokit)`.  With ocamlfind, do
```
        ocamlfind ocamlopt -package cryptokit ...             # for compilation
        ocamlfind ocamlopt -package cryptokit -linkpkg ...    # for linking
```

## Documentation

See the extensive documentation comments in file `src/cryptokit.mli`.

To build HTML documentation, run `dune build @doc`. The resulting index file is
located at `_build/default/_doc/_html/cryptokit/Cryptokit/index.html`.

## Warnings and disclaimers

Disclaimer 1: the author is not an expert in cryptography.  While reasonable care has been taken to select good, widely-used implementations of the ciphers and hashes, and follow recommended practices found in reputable applied cryptography textbooks, you are advised to review thoroughly the implementation of this module before using it in a security-critical application.

Disclaimer 2: some knowledge of cryptography is needed to use effectively this library.  A recommended reading is the [Handbook of Applied Cryptography](http://www.cacr.math.uwaterloo.ca/hac/).  Building secure applications out of cryptographic primitives also requires a general background in computer security.

Disclaimer 3: in some countries, the use, distribution, import and/or export of cryptographic applications is restricted by law. The precise restrictions may depend on the strenght of the cryptography used (e.g. key size), but also on its purpose (e.g. confidentiality vs. authentication).  It is up to the users of this library to comply with regulations applicable in their country.

## Design notes and references

The library is organized around the concept of "transforms".  A transform is an object that accepts strings, sub-strings, characters and bytes as input, transforms them, and buffers the output.  While it is possible to enter all input, then fetch the output, lower memory requirements can be achieved by purging the output periodically during data input.

The AES implementation is the public-domain optimized reference implementation by Daemen, Rijmen and Barreto.  On x86 processors that support the AES-NI extensions, hardware implementation is used instead.

The Chacha20 implementation is due to D.J.Bernstein, https://cr.yp.to/streamciphers/timings/estreambench/submissions/salsa20/chacha8/regs/chacha.c . It is in the public domain.

The DES implementation is based on Outerbridge's popular "d3des" implementation.  This is not the fastest DES implementation available, but one of the cleanest.  Outerbridge's code is marked as public domain.

The Blowfish implementation is that of Paul Kocher with some performance improvements.  It is under the LGPL.  It passes the test vectors listed at http://www.schneier.com/code/vectors.txt

ARCfour (``alleged RC4'') is implemented from scratch, based on the algorithm described in Schneier's _Applied Cryptography_

SHA-1 is also implemented from scratch, based on the algorithm described in the _Handbook of Applied Cryptography_.   It passes the FIPS test vectors.

SHA-2 is implemented from scratch based on FIPS publication 180-2.  It passes the FIPS test vectors.

SHA-3 is based on the "readable" implementation of Keccak written by Markku-Juhani O. Saarinen <mjos@iki.fi>.

BLAKE2b is implemented from scratch based on RFC 7693.  The test vectors are taken from https://github.com/BLAKE2/BLAKE2/tree/master/testvectors; others were obtained with the b2sum program.

RIPEMD-160 is based on the reference implementation by A.Bosselaers. It passes the test vectors listed at http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html

MD5 uses the public-domain implementation by Colin Plumb that is also used in the OCaml runtime system for module Digest.

RSA encryption and decryption was implemented from scratch, using the Zarith OCaml library for arbitrary-precision arithmetic, which itself uses GMP.  Modular  exponentiation is the constant-time implementation provided by GMP.  The Chinese remainder theorem is exploited when possible, though.  Like all ciphers in this library, the RSA implementation is *not* protected against timing attacks.

RSA key generation uses GMP's `nextprime` function for probabilistic primality testing.

The hardware RNG uses the RDRAND instruction of recent x86 processors, if supported.  It is not available on other platforms.  A check is included to reject the broken RDRAND on AMD Ryzen 3000 processors (https://arstechnica.com/gadgets/2019/10/how-a-months-old-amd-microcode-bug-destroyed-my-weekend/).

The seeded PRNG is just the Chacha20 stream cipher encrypting the all-zeroes message.  The seed is used as the Chacha20 key.  An alternate seeded PRNG is provided, based on AES encryption of a 128-bit counter.  Both PRNGs pass the Dieharder statistical tests.  Still, better use the system RNG or the hardware RNG if high-quality random numbers are needed.

## Performance

If you run `dune exec test/speedtest.exe`, a simple benchmark is performed and shows the speed of various operations from this library.
