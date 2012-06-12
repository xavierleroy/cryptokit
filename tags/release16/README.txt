(* OASIS_START *)
(* DO NOT EDIT (digest: 2b665a99f48c402d82851ffc8430f1f3) *)
This is the README file for the cryptokit distribution.

Cryptographic primitives

This library provides a variety of cryptographic primitives that can be used
to implement cryptographic protocols in security-sensitive applications.  The
primitives provided include:

- Symmetric-key ciphers: AES, DES, Triple-DES, ARCfour,   in ECB, CBC, CFB
and OFB modes. - Public-key cryptography: RSA encryption, Diffie-Hellman key
agreement. - Hash functions and MACs: SHA-1, MD5, and MACs based on AES and
DES. - Random number generation. - Encodings and compression: base 64,
hexadecimal, Zlib compression.

Additional ciphers and hashes can easily be used in conjunction with the
library. In particular, basic mechanisms such as chaining modes, output
buffering, and padding are provided by generic classes that can easily be
composed with user-provided ciphers. More generally, the library promotes a
"Lego"-like style of constructing and composing transformations over
character streams.

See the files INSTALL.txt for building and installation instructions. 


(* OASIS_STOP *)

EXTRA REQUIREMENTS:

  - The Zlib C library, version 1.1.3 or up is recommended.
    If it is not installed on your system (look for libz.a or libz.so),
    get it from http://www.gzip.org/, or call configure with the flag
    "--disable-zlib".
    If you are running Linux or BSD, chances are that your distribution
    provides precompiled binaries for this library.

  - If the operating system does not provide the /dev/random device
    (for random number generation), consider installing the EGD
    entropy gathering daemon http://egd.sourceforge.net/
    Without /dev/random nor EGD, this library cannot generate random data
    and RSA keys.  The remainder of the library still works, though.

WARNINGS AND DISCLAIMERS:

  Disclaimer 1: the author is not an expert in cryptography.
  While reasonable care has been taken to select good, widely-used
  implementations of the ciphers and hashes, and follow recommended
  practices found in reputable applied cryptography textbooks,
  you are advised to review thoroughly the implementation of this module
  before using it in a security-critical application.

  Disclaimer 2: some knowledge of cryptography is needed to use
  effectively this library.  A recommended reading is the
  Handbook of Applied Cryptography http://www.cacr.math.uwaterloo.ca/hac/
  Building secure applications out of cryptographic primitives also
  requires a general background in computer security.

  Disclaimer 3: in some countries, the use, distribution, import
  and/or export of cryptographic applications is restricted by law.
  The precise restrictions may depend on the strenght of the cryptography
  used (e.g. key size), but also on its purpose (e.g. confidentiality
  vs. authentication).  It is up to the users of this library to
  comply with regulations applicable in their country.


DESIGN NOTES AND REFERENCES:

  The library is organized around the concept of "transforms".  A transform
  is an object that accepts strings, sub-strings, characters and bytes
  as input, transforms them, and buffers the output.  While it is possible
  to enter all input, then fetch the output, lower memory requirements
  can be achieved by purging the output periodically during data input.

  The AES implementation is the public-domain optimized reference
  implementation by Daemen, Rijmen and Barreto.

  The DES implementation is based on Outerbridge's popular "d3des"
  implementation.  This is not the fastest DES implementation available,
  but one of the cleanest.  Outerbridge's code is marked as public domain.

  The Blowfish implementation is that of Paul Kocher with some
  performance improvements.  It is under the LGPL.  It passes the
  test vectors listed at http://www.schneier.com/code/vectors.txt

  ARCfour (``alleged RC4'') is implemented from scratch, based on the
  algorithm described in Schneier's _Applied_Cryptography_

  SHA-1 is also implemented from scratch, based on the algorithm
  described in the _Handbook_of_Applied_Cryptography_.   It passes the
  FIPS test vectors.

  SHA-256 is implemented from scratch based on FIPS publication 180-2.
  It passes the FIPS test vectors.

  RIPEMD-160 is based on the reference implementation by A.Bosselaers.
  It passes the test vectors listed at
     http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html

  MD5 uses the public-domain implementation by Colin Plumb that is also
  used in the OCaml runtime system for module Digest.

  RSA encryption and decryption was implemented from scratch, using
  OCaml's bignum library for arbitrary-precision arithmetic.  Modular
  exponentiation uses the trivial Russian peasant algorithm, because the
  bignum library does not support Montgomery modular multiplication.
  The Chinese remainder theorem is exploited when possible, though.
  Like all ciphers in this library, the RSA implementation is *not*
  protected against timing attacks.

  RSA key generation follows the algorithms used in PGP 2.6.3.
  Probabilistic primality testing is achieved by Fermat tests using the
  first 8 prime numbers.  While not as good on paper as a Miller-Rabin
  probabilistic primality test, this seems good enough for PGP, so it
  should be good enough for us.

  The seeded PRNG is a combination of AES encryption in CBC mode and a lagged
  Fibonacci generator with long period.  It appears to pass the Diehard
  statistical tests.  Still, better to use the system RNG if high-quality
  random numbers are needed.


PERFORMANCE:

Some performance figures measured on a Pentium 4 2Ghz:

  AES 128: raw encryption  39 Mbyte/s; with CBC and buffering  15 Mbytes/s
  AES 192: raw encryption  34 Mbyte/s; with CBC and buffering  14 Mbytes/s
  AES 256: raw encryption  29 Mbyte/s; with CBC and buffering  13 Mbytes/s
      DES: raw encryption  19 Mbyte/s; with CBC and buffering   8 Mbytes/s
     3DES: raw encryption 6.5 Mbyte/s; with CBC and buffering 4.5 Mbytes/s
     ARC4: raw encryption  57 Mbyte/s; with buffering          47 Mbytes/s
     SHA1: 31 Mbyte/s
   SHA256: 21 Mbyte/s
RIPEMD160: 21 Mbyte/s
      MD5: 53 Mbyte/s
  AES MAC: 20 Mbyte/s
 RSA 1024: key generation 120 ms
           public-key operation (public exponent 65537) 0.70 ms
           private-key operation 29 ms
           private-key operation with CRT 9 ms
