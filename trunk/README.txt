(* OASIS_START *)
(* DO NOT EDIT (digest: 592916c399140f33e2d314e1d2389ed4) *)

cryptokit - Cryptographic primitives
====================================

This library provides a variety of cryptographic primitives that can be used
to implement cryptographic protocols in security-sensitive applications. The
primitives provided include:

- Symmetric-key ciphers: AES, DES, Triple-DES, ARCfour,
  in ECB, CBC, CFB and OFB modes.
- Public-key cryptography: RSA encryption, Diffie-Hellman key agreement. -
Hash functions and MACs: SHA-1, SHA-2, SHA-3, RIPEMD160, MD5,
  and MACs based on AES and DES.
- Random number generation. - Encodings and compression: base 64,
hexadecimal, Zlib compression.

Additional ciphers and hashes can easily be used in conjunction with the
library. In particular, basic mechanisms such as chaining modes, output
buffering, and padding are provided by generic classes that can easily be
composed with user-provided ciphers. More generally, the library promotes a
"Lego"-like style of constructing and composing transformations over
character streams.

See the file [INSTALL.txt](INSTALL.txt) for building and installation
instructions.

Copyright and license
---------------------

cryptokit is distributed under the terms of the GNU Lesser General Public
License version 2 with OCaml linking exception.

(* OASIS_STOP *)
