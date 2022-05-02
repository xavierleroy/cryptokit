(lang dune 2.5)
(generate_opam_files true)

(name cryptokit)
(source (github xavierleroy/cryptokit))
(authors "Xavier Leroy")
(maintainers "Xavier Leroy <xavier.leroy@college-de-france.fr>")

(package
 (name cryptokit)
 (synopsis "A library of cryptographic primitives")
 (version 1.18)
 (description "Cryptokit includes authenticated encryption (AES-GCM, Chacha20-Poly1305), block ciphers (AES, DES, 3DES), stream ciphers (Chacha20, ARCfour), public-key cryptography (RSA, DH), hashes (SHA-256, SHA-512, SHA-3, Blake2), MACs, compression, random number generation -- all presented with a compositional, extensible interface.")

(depends
  (ocaml (>= 4.08.0))
  (dune (>= 2.0))
  dune-configurator
  (zarith (>= 1.4))
  conf-zlib
  conf-gmp-powm-sec))
