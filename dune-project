(lang dune 2.0)
(generate_opam_files true)

(name cryptokit)
(source (github xavierleroy/cryptokit))
(authors "Xavier Leroy")
(maintainers "Xavier Leroy <xavier.leroy@college-de-france.fr>")

(package
 (name cryptokit)
 (synopsis "A library of cryptographic primitives")

 (description "Cryptokit includes block ciphers (AES, DES, 3DES), stream ciphers
(ARCfour), public-key crypto (RSA, DH), hashes (SHA-1, SHA-256,
SHA-3), MACs, compression, random number generation -- all presented
with a compositional, extensible interface.")

 (depends
  (ocaml (>= 4.03.0))
  (dune (>= 2.0))
  dune-configurator
  (zarith (>= 1.4))
  conf-zlib
  conf-gmp-powm-sec))
