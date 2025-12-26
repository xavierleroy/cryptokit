(***********************************************************************)
(*                                                                     *)
(*                      The Cryptokit library                          *)
(*                                                                     *)
(*            Xavier Leroy, projet Cristal, INRIA Rocquencourt         *)
(*                                                                     *)
(*  Copyright 2002 Institut National de Recherche en Informatique et   *)
(*  en Automatique.  All rights reserved.  This file is distributed    *)
(*  under the terms of the GNU Library General Public License, with    *)
(*  the special exception on linking described in file LICENSE.        *)
(*                                                                     *)
(***********************************************************************)

(* $Id$ *)

(* Performance measurement *)

open Cryptokit

let time_fn msg fn =
  let start = Sys.time() in
  let rec do_time nrun =
    let res = fn () in
    let stop = Sys.time() in
    let t = stop -. start in
    if t < 0.5 then do_time (nrun + 1) else begin
      Printf.printf "%7.3f  %s\n%!" (t /. float nrun) msg;
      res
    end
  in do_time 1

let rec repeat n fn () =
  if n <= 1 then fn() else (ignore(fn()); repeat (n-1) fn ())

let raw_block_cipher cipher niter () =
  let msg = Bytes.create cipher#blocksize in
  for i = 1 to niter do
    cipher#transform msg 0 msg 0
  done

let raw_stream_cipher cipher niter blocksize () =
  let msg = Bytes.create blocksize in
  for i = 1 to niter do
    cipher#transform msg 0 msg 0 blocksize
  done

let transform tr niter blocksize () =
  let msg = Bytes.create blocksize in
  for i = 1 to niter do
    tr#put_substring msg 0 blocksize; ignore(tr#get_substring)
  done

let hash h niter blocksize () =
  let msg = Bytes.create blocksize in
  for i = 1 to niter do
    h#add_substring msg 0 blocksize
  done;
  ignore(h#result)

let rng r niter blocksize () =
  let buf = Bytes.create blocksize in
  for i = 1 to niter do
    r#random_bytes buf 0 blocksize
  done

let _ =
  time_fn "Raw AES 128, 64_000_000 bytes"
    (raw_block_cipher (new Block.aes_encrypt "0123456789ABCDEF") 4000000);
  time_fn "Raw AES 192, 64_000_000 bytes"
    (raw_block_cipher (new Block.aes_encrypt "0123456789ABCDEF01234567") 4000000);
  time_fn "Raw AES 256, 64_000_000 bytes"
    (raw_block_cipher (new Block.aes_encrypt "0123456789ABCDEF0123456789ABCDEF")  4000000);
  time_fn "Raw DES, 16_000_000 bytes"
    (raw_block_cipher (new Block.des_encrypt "01234567") 2000000);
  time_fn "Raw 3DES, 16_000_000 bytes"
    (raw_block_cipher (new Block.triple_des_encrypt "0123456789ABCDEF") 2000000);
  time_fn "Raw ARCfour, 64_000_000 bytes, 16-byte chunks"
    (raw_stream_cipher (new Stream.arcfour "0123456789ABCDEF") 4000000 16);
  time_fn "Raw ARCfour, 64_000_000 bytes, 64-byte chunks"
    (raw_stream_cipher (new Stream.arcfour "0123456789ABCDEF") 1000000 64);
  time_fn "Raw Chacha20, 64_000_000 bytes, 16-byte chunks"
    (raw_stream_cipher (new Stream.arcfour "0123456789ABCDEF") 4000000 16);
  time_fn "Raw Chacha20, 64_000_000 bytes, 64-byte chunks"
    (raw_stream_cipher (new Stream.arcfour "0123456789ABCDEF") 1000000 64);
  time_fn "Raw Blowfish 128, 64_000_000 bytes"
    (raw_block_cipher (new Block.blowfish_encrypt "0123456789ABCDEF")  8000000);
  time_fn "AES-GCM, 64_000_000 bytes"
    (transform (AEAD.aes_gcm ~iv:"0123456789AB" "0123456789ABCDEF" AEAD.Encrypt) 4000000 16);
  time_fn "Chacha20-Poly1305, 64_000_000 bytes"
    (transform (AEAD.chacha20_poly1305 ~iv:"0123456789AB" "0123456789ABCDEF" AEAD.Encrypt) 4000000 16);
  time_fn "Wrapped AES 128 CBC, 64_000_000 bytes"
    (transform (Cipher.aes "0123456789ABCDEF" Cipher.Encrypt) 4000000 16);
  time_fn "Wrapped AES 192 CBC, 64_000_000 bytes"
    (transform (Cipher.aes "0123456789ABCDEF01234567" Cipher.Encrypt) 4000000 16);
  time_fn "Wrapped AES 256 CBC, 64_000_000 bytes"
    (transform (Cipher.aes "0123456789ABCDEF0123456789ABCDEF" Cipher.Encrypt) 4000000 16);
  time_fn "Wrapped DES CBC, 16_000_000 bytes"
    (transform (Cipher.des "01234567" Cipher.Encrypt) 1000000 16);
  time_fn "Wrapped 3DES CBC, 16_000_000 bytes"
    (transform (Cipher.triple_des "0123456789ABCDEF" Cipher.Encrypt) 1000000 16);
  time_fn "Wrapped ARCfour, 64_000_000 bytes"
    (transform (Cipher.arcfour "0123456789ABCDEF" Cipher.Encrypt) 4000000 16);
  time_fn "Wrapped Chacha20, 64_000_000 bytes"
    (transform (Cipher.chacha20 "0123456789ABCDEF" Cipher.Encrypt) 4000000 16);
  time_fn "Wrapped Blowfish 128 CBC, 64_000_000 bytes"
    (transform (Cipher.blowfish "0123456789ABCDEF" Cipher.Encrypt) 4000000 16);
  time_fn "SHA-1, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.sha1()) 4000000 16);
  time_fn "SHA-256, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.sha256()) 4000000 16);
  time_fn "SHA-512, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.sha512()) 4000000 16);
  time_fn "SHA-512/256, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.sha512_256()) 4000000 16);
  time_fn "SHA-512/224, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.sha512_224()) 4000000 16);
  time_fn "SHA-3 256, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.sha3 256) 4000000 16);
  time_fn "SHA-3 512, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.sha3 512) 4000000 16);
  time_fn "BLAKE2b 512, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.blake2b 512) 4000000 16);
  time_fn "BLAKE2s 256, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.blake2s 256) 4000000 16);
  time_fn "BLAKE3, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.blake3 256) 4000000 16);
  time_fn "RIPEMD-160, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.ripemd160()) 4000000 16);
  time_fn "MD5, 64_000_000 bytes, 16-byte chunks"
    (hash (Hash.md5()) 4000000 16);
  time_fn "AES CMAC, 64_000_000 bytes, 16-byte chunks"
    (hash (MAC.aes_cmac "0123456789ABCDEF") 4000000 16);
  time_fn "HMAC-SHA1, 64_000_000 bytes, 16-byte chunks"
    (hash (MAC.hmac_sha1 "0123456789ABCDEF") 4000000 16);
  time_fn "HMAC-SHA256, 64_000_000 bytes, 16-byte chunks"
    (hash (MAC.hmac_sha256 "0123456789ABCDEF") 4000000 16);
  time_fn "SipHash 64, 64_000_000 bytes, 16-byte chunks"
    (hash (MAC.siphash "0123456789ABCDEF") 4000000 16);
  time_fn "SipHash 128, 64_000_000 bytes, 16-byte chunks"
    (hash (MAC.siphash128 "0123456789ABCDEF") 4000000 16);
  let prng = Random.pseudo_rng "supercalifragilistusexpialidolcius" in
  let (priv_key, pub_key) =
  time_fn "RSA key generation (2048 bits) x 10"
    (repeat 10 (fun () -> RSA.new_key ~rng:prng ~e:65537 2048)) in
  let plaintext = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ" in
  let ciphertext =
  time_fn "RSA public-key operation (2048 bits, exponent 65537) x 1000"
    (repeat 1000 (fun () -> RSA.encrypt pub_key plaintext)) in
  time_fn "RSA private-key operation (2048 bits) x 100"
    (repeat 100 (fun () -> ignore(RSA.decrypt priv_key ciphertext)));
  time_fn "RSA private-key operation with CRT (2048 bits) x 100"
    (repeat 100 (fun () -> ignore(RSA.decrypt_CRT priv_key ciphertext)));
  let module E256 = ECDSA(P256) in
  let hash = hash_string (Hash.sha256()) plaintext in
  let (priv_key, pub_key) =
  time_fn "ECDSA key generation (P256) x 100"
    (repeat 100 (fun () -> E256.new_key ~rng:prng ())) in
  let sg =
  time_fn "ECDSA signature (P256) x 100"
    (repeat 100 (fun () -> E256.sign ~rng:prng priv_key hash)) in
  let _ =
  time_fn "ECDSA verification (P256) x 100"
    (repeat 100 (fun () -> E256.verify pub_key sg hash)) in
  time_fn "PRNG, 64_000_000 bytes"
    (rng prng 1000000 64);
  time_fn "PRNG AES CTR, 64_000_000 bytes"
    (rng (Random.pseudo_rng_aes_ctr "supercalifragilistusexpialidolcius") 1000000 64);
  begin try
    let hr = Random.hardware_rng () in
    time_fn "Hardware RNG, 64_000_000 bytes"
      (rng hr 1000000 64)
  with Error No_entropy_source -> ()
  end;
  ()
