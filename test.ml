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

(* Test vectors *)

open Printf
open Cryptokit

(* Test harness *)

let error_occurred = ref false

let function_tested = ref ""

let testing_function s =
    function_tested := s;
    print_newline();
    print_string s;
    print_newline()

let test test_number answer correct_answer =
 flush stdout;
 flush stderr;
 if answer <> correct_answer then begin
   eprintf "*** Bad result (%s, test %d)\n" !function_tested test_number;
   flush stderr;
   error_occurred := true
 end else begin
   printf " %d..." test_number
 end

(* Useful auxiliaries *)

let hex s = transform_string (Hexa.decode()) s
let tohex s = transform_string (Hexa.encode()) s

(* Test hex conversion first... *)
let _ =
  testing_function "Hex conversion";
  test 1 "6162636465666768696a6b6c6d6e6f70710a"
         (transform_string (Hexa.encode()) "abcdefghijklmnopq\n");
  test 2 "abcdefghijklmnopq\n"
         (transform_string (Hexa.decode())
              "616263 64656667 \n 68696a6b 6c6d6e6f\t70710a")

(* Basic ciphers and hashes *)

(* AES *)
let _ =
  testing_function "AES";
  let res = String.create 16 in
  let c = new Block.aes_encrypt (hex "000102030405060708090A0B0C0D0E0F")
  and d = new Block.aes_decrypt (hex "000102030405060708090A0B0C0D0E0F") in
  let plain = hex "00112233445566778899AABBCCDDEEFF"
  and cipher = hex "69C4E0D86A7B0430D8CDB78070B4C55A" in
  c#transform plain 0 res 0; test 1 res cipher;
  d#transform cipher 0 res 0; test 2 res plain

(* DES *)
let _ =
  testing_function "DES";
  let res = String.create 8 in
  let c = new Block.des_encrypt (hex "0123456789abcdef")
  and d = new Block.des_decrypt (hex "0123456789abcdef") in
  let plain = hex "0123456789abcde7"
  and cipher = hex "c95744256a5ed31d" in
  c#transform plain 0 res 0; test 1 res cipher;
  d#transform cipher 0 res 0; test 2 res plain;
  let rec iter n key input =
    if n <= 0 then key else begin
      let c = new Block.des_encrypt key in
      let t1 = String.create 8 in c#transform input 0 t1 0;
      let t2 = String.create 8 in c#transform t1 0 t2 0;
      let d = new Block.des_decrypt t2 in
      let t3 = String.create 8 in d#transform t1 0 t3 0;
      iter (n-1) t3 t1
    end in
  test 3 (iter 64 (hex "5555555555555555") (hex "ffffffffffffffff"))
         (hex "246e9db9c550381a")

(* Triple DES *)
let _ =
  testing_function "Triple DES";
  let res = String.create 8 in
  let c = new Block.triple_des_encrypt (hex "0123456789abcdeffedcba9876543210")
  and d = new Block.triple_des_decrypt (hex "0123456789abcdeffedcba9876543210") in
  let plain = hex "0123456789abcde7"
  and cipher = hex "7f1d0a77826b8aff" in
  c#transform plain 0 res 0; test 1 res cipher;
  d#transform cipher 0 res 0; test 2 res plain;
  let c = new Block.triple_des_encrypt (hex "0123456789abcdef0123456789abcdef")
  and d = new Block.triple_des_decrypt (hex "0123456789abcdef0123456789abcdef") in
  let plain = hex "0123456789abcde7"
  and cipher = hex "c95744256a5ed31d" in
  c#transform plain 0 res 0; test 3 res cipher;
  d#transform cipher 0 res 0; test 4 res plain

(* ARCfour *)

let _ =
  testing_function "ARCfour";
  let do_test n1 n2 key input output =
    let key = hex key and input = hex input and output = hex output in
    let c = new Stream.arcfour key in
    let d = new Stream.arcfour key in
    let res = String.create (String.length input) in
    c#transform input 0 res 0 (String.length input);
    test n1 res output;
    d#transform output 0 res 0 (String.length output);
    test n2 res input in
  do_test 1 2 "0123456789abcdef" "0123456789abcdef" "75b7878099e0c596";
  do_test 3 4 "0123456789abcdef" "0000000000000000" "7494c2e7104b0879";
  do_test 5 6 "0000000000000000" "0000000000000000" "de188941a3375d3a";
  do_test 7 8 "ef012345" "00000000000000000000" "d6a141a7ec3c38dfbd61"

(* SHA-1 *)
let _ =
  testing_function "SHA-1";
  let hash s = hash_string (Hash.sha1()) s in
  test 1 (hash "") (hex "da39a3ee5e6b4b0d3255bfef95601890afd80709");
  test 2 (hash "a") (hex "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8");
  test 3 (hash "abc") (hex "a9993e364706816aba3e25717850c26c9cd0d89d");
  test 4 (hash "abcdefghijklmnopqrstuvwxyz") 
         (hex "32d10c7b8cf96570ca04ce37f2a19d84240d3a89");
  test 5 (hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
         (hex "84983E441C3BD26EBAAE4AA1F95129E5E54670F1");
  test 6 (hash (String.make 1000000 'a'))
         (hex "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F")

(* MD5 *)
let _ =
  testing_function "MD5";
  let hash s = hash_string (Hash.md5()) s in
  test 1 (hash "") (hex "D41D8CD98F00B204E9800998ECF8427E");
  test 2 (hash "a") (hex "0CC175B9C0F1B6A831C399E269772661");
  test 3 (hash "abc") (hex "900150983CD24FB0D6963F7D28E17F72");
  test 4 (hash "message digest")
         (hex "F96B697D7CB7938D525A2F31AAF161D0")

(* Chaining modes *)

open Cipher

let some_key = hex "0123456789abcdef"

let test_enc_dec testno cipher cleartext =
  let enc = cipher some_key Encrypt and dec = cipher some_key Decrypt in
  test testno (transform_string dec (transform_string enc cleartext))
              cleartext

let _ =
  testing_function "ECB";
  test_enc_dec 1 (des ~mode:ECB) "abcdefgh";
  test_enc_dec 2 (des ~mode:ECB) "abcdefgh01234567";
  test_enc_dec 3 (des ~mode:ECB ~pad:Padding.length) "0123456789";
  test_enc_dec 4 (des ~mode:ECB ~pad:Padding.length) "abcdefghijklmnopqrstuvwxyz";
  test_enc_dec 5 (des ~mode:ECB ~pad:Padding._8000) "0123456789";
  test_enc_dec 6 (des ~mode:ECB ~pad:Padding._8000) "abcdefghijklmnopqrstuvwxyz"

let _ =
  testing_function "CBC";
  test_enc_dec 1 (des ~mode:CBC) "abcdefgh";
  test_enc_dec 2 (des ~mode:CBC) "abcdefgh01234567";
  test_enc_dec 3 (des ~mode:CBC ~pad:Padding.length) "0123456789";
  test_enc_dec 4 (des ~mode:CBC ~pad:Padding.length) "abcdefghijklmnopqrstuvwxyz";
  test_enc_dec 5 (des ~mode:CBC ~pad:Padding.length ~iv:"#@#@#@#@") "0123456789";
  test_enc_dec 6 (des ~mode:CBC ~pad:Padding.length ~iv:"ABCDEFGH") "abcdefghijklmnopqrstuvwxyz"

let _ =
  testing_function "CFB 1";
  test_enc_dec 1 (des ~mode:(CFB 1)) "ab";
  test_enc_dec 2 (des ~mode:(CFB 1)) "abcd";
  test_enc_dec 3 (des ~mode:(CFB 1)) "abcdefgh01234567";
  test_enc_dec 4 (des ~mode:(CFB 1)) "abcdefghijklmnopqrstuvwxyz";
  test_enc_dec 5 (des ~mode:(CFB 1) ~iv:"#@#@#@#@") "abcdefghijklmnopqrstuvwxyz"

let _ =
  testing_function "CFB 4";
  test_enc_dec 1 (des ~mode:(CFB 4)) "abcd";
  test_enc_dec 2 (des ~mode:(CFB 4)) "abcdefgh01234567";
  test_enc_dec 3 (des ~mode:(CFB 4) ~pad:Padding._8000) "abcdefghijklmnopqrstuvwxyz"

let _ =
  testing_function "OFB 1";
  test_enc_dec 1 (des ~mode:(OFB 1)) "ab";
  test_enc_dec 2 (des ~mode:(OFB 1)) "abcd";
  test_enc_dec 3 (des ~mode:(OFB 1)) "abcdefgh01234567";
  test_enc_dec 4 (des ~mode:(OFB 1)) "abcdefghijklmnopqrstuvwxyz";
  test_enc_dec 5 (des ~mode:(OFB 1) ~iv:"#@#@#@#@") "abcdefghijklmnopqrstuvwxyz"

let _ =
  testing_function "OFB 8";
  test_enc_dec 1 (des ~mode:(OFB 8)) "abcdefgh";
  test_enc_dec 2 (des ~mode:(OFB 8)) "abcdefgh01234567";
  test_enc_dec 3 (des ~mode:(OFB 8) ~pad:Padding._8000) "abcdefghijklmnopqrstuvwxyz"

(* RSA *)

let some_rsa_key = {
  RSA.size = 512;
  RSA.n = hex "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000c0764797b8bec8972a0ed8c90a8c334dd049add0222c09d20be0a79e338910bcae422060906ae0221de3f3fc747ccf98aecc85d6edc52d93d5b7396776160525";
  RSA.e = hex "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
  RSA.d = hex "000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001ae36b7522f66487d9f4610d1550290ac202c929bedc7032cc3e02acf37e3ebc1f866ee7ef7a0868d23ae2b184c1abd6d4db8ea9bec046bd82803727f2888701";
  RSA.p = hex "0000000000000000000000000000000000000000000000000000000000000000df02b615fe15928f41b02b586b51c2c02260ca396818ca4cba60bb892465be35";
  RSA.q = hex "0000000000000000000000000000000000000000000000000000000000000000dceeb60d543518b4ac74834a0546c507f2e91e389a87e2f2becc6f8c67d1c931";
  RSA.dp = hex "000000000000000000000000000000000000000000000000000000000000000059487e99e375c38d732112d97d6de8687fdafc5b6b5fb16e7297d3bd1e435599";
  RSA.dq = hex "000000000000000000000000000000000000000000000000000000000000000061b550de6437774db0577718ed6c770724eee466b43114b5b69c43591d313281";
  RSA.qinv = hex "0000000000000000000000000000000000000000000000000000000000000000744c79c4b9bea97c25e563c9407a2d09b57358afe09af67d71f8198cb7c956b8"
}

let some_msg = "Supercalifragilistusexpialidolcius"

let test_same_message testno msg1 msg2 =
  test testno msg1 (String.sub msg2 (String.length msg2 - String.length msg1)
                                    (String.length msg1))

let _ =
  testing_function "RSA";
  (* Signature, no CRT *)
  test_same_message 1 some_msg 
    (RSA.unwrap_signature some_rsa_key (RSA.sign some_rsa_key some_msg));
  (* Signature, CRT *)
  test_same_message 2 some_msg
    (RSA.unwrap_signature some_rsa_key (RSA.sign_CRT some_rsa_key some_msg));
  (* Encryption, no CRT *)
  test_same_message 3 some_msg
    (RSA.decrypt some_rsa_key (RSA.encrypt some_rsa_key some_msg));
  (* Encryption, CRT *)
  test_same_message 4 some_msg
    (RSA.decrypt_CRT some_rsa_key (RSA.encrypt some_rsa_key some_msg));
  (* Same, with a home-made key *)
  let prng =
    new Random.pseudo_rng (hex "5b5e50dc5b6eaf5346eba8244e5666ac4dcd5409") in
  let key = RSA.new_key ~rng:prng 1024 in
  test_same_message 5 some_msg
    (RSA.unwrap_signature key (RSA.sign key some_msg));
  test_same_message 6 some_msg
    (RSA.unwrap_signature key (RSA.sign_CRT key some_msg));
  test_same_message 7 some_msg
    (RSA.decrypt key (RSA.encrypt key some_msg));
  test_same_message 8 some_msg
    (RSA.decrypt_CRT key (RSA.encrypt key some_msg));
  (* Same, with a home-made key of fixed public exponent *)
  let key = RSA.new_key ~rng:prng ~e:65537 1024 in
  test_same_message 9 some_msg
    (RSA.unwrap_signature key (RSA.sign key some_msg));
  test_same_message 10 some_msg
    (RSA.unwrap_signature key (RSA.sign_CRT key some_msg));
  test_same_message 11 some_msg
    (RSA.decrypt key (RSA.encrypt key some_msg));
  test_same_message 12 some_msg
    (RSA.decrypt_CRT key (RSA.encrypt key some_msg))

(* Base64 encoding *)

let _ =
  testing_function "Base64";
  test 1 
"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNr
IGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZv
eCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBv
dmVyIHRoZSBsYXp5IGRvZy4K
" (transform_string (Base64.encode_multiline())
"The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
");
  test 2
"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNr
IGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZv
eCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBv
dmVyIHRoZSBsYXp5IGRvZy4uCg==
" (transform_string (Base64.encode_multiline())
"The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog..
");
  test 3
"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNr
IGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZv
eCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBv
dmVyIHRoZSBsYXp5IGRvZy4uLgo=
" (transform_string (Base64.encode_multiline())
"The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog...
");
  test 4 
"The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
"
 (transform_string (Base64.decode())
"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNr
IGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZv
eCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBv
dmVyIHRoZSBsYXp5IGRvZy4K
");
  test 5
"The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog..
"
 (transform_string (Base64.decode())
"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNr
IGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZv
eCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBv
dmVyIHRoZSBsYXp5IGRvZy4uCg==
");
  test 6
"The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog...
"
 (transform_string (Base64.decode())
"VGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNr
IGJyb3duIGZveCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZv
eCBqdW1wcyBvdmVyIHRoZSBsYXp5IGRvZy4KVGhlIHF1aWNrIGJyb3duIGZveCBqdW1wcyBv
dmVyIHRoZSBsYXp5IGRvZy4uLgo=
");
  let binarytext = String.create 256 in
  for i = 0 to 255 do binarytext.[i] <- Char.chr i done;
  test 7 binarytext
    (transform_string (Base64.decode())
      (transform_string (Base64.encode_compact()) binarytext))

(* Compression *)

let _ =
  testing_function "Zlib compression";
  let text =
"The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
The quick brown fox jumps over the lazy dog.
" in
  test 1 text (transform_string (Zlib.uncompress()) (transform_string (Zlib.compress()) text))

(* End of tests *)

let _ =
  print_newline();
  if !error_occurred then begin
    printf "********* TEST FAILED ***********\n";
    exit 2 
  end else begin
    printf "All tests successful.\n";
    exit 0
  end

