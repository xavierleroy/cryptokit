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

(* Whether to run the most expensive tests or not *)

let long_tests = ref false

(* Useful auxiliaries *)

let hex s = transform_string (Hexa.decode()) s
let hexbytes s = Bytes.of_string (hex s)
let tohex s = transform_string (Hexa.encode()) s

(* Test hex conversion first... *)
let _ =
  testing_function "Hex conversion";
  test 1 "6162636465666768696a6b6c6d6e6f70710a"
         (tohex "abcdefghijklmnopq\n");
  test 2 "abcdefghijklmnopq\n"
         (hex "616263 64656667 \n 68696a6b 6c6d6e6f\t70710a")

(* Basic ciphers and hashes *)

(* AES *)
let _ =
  testing_function "AES";
  let res = Bytes.create 16 in
  let do_test key plain cipher testno1 testno2 =
    let c = new Block.aes_encrypt (hex key)
    and d = new Block.aes_decrypt (hex key) in
    let plain = hexbytes plain
    and cipher = hexbytes cipher in
    c#transform plain 0 res 0;  test testno1 res cipher;
    d#transform cipher 0 res 0; test testno2 res plain in
  do_test
    "000102030405060708090A0B0C0D0E0F"
    "00112233445566778899AABBCCDDEEFF"
    "69C4E0D86A7B0430D8CDB78070B4C55A"
    1 2;
  do_test
    "000102030405060708090A0B0C0D0E0F1011121314151617"
    "00112233445566778899AABBCCDDEEFF"
    "DDA97CA4864CDFE06EAF70A0EC0D7191"
    3 4;
  do_test
    "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    "00112233445566778899AABBCCDDEEFF"
    "8EA2B7CA516745BFEAFC49904B496089"
    5 6

(* Blowfish *)

let _ =
  testing_function "Blowfish";
  let res = Bytes.create 16 in
  let do_test key plain cipher testno =
    let c = new Block.blowfish_encrypt (hex key)
    and d = new Block.blowfish_decrypt (hex key) in
    let plain = hexbytes plain
    and cipher = hexbytes cipher in
    c#transform plain 0 res 0;
    d#transform cipher 0 res 8;
    test testno res (Bytes.cat cipher plain) in
  do_test "0000000000000000" "0000000000000000" "4EF997456198DD78" 1;
  do_test "FFFFFFFFFFFFFFFF" "FFFFFFFFFFFFFFFF" "51866FD5B85ECB8A" 2;
  do_test "3000000000000000" "1000000000000001" "7D856F9A613063F2" 3;
  do_test "1111111111111111" "1111111111111111" "2466DD878B963C9D" 4;
  do_test "0123456789ABCDEF" "1111111111111111" "61F9C3802281B096" 5;
  do_test "1111111111111111" "0123456789ABCDEF" "7D0CC630AFDA1EC7" 6;
  do_test "0000000000000000" "0000000000000000" "4EF997456198DD78" 7;
  do_test "FEDCBA9876543210" "0123456789ABCDEF" "0ACEAB0FC6A0A28D" 8;
  do_test "7CA110454A1A6E57" "01A1D6D039776742" "59C68245EB05282B" 9;
  do_test "0131D9619DC1376E" "5CD54CA83DEF57DA" "B1B8CC0B250F09A0" 10;
  do_test "07A1133E4A0B2686" "0248D43806F67172" "1730E5778BEA1DA4" 11;
  do_test "3849674C2602319E" "51454B582DDF440A" "A25E7856CF2651EB" 12;
  do_test "04B915BA43FEB5B6" "42FD443059577FA2" "353882B109CE8F1A" 13;
  do_test "0113B970FD34F2CE" "059B5E0851CF143A" "48F4D0884C379918" 14;
  do_test "0170F175468FB5E6" "0756D8E0774761D2" "432193B78951FC98" 15;
  do_test "43297FAD38E373FE" "762514B829BF486A" "13F04154D69D1AE5" 16;
  do_test "07A7137045DA2A16" "3BDD119049372802" "2EEDDA93FFD39C79" 17;
  do_test "04689104C2FD3B2F" "26955F6835AF609A" "D887E0393C2DA6E3" 18;
  do_test "37D06BB516CB7546" "164D5E404F275232" "5F99D04F5B163969" 19;
  do_test "1F08260D1AC2465E" "6B056E18759F5CCA" "4A057A3B24D3977B" 20;
  do_test "584023641ABA6176" "004BD6EF09176062" "452031C1E4FADA8E" 21;
  do_test "025816164629B007" "480D39006EE762F2" "7555AE39F59B87BD" 22;
  do_test "49793EBC79B3258F" "437540C8698F3CFA" "53C55F9CB49FC019" 23;
  do_test "4FB05E1515AB73A7" "072D43A077075292" "7A8E7BFA937E89A3" 24;
  do_test "49E95D6D4CA229BF" "02FE55778117F12A" "CF9C5D7A4986ADB5" 25;
  do_test "018310DC409B26D6" "1D9D5C5018F728C2" "D1ABB290658BC778" 26;
  do_test "1C587F1C13924FEF" "305532286D6F295A" "55CB3774D13EF201" 27;
  do_test "0101010101010101" "0123456789ABCDEF" "FA34EC4847B268B2" 28;
  do_test "1F1F1F1F0E0E0E0E" "0123456789ABCDEF" "A790795108EA3CAE" 29;
  do_test "E0FEE0FEF1FEF1FE" "0123456789ABCDEF" "C39E072D9FAC631D" 30;
  do_test "0000000000000000" "FFFFFFFFFFFFFFFF" "014933E0CDAFF6E4" 31;
  do_test "FFFFFFFFFFFFFFFF" "0000000000000000" "F21E9A77B71C49BC" 32;
  do_test "0123456789ABCDEF" "0000000000000000" "245946885754369A" 33;
  do_test "FEDCBA9876543210" "FFFFFFFFFFFFFFFF" "6B5C5A9C5D9E0A5A" 34

(* DES *)
let _ =
  testing_function "DES";
  let res = Bytes.create 8 in
  let c = new Block.des_encrypt (hex "0123456789abcdef")
  and d = new Block.des_decrypt (hex "0123456789abcdef") in
  let plain = hexbytes "0123456789abcde7"
  and cipher = hexbytes "c95744256a5ed31d" in
  c#transform plain 0 res 0; test 1 res cipher;
  d#transform cipher 0 res 0; test 2 res plain;
  let rec iter n key input =
    if n <= 0 then key else begin
      let c = new Block.des_encrypt key in
      let t1 = Bytes.create 8 in c#transform input 0 t1 0;
      let t2 = Bytes.create 8 in c#transform t1 0 t2 0;
      let d = new Block.des_decrypt (Bytes.unsafe_to_string t2) in
      let t3 = Bytes.create 8 in d#transform t1 0 t3 0;
      iter (n-1) (Bytes.unsafe_to_string t3) t1
    end in
  test 3 (iter 64 (hex "5555555555555555")
                  (hexbytes "ffffffffffffffff"))
         (hex "246e9db9c550381a")

(* Triple DES *)
let _ =
  testing_function "Triple DES";
  let res = Bytes.create 8 in
  let do_test key plain cipher testno1 testno2 =
    let c = new Block.triple_des_encrypt (hex key)
    and d = new Block.triple_des_decrypt (hex key) in
    let plain = hexbytes plain
    and cipher = hexbytes cipher in
    c#transform plain 0 res 0; test testno1 res cipher;
    d#transform cipher 0 res 0; test testno2 res plain in
  do_test
    "0123456789abcdeffedcba9876543210"
    "0123456789abcde7"
    "7f1d0a77826b8aff"
    1 2;
  do_test
    "0123456789abcdef0123456789abcdef"
    "0123456789abcde7"
    "c95744256a5ed31d"
    3 4;
  do_test
    "0123456789abcdeffedcba987654321089abcdef01234567"
    "0123456789abcde7"
    "de0b7c06ae5e0ed5"
    5 6

(* ARCfour *)

let _ =
  testing_function "ARCfour";
  let do_test n1 n2 key input output =
    let key = hex key
    and input = hexbytes input
    and output = hexbytes output in
    let c = new Stream.arcfour key in
    let d = new Stream.arcfour key in
    let res = Bytes.create (Bytes.length input) in
    c#transform input 0 res 0 (Bytes.length input);
    test n1 res output;
    d#transform output 0 res 0 (Bytes.length output);
    test n2 res input in
  do_test 1 2 "0123456789abcdef" "0123456789abcdef" "75b7878099e0c596";
  do_test 3 4 "0123456789abcdef" "0000000000000000" "7494c2e7104b0879";
  do_test 5 6 "0000000000000000" "0000000000000000" "de188941a3375d3a";
  do_test 7 8 "ef012345" "00000000000000000000" "d6a141a7ec3c38dfbd61";
  let c2 = Cipher.arcfour "key" Cipher.Encrypt in
  c2#put_string (String.make 1024 'x');
  test 9 c2#available_output 1024

(* Chacha20 *)

let _ =
  testing_function "Chacha20";
  let do_test n1 n2 key nonce plain cipher counter =
    let key = hex key
    and nonce = hex nonce
    and plain = hexbytes plain
    and cipher = hexbytes cipher in
    let c = new Stream.chacha20 ~iv:nonce ~ctr:counter key in
    let d = new Stream.chacha20 ~iv:nonce ~ctr:counter key in
    let res = Bytes.create (Bytes.length plain) in
    c#transform plain 0 res 0 (Bytes.length plain);
    test n1 res cipher;
    d#transform cipher 0 res 0 (Bytes.length cipher);
    test n2 res plain in
  do_test 1 2
    "0000000000000000000000000000000000000000000000000000000000000000"
    "0000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
   "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586"
    0L;
  do_test 3 4
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000002"
    "416e79207375626d697373696f6e20746f20746865204945544620696e74656e6465642062792074686520436f6e7472696275746f7220666f72207075626c69636174696f6e20617320616c6c206f722070617274206f6620616e204945544620496e7465726e65742d4472616674206f722052464320616e6420616e792073746174656d656e74206d6164652077697468696e2074686520636f6e74657874206f6620616e204945544620616374697669747920697320636f6e7369646572656420616e20224945544620436f6e747269627574696f6e222e20537563682073746174656d656e747320696e636c756465206f72616c2073746174656d656e747320696e20494554462073657373696f6e732c2061732077656c6c206173207772697474656e20616e6420656c656374726f6e696320636f6d6d756e69636174696f6e73206d61646520617420616e792074696d65206f7220706c6163652c207768696368206172652061646472657373656420746f"
    "a3fbf07df3fa2fde4f376ca23e82737041605d9f4f4f57bd8cff2c1d4b7955ec2a97948bd3722915c8f3d337f7d370050e9e96d647b7c39f56e031ca5eb6250d4042e02785ececfa4b4bb5e8ead0440e20b6e8db09d881a7c6132f420e52795042bdfa7773d8a9051447b3291ce1411c680465552aa6c405b7764d5e87bea85ad00f8449ed8f72d0d662ab052691ca66424bc86d2df80ea41f43abf937d3259dc4b2d0dfb48a6c9139ddd7f76966e928e635553ba76c5c879d7b35d49eb2e62b0871cdac638939e25e8a1e0ef9d5280fa8ca328b351c3c765989cbcf3daa8b6ccc3aaf9f3979c92b3720fc88dc95ed84a1be059c6499b9fda236e7e818b04b0bc39c1e876b193bfe5569753f88128cc08aaa9b63d1a16f80ef2554d7189c411f5869ca52c5b83fa36ff216b9c1d30062bebcfd2dc5bce0911934fda79a86f6e698ced759c3ff9b6477338f3da4f9cd8514ea9982ccafb341b2384dd902f3d1ab7ac61dd29c6f21ba5b862f3730e37cfdc4fd806c22f221"
    1L;
  do_test 5 6
    "1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0"
    "0000000000000002"
    "2754776173206272696c6c69672c20616e642074686520736c6974687920746f7665730a446964206779726520616e642067696d626c6520696e2074686520776162653a0a416c6c206d696d737920776572652074686520626f726f676f7665732c0a416e6420746865206d6f6d65207261746873206f757467726162652e"
    "62e6347f95ed87a45ffae7426f27a1df5fb69110044c0d73118effa95b01e5cf166d3df2d721caf9b21e5fb14c616871fd84c54f9d65b283196c7fe4f60553ebf39c6402c42234e32a356b3e764312a61a5532055716ead6962568f87d3f3f7704c6a8d1bcd1bf4d50d6154b6da731b187b58dfd728afa36757a797ac188d1"
    42L

(* Blowfish *)

let _ =
  testing_function "Blowfish";
  let testcnt = ref 0 in
  let res = Bytes.create 8 in
  let do_test (key, plain, cipher) =
    let key = hex key
    and plain = hexbytes plain
    and cipher = hexbytes cipher in
    let c = new Block.blowfish_encrypt key
    and d = new Block.blowfish_decrypt key in
    c#transform plain 0 res 0;  incr testcnt; test !testcnt res cipher;
    d#transform cipher 0 res 0; incr testcnt; test !testcnt res plain in
  List.iter do_test [
    ("0000000000000000", "0000000000000000", "4EF997456198DD78");
    ("FFFFFFFFFFFFFFFF", "FFFFFFFFFFFFFFFF", "51866FD5B85ECB8A");
    ("3000000000000000", "1000000000000001", "7D856F9A613063F2");
    ("1111111111111111", "1111111111111111", "2466DD878B963C9D");
    ("0123456789ABCDEF", "1111111111111111", "61F9C3802281B096");
    ("1111111111111111", "0123456789ABCDEF", "7D0CC630AFDA1EC7");
    ("0000000000000000", "0000000000000000", "4EF997456198DD78");
    ("FEDCBA9876543210", "0123456789ABCDEF", "0ACEAB0FC6A0A28D");
    ("7CA110454A1A6E57", "01A1D6D039776742", "59C68245EB05282B");
    ("0131D9619DC1376E", "5CD54CA83DEF57DA", "B1B8CC0B250F09A0");
    ("07A1133E4A0B2686", "0248D43806F67172", "1730E5778BEA1DA4");
    ("3849674C2602319E", "51454B582DDF440A", "A25E7856CF2651EB");
    ("04B915BA43FEB5B6", "42FD443059577FA2", "353882B109CE8F1A");
    ("0113B970FD34F2CE", "059B5E0851CF143A", "48F4D0884C379918");
    ("0170F175468FB5E6", "0756D8E0774761D2", "432193B78951FC98");
    ("43297FAD38E373FE", "762514B829BF486A", "13F04154D69D1AE5");
    ("07A7137045DA2A16", "3BDD119049372802", "2EEDDA93FFD39C79");
    ("04689104C2FD3B2F", "26955F6835AF609A", "D887E0393C2DA6E3");
    ("37D06BB516CB7546", "164D5E404F275232", "5F99D04F5B163969");
    ("1F08260D1AC2465E", "6B056E18759F5CCA", "4A057A3B24D3977B");
    ("584023641ABA6176", "004BD6EF09176062", "452031C1E4FADA8E");
    ("025816164629B007", "480D39006EE762F2", "7555AE39F59B87BD");
    ("49793EBC79B3258F", "437540C8698F3CFA", "53C55F9CB49FC019");
    ("4FB05E1515AB73A7", "072D43A077075292", "7A8E7BFA937E89A3");
    ("49E95D6D4CA229BF", "02FE55778117F12A", "CF9C5D7A4986ADB5");
    ("018310DC409B26D6", "1D9D5C5018F728C2", "D1ABB290658BC778");
    ("1C587F1C13924FEF", "305532286D6F295A", "55CB3774D13EF201");
    ("0101010101010101", "0123456789ABCDEF", "FA34EC4847B268B2");
    ("1F1F1F1F0E0E0E0E", "0123456789ABCDEF", "A790795108EA3CAE");
    ("E0FEE0FEF1FEF1FE", "0123456789ABCDEF", "C39E072D9FAC631D");
    ("0000000000000000", "FFFFFFFFFFFFFFFF", "014933E0CDAFF6E4");
    ("FFFFFFFFFFFFFFFF", "0000000000000000", "F21E9A77B71C49BC");
    ("0123456789ABCDEF", "0000000000000000", "245946885754369A");
    ("FEDCBA9876543210", "FFFFFFFFFFFFFFFF", "6B5C5A9C5D9E0A5A")
  ]

(* Input message: a million 'a' *)
let hash_million_a (h: hash) =
  for i = 1 to 10_000 do
    h#add_string "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  done;
  h#result

(* Input message: the extremely-long message "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" repeated 16,777,216 times: a bit string of length 233 bits. This test is from the SHA-3 Candidate Algorithm Submissions document. *)
let hash_extremely_long (h: hash) =
  for i = 1 to 16_777_216 do
    h#add_string "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno"
  done;
  h#result

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
  test 6 (hash_million_a (Hash.sha1()))
         (hex "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F");
  if !long_tests then
  test 99 (hash_extremely_long (Hash.sha1()))
         (hex "7789f0c9 ef7bfc40 d9331114 3dfbe69e 2017f592")

(* SHA-224 *)
let _ =
  testing_function "SHA-2 224";
  let hash s = hash_string (Hash.sha2 224) s in
  test 1 (hash "abc")
    (hex "23097d22 3405d822 8642a477 bda255b3 2aadbce4 bda0b3f7 e36c9da7");
  test 2 (hash "")
    (hex "d14a028c 2a3a2bc9 476102bb 288234c4 15a2b01f 828ea62a c5b3e42f");
  test 3 (hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    (hex "75388b16 512776cc 5dba5da1 fd890150 b0c6455c b4f58b19 52522525");
  test 4 (hash_million_a (Hash.sha2 224))
    (hex "20794655 980c91d8 bbb4c1ea 97618a4b f03f4258 1948b2ee 4ee7ad67")

(* SHA-256 *)
let _ =
  testing_function "SHA-2 256";
  let hash s = hash_string (Hash.sha2 256) s in
  test 1 (hash "abc")
    (hex "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  test 2 (hash "")
    (hex "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
  test 3 (hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    (hex "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1");
  test 4 (hash_million_a (Hash.sha2 256))
    (hex "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
  if !long_tests then
  test 99 (hash_extremely_long (Hash.sha256()))
         (hex "50e72a0e 26442fe2 552dc393 8ac58658 228c0cbf b1d2ca87 2ae43526 6fcd055e")

(* SHA-384 *)
let _ =
  testing_function "SHA-2 384";
  let hash s = hash_string (Hash.sha2 384) s in
  test 1 (hash "abc")
    (hex "cb00753f45a35e8b b5a03d699ac65007 272c32ab0eded163 1a8b605a43ff5bed 8086072ba1e7cc23 58baeca134c825a7");
  test 2 (hash "")
    (hex "38b060a751ac9638 4cd9327eb1b1e36a 21fdb71114be0743 4c0cc7bf63f6e1da 274edebfe76f65fb d51ad2f14898b95b");
  test 3 (hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    (hex "3391fdddfc8dc739 3707a65b1b470939 7cf8b1d162af05ab fe8f450de5f36bc6 b0455a8520bc4e6f 5fe95b1fe3c8452b");
  test 4 (hash_million_a (Hash.sha2 384))
    (hex "9d0e1809716474cb 086e834e310a4a1c ed149e9c00f24852 7972cec5704c2a5b 07b8b3dc38ecc4eb ae97ddd87f3d8985")

(* SHA-512 *)
let _ =
  testing_function "SHA-2 512";
  let hash s = hash_string (Hash.sha2 512) s in
  test 1 (hash "abc")
    (hex "ddaf35a193617aba cc417349ae204131 12e6fa4e89a97ea2 0a9eeee64b55d39a 2192992a274fc1a8 36ba3c23a3feebbd 454d4423643ce80e 2a9ac94fa54ca49f");
  test 2 (hash "")
    (hex "cf83e1357eefb8bd f1542850d66d8007 d620e4050b5715dc 83f4a921d36ce9ce 47d0d13c5d85f2b0 ff8318d2877eec2f 63b931bd47417a81 a538327af927da3e");
  test 3 (hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    (hex "204a8fc6dda82f0a 0ced7beb8e08a416 57c16ef468b228a8 279be331a703c335 96fd15c13b1b07f9 aa1d3bea57789ca0 31ad85c7a71dd703 54ec631238ca3445");
  test 4 (hash "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
    (hex "8e959b75dae313da 8cf4f72814fc143f 8f7779c6eb9f7fa1 7299aeadb6889018 501d289e4900f7e4 331b99dec4b5433a c7d329eeb6dd2654 5e96e55b874be909");
  test 5 (hash_million_a (Hash.sha2 512))
    (hex "e718483d0ce76964 4e2e42c7bc15b463 8e1f98b13b204428 5632a803afa973eb de0ff244877ea60a 4cb0432ce577c31b eb009c5c2c49aa2e 4eadb217ad8cc09b");
  if !long_tests then
  test 99 (hash_extremely_long (Hash.sha2 512))
         (hex "b47c933421ea2db1 49ad6e10fce6c7f9 3d0752380180ffd7 f4629a712134831d 77be6091b819ed35 2c2967a2e2d4fa50 50723c9630691f1a 05a7281dbe6c1086")

(* SHA-3 *)
let _ =
  testing_function "SHA-3";
  let hash n s = hash_string (Hash.sha3 n) s in
  let s = "" in
  test 1 (hash 224 s)
    (hex "6b4e03423667dbb7 3b6e15454f0eb1ab d4597f9a1b078e3f 5b5a6bc7");
  test 2 (hash 256 s)
    (hex "a7ffc6f8bf1ed766 51c14756a061d662 f580ff4de43b49fa 82d80a4b80f8434a");
  test 3 (hash 384 s)
    (hex "0c63a75b845e4f7d 01107d852e4c2485 c51a50aaaa94fc61 995e71bbee983a2a c3713831264adb47 fb6bd1e058d5f004");
  test 4 (hash 512 s)
    (hex "a69f73cca23a9ac5 c8b567dc185a756e 97c982164fe25859 e0d1dcc1475c80a6 15b2123af1f5f94c 11e3e9402c3ac558 f500199d95b6d3e3 01758586281dcd26");
  let s = "abc" in
  test 5 (hash 224 s)
    (hex "e642824c3f8cf24a d09234ee7d3c766f c9a3a5168d0c94ad 73b46fdf");
  test 6 (hash 256 s)
    (hex "3a985da74fe225b2 045c172d6bd390bd 855f086e3e9d525b 46bfe24511431532");
  test 7 (hash 384 s)
    (hex "ec01498288516fc9 26459f58e2c6ad8d f9b473cb0fc08c25 96da7cf0e49be4b2 98d88cea927ac7f5 39f1edf228376d25");
  test 8 (hash 512 s)
    (hex "b751850b1a57168a 5693cd924b6b096e 08f621827444f70d 884f5d0240d2712e 10e116e9192af3c9 1a7ec57647e39340 57340b4cf408d5a5 6592f8274eec53f0");
  let s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" in
  test 9 (hash 224 s)
    (hex "8a24108b154ada21 c9fd5574494479ba 5c7e7ab76ef264ea d0fcce33");
  test 10 (hash 256 s)
    (hex "41c0dba2a9d62408 49100376a8235e2c 82e1b9998a999e21 db32dd97496d3376");
  test 11 (hash 384 s)
    (hex "991c665755eb3a4b 6bbdfb75c78a492e 8c56a22c5c4d7e42 9bfdbc32b9d4ad5a a04a1f076e62fea1 9eef51acd0657c22");
  test 12 (hash 512 s)
    (hex "04a371e84ecfb5b8 b77cb48610fca818 2dd457ce6f326a0f d3d7ec2f1e91636d ee691fbe0c985302 ba1b0d8dc78c0863 46b533b49c030d99 a27daf1139d6e75e");
  let s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" in
  test 13 (hash 224 s)
    (hex "543e6868e1666c1a 643630df77367ae5 a62a85070a51c14c bf665cbc");
  test 14 (hash 256 s)
    (hex "916f6061fe879741 ca6469b43971dfdb 28b1a32dc36cb325 4e812be27aad1d18");
  test 15 (hash 384 s)
    (hex "79407d3b5916b59c 3e30b09822974791 c313fb9ecc849e40 6f23592d04f625dc 8c709b98b43b3852 b337216179aa7fc7");
  test 16 (hash 512 s)
    (hex "afebb2ef542e6579 c50cad06d2e578f9 f8dd6881d7dc824d 26360feebf18a4fa 73e3261122948efc fd492e74e82e2189 ed0fb440d187f382 270cb455f21dd185");
  test 17 (hash_million_a (Hash.sha3 224))
    (hex "d69335b93325192e 516a912e6d19a15c b51c6ed5c15243e7 a7fd653c");
  test 18 (hash_million_a (Hash.sha3 256))
    (hex "5c8875ae474a3634 ba4fd55ec85bffd6 61f32aca75c6d699 d0cdcb6c115891c1");
  test 19 (hash_million_a (Hash.sha3 384))
    (hex "eee9e24d78c18553 37983451df97c8ad 9eedf256c6334f8e 948d252d5e0e7684 7aa0774ddb90a842 190d2c558b4b8340");
  test 20 (hash_million_a (Hash.sha3 512))
    (hex "3c3a876da14034ab 60627c077bb98f7e 120a2a5370212dff b3385a18d4f38859 ed311d0a9d5141ce 9cc5c66ee689b266 a8aa18ace8282a0e 0db596c90b0a7b87");
  if !long_tests then
  test 99 (hash_extremely_long (Hash.sha3 512))
    (hex "235ffd53504ef836 a1342b488f483b39 6eabbfe642cf78ee 0d31feec788b23d0 d18d5c339550dd59 58a500d4b95363da 1b5fa18affc1bab2 292dc63b7d85097c")

(* Keccak *)
(* The test cases are taken from commit dec7e6dd8e5bbfe4534f7dd4c3fb4429575b23f8 *)
let _ =
  testing_function "Keccak";
  let hash n s = hash_string (Hash.keccak n) s in
  let s = "abc" in
  test 1 (hash 224 s)
    (hex "c30411768506ebe1 c2871b1ee2e87d38 df342317300a9b97 a95ec6a8");
  test 2 (hash 256 s)
    (hex "4e03657aea45a94f c7d47ba826c8d667 c0d1e6e33a64a036 ec44f58fa12d6c45");
  test 3 (hash 384 s)
    (hex "f7df1165f033337b e098e7d288ad6a2f 74409d7a60b49c36 642218de161b1f99 f8c681e4afaf31a3 4db29fb763e3c28e");
  test 4 (hash 512 s)
    (hex "18587dc2ea106b9a 1563e32b3312421c a164c7f1f07bc922 a9c83d77cea3a1e5 d0c6991073902537 2dc14ac964262937 9540c17e2a65b19d 77aa511a9d00bb96");
  let s = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq" in
  test 5 (hash 224 s)
    (hex "e51faa2b4655150b 931ee8d700dc202f 763ca5f962c529ea e55012b6");
  test 6 (hash 256 s)
    (hex "45d3b367a6904e6e 8d502ee04999a7c2 7647f91fa845d456 525fd352ae3d7371");
  test 7 (hash 384 s)
    (hex "b41e8896428f1bcb b51e17abd6acc980 52a3502e0d5bf7fa 1af949b4d3c855e7 c4dc2c390326b3f3 e74c7b1e2b9a3657");
  test 8 (hash 512 s)
    (hex "6aa6d3669597df6d 5a007b00d09c2079 5b5c4218234e1698 a944757a488ecdc0 9965435d97ca32c3 cfed7201ff30e070 cd947f1fc12b9d92 14c467d342bcba5d");
  let s = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu" in
  test 9 (hash 224 s)
    (hex "344298994b1b0687 3eae2ce739c425c4 7291a2e24189e01b 524f88dc");
  test 10 (hash 256 s)
    (hex "f519747ed599024f 3882238e5ab43960 132572b7345fbeb9 a90769dafd21ad67");
  test 11 (hash 384 s)
    (hex "cc063f3468513536 8b34f7449108f6d1 0fa727b09d696ec5 331771da46a923b6 c34dbd1d4f77e595 689c1f3800681c28");
  test 12 (hash 512 s)
    (hex "ac2fb35251825d3a a48468a9948c0a91 b8256f6d97d8fa41 60faff2dd9dfcc24 f3f1db7a983dad13 d53439ccac0b37e2 4037e7b95f80f59f 37a2f683c4ba4682");
  test 13 (hash_million_a (Hash.keccak 224))
    (hex "19f9167be2a04c43 abd0ed554788101b 9c339031acc8e146 8531303f");
  test 14 (hash_million_a (Hash.keccak 256))
    (hex "fadae6b49f129bbb 812be8407b7b2894 f34aecf6dbd1f9b0 f0c7e9853098fc96");
  test 15 (hash_million_a (Hash.keccak 384))
    (hex "0c8324e1ebc18282 2c5e2a086cac07c2 fe00e3bce61d01ba 8ad6b71780e2dec5 fb89e5ae90cb593e 57bc6258fdd94e17");
  test 16 (hash_million_a (Hash.keccak 512))
    (hex "5cf53f2e556be5a6 24425ede23d0e8b2 c7814b4ba0e4e09c bbf3c2fac7056f61 e048fc341262875e bc58a5183fea6514 47124370c1ebf4d6 c89bc9a7731063bb");
  let s = "" in
  test 17 (hash 224 s)
    (hex "f71837502ba8e108 37bdd8d365adb855 91895602fc552b48 b7390abd");
  test 18 (hash 256 s)
    (hex "c5d2460186f7233c 927e7db2dcc703c0 e500b653ca82273b 7bfad8045d85a470");
  test 19 (hash 384 s)
    (hex "2c23146a63a29acf 99e73b88f8c24eaa 7dc60aa771780ccc 006afbfa8fe2479b 2dd2b21362337441 ac12b515911957ff");
  test 20 (hash 512 s)
    (hex "0eab42de4c3ceb92 35fc91acffe746b2 9c29a8c366b7c60e 4e67c466f36a4304 c00fa9caf9d87976 ba469bcbe06713b4 35f091ef2769fb16 0cdab33d3670680e");
  if !long_tests then
  test 98 (hash_extremely_long (Hash.keccak 256))
         (hex "5f313c39963dcf79 2b5470d4ade9f3a3 56a3e4021748690a 958372e2b06f82a4");
  if !long_tests then
  test 99 (hash_extremely_long (Hash.keccak 512))
         (hex "3e122edaf3739823 1cfaca4c7c216c9d 66d5b899ec1d7ac6 17c40c7261906a45 fc01617a021e5da3 bd8d4182695b5cb7 85a28237cbb16759 0e34718e56d8aab8")

(* BLAKE2b *)

let _ =
  testing_function "BLAKE2b-512";
  let hash s = hash_string (Hash.blake2b512 ()) s in
  test 1 (hash "")
         (hex "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
  test 2 (hash "abc")
         (hex "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
  test 3 (hash "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu")
         (hex "ce741ac5930fe346811175c5227bb7bfcd47f42612fae46c0809514f9e0e3a11ee1773287147cdeaeedff50709aa716341fe65240f4ad6777d6bfaf9726e5e52")

let _ =
  testing_function "BLAKE2b-512 (keyed)";
  let mkstring n = String.init n  (fun i -> Char.chr i) in
  let key = mkstring 0x40 in
  let hash s = hash_string (MAC.blake2b512 key) s in
  List.iter
    (fun (len, result) -> test len (hash (mkstring len)) (hex result))
    [
0, "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568";
1, "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd";
2, "da2cfbe2d8409a0f38026113884f84b50156371ae304c4430173d08a99d9fb1b983164a3770706d537f49e0c916d9f32b95cc37a95b99d857436f0232c88a965";
3, "33d0825dddf7ada99b0e7e307104ad07ca9cfd9692214f1561356315e784f3e5a17e364ae9dbb14cb2036df932b77f4b292761365fb328de7afdc6d8998f5fc1";
4, "beaa5a3d08f3807143cf621d95cd690514d0b49efff9c91d24b59241ec0eefa5f60196d407048bba8d2146828ebcb0488d8842fd56bb4f6df8e19c4b4daab8ac";
5, "098084b51fd13deae5f4320de94a688ee07baea2800486689a8636117b46c1f4c1f6af7f74ae7c857600456a58a3af251dc4723a64cc7c0a5ab6d9cac91c20bb";
6, "6044540d560853eb1c57df0077dd381094781cdb9073e5b1b3d3f6c7829e12066bbaca96d989a690de72ca3133a83652ba284a6d62942b271ffa2620c9e75b1f";
7, "7a8cfe9b90f75f7ecb3acc053aaed6193112b6f6a4aeeb3f65d3de541942deb9e2228152a3c4bbbe72fc3b12629528cfbb09fe630f0474339f54abf453e2ed52";
128, "72065ee4dd91c2d8509fa1fc28a37c7fc9fa7d5b3f8ad3d0d7a25626b57b1b44788d4caf806290425f9890a3a2a35a905ab4b37acfd0da6e4517b2525c9651e4";
192, "8d6cf87c08380d2d1506eee46fd4222d21d8c04e585fbfd08269c98f702833a156326a0724656400ee09351d57b440175e2a5de93cc5f80db6daf83576cf75fa";
255, "142709d62e28fcccd0af97fad0f8465b971e82201dc51070faa0372aa43e92484be1c1e73ba10906d5d1853db6a4106e0a7bf9800d373d6dee2d46d62ef2a461"
    ]

let _ =
  testing_function "BLAKE2s-256 (keyed)";
  let mkstring n = String.init n  (fun i -> Char.chr i) in
  let key = mkstring 0x20 in
  let hash s = hash_string (MAC.blake2s256 key) s in
  List.iter
    (fun (len, result) -> test len (hash (mkstring len)) (hex result))
    [
0, "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49";
1, "40d15fee7c328830166ac3f918650f807e7e01e177258cdc0a39b11f598066f1";
2, "6bb71300644cd3991b26ccd4d274acd1adeab8b1d7914546c1198bbe9fc9d803";
3, "1d220dbe2ee134661fdf6d9e74b41704710556f2f6e5a091b227697445dbea6b";
4, "f6c3fbadb4cc687a0064a5be6e791bec63b868ad62fba61b3757ef9ca52e05b2";
5, "49c1f21188dfd769aea0e911dd6b41f14dab109d2b85977aa3088b5c707e8598";
6, "fdd8993dcd43f696d44f3cea0ff35345234ec8ee083eb3cada017c7f78c17143";
7, "e6c8125637438d0905b749f46560ac89fd471cf8692e28fab982f73f019b83a9";
128, "0c311f38c35a4fb90d651c289d486856cd1413df9b0677f53ece2cd9e477c60a";
192, "5950d39a23e1545f301270aa1a12f2e6c453776e4d6355de425cc153f9818867";
255, "3fb735061abc519dfe979e54c1ee5bfad0a9d858b3315bad34bde999efd724dd"
    ]

(* RIPEMD-160 *)
let _ =
  testing_function "RIPEMD-160";
  let hash s = hash_string (Hash.ripemd160()) s in
  test 1 (hash "")
    (hex "9c1185a5c5e9fc54612808977ee8f548b2258d31");
  test 2 (hash "a")
    (hex "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe");
  test 3 (hash "abc")
    (hex "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
  test 4 (hash "message digest")
    (hex "5d0689ef49d2fae572b881b123a85ffa21595f36");
  test 5 (hash "abcdefghijklmnopqrstuvwxyz")
    (hex "f71c27109c692c1b56bbdceb5b9d2865b3708dbc");
  test 6 (hash "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")
    (hex "12a053384a9c0c88e405a06c27dcf49ada62eb2b");
  test 7 (hash "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789")
    (hex "b0e20b6e3116640286ed3a87a5713079b21f5189");
  test 8 (hash "12345678901234567890123456789012345678901234567890123456789012345678901234567890")
    (hex "9b752e45573d4b39f4dbd3323cab82bf63326bfb");
  test 9 (hash (String.make 1000000 'a'))
    (hex "52783243c1697bdbe16d37f97f68f08325dc1528")

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

let _ =
  testing_function "CTR";
  test_enc_dec 1 (des ~mode:CTR) "abcdefgh";
  test_enc_dec 2 (des ~mode:CTR) "abcdefgh01234567";
  test_enc_dec 3 (des ~mode:CTR ~pad:Padding._8000) "abcdefghijklmnopqrstuvwxyz";
  test_enc_dec 4 (des ~mode:CTR ~iv:"\000\000\000\000\255\255\255\255" ~pad:Padding._8000) "abcdefghijklmnopqrstuvwxyz"

(* HMAC-SHA256 *)

let _ =
  testing_function "HMAC-SHA256";
  List.iter
    (fun (testno, hexkey, msg, hexhash) ->
      test testno
        (hash_string (MAC.hmac_sha256 (hex hexkey)) msg)
        (hex hexhash))
[
(1,
 "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
 "abc",
 "a21b1f5d4cf4f73a4dd939750f7a066a7f98cc131cb16a6692759021cfab8181");
(2,
 "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
 "104fdc1257328f08184ba73131c53caee698e36119421149ea8c712456697d30");
(3,
 "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20",
 "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopqabcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
 "470305fc7e40fe34d3eeb3e773d95aab73acf0fd060447a5eb4595bf33a9d1a3");
(4,
 "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
 "Hi There",
 "198a607eb44bfbc69903a0f1cf2bbdc5ba0aa3f3d9ae3c1c7a3b1696a0b68cf7");
(5,
 "4a656665", (* "Jefe" *)
 "what do ya want for nothing?",
 "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843");
(6,
 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd",
 "cdcb1220d1ecccea91e53aba3092f962e549fe6ce9ed7fdc43191fbde45c30b0");
(7,
 "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425",
 "\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd\xcd",
 "d4633c17f6fb8d744c66dee0f8f074556ec4af55ef07998541468eb49bd2e917");
(8,
 "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c",
 "Test With Truncation",
 "7546af01841fc09b1ab9c3749a5f1c17d4f589668a587b2700a9c97c1193cf42");
(9,
 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "Test Using Larger Than Block-Size Key - Hash Key First",
 "6953025ed96f0c09f80a96f78e6538dbe2e7b820e3dd970e7ddd39091b32352f");
(10,
 "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
 "6355ac22e890d0a3c8481a5ca4825bc884d3e7a1ff98a2fc2ac7d8e064c3b2e6")
]

(* HMAC-SHA512 *)

let _ =
  testing_function "HMAC-SHA512";
  List.iter
    (fun (testno, hexkey, hexmsg, hexhash) ->
      test testno
        (hash_string (MAC.hmac_sha512 (hex hexkey)) (hex hexmsg))
        (hex hexhash))
 [(1,
   "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\
    0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\
    0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\
    0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
   "4869205468657265",
   "637edc6e01dce7e6742a99451aae82df\
    23da3e92439e590e43e761b33e910fb8\
    ac2878ebd5803f6f0b61dbce5e251ff8\
    789a4722c1be65aea45fd464e89f8f5b");
  (2,
   "4a6566654a6566654a6566654a656665\
    4a6566654a6566654a6566654a656665\
    4a6566654a6566654a6566654a656665\
    4a6566654a6566654a6566654a656665",
   "7768617420646f2079612077616e7420\
    666f72206e6f7468696e673f",
   "cb370917ae8a7ce28cfd1d8f4705d614\
    1c173b2a9362c15df235dfb251b15454\
    6aa334ae9fb9afc2184932d8695e397b\
    fa0ffb93466cfcceaae38c833b7dba38");
  (3,
   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
   "dddddddddddddddddddddddddddddddd\
    dddddddddddddddddddddddddddddddd\
    dddddddddddddddddddddddddddddddd\
    dddd",
   "2ee7acd783624ca9398710f3ee05ae41\
    b9f9b0510c87e49e586cc9bf961733d8\
    623c7b55cebefccf02d5581acc1c9d5f\
    b1ff68a1de45509fbe4da9a433922655")]

(* HMAC-MD5 *)

let _ =
  testing_function "HMAC-MD5";
  test 1
    (hash_string (MAC.hmac_md5 (hex "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b"))
                 "Hi There")
    (hex "9294727a3638bb1c13f48ef8158bfc9d");
  test 2
    (hash_string (MAC.hmac_md5 "Jefe")
                 "what do ya want for nothing?")
    (hex "750c783e6ab0b503eaa86e310a5db738");
  test 3
    (hash_string (MAC.hmac_md5 (hex "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"))
                 (String.make 50 '\221'))
    (hex "56be34521d144c88dbb8c733f0e8b3f6")

(* AES-CMAC (from RFC4493) *)

let _ =
  testing_function "AES-CMAC";
  let key = hex "2b7e1516 28aed2a6 abf71588 09cf4f3c" in
  let msg = hex "6bc1bee2 2e409f96 e93d7e11 7393172a \
                 ae2d8a57 1e03ac9c 9eb76fac 45af8e51 \
                 30c81c46 a35ce411 e5fbc119 1a0a52ef \
                 f69f2445 df4f9b17 ad2b417b e66c3710" in
  test 1
    (hash_string (MAC.aes_cmac key)
                 "")
    (hex "bb1d6929 e9593728 7fa37d12 9b756746");
  test 2
    (hash_string (MAC.aes_cmac key)
                 (String.sub msg 0 16))
    (hex "070a16b4 6b4d4144 f79bdd9d d04a287c");
  test 3
    (hash_string (MAC.aes_cmac key)
                 (String.sub msg 0 40))
    (hex "dfa66747 de9ae630 30ca3261 1497c827");
  test 4
    (hash_string (MAC.aes_cmac key)
                 msg)
    (hex "51f0bebf 7e3b9d92 fc497417 79363cfe")

(* RSA *)

let some_rsa_key = {
  RSA.size = 512;
  RSA.n = hex "c0764797b8bec8972a0ed8c90a8c334dd049add0222c09d20be0a79e338910bcae422060906ae0221de3f3fc747ccf98aecc85d6edc52d93d5b7396776160525";
  RSA.e = hex "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010001";
  RSA.d = hex "1ae36b7522f66487d9f4610d1550290ac202c929bedc7032cc3e02acf37e3ebc1f866ee7ef7a0868d23ae2b184c1abd6d4db8ea9bec046bd82803727f2888701";
  RSA.p = hex "df02b615fe15928f41b02b586b51c2c02260ca396818ca4cba60bb892465be35";
  RSA.q = hex "dceeb60d543518b4ac74834a0546c507f2e91e389a87e2f2becc6f8c67d1c931";
  RSA.dp = hex "59487e99e375c38d732112d97d6de8687fdafc5b6b5fb16e7297d3bd1e435599";
  RSA.dq = hex "61b550de6437774db0577718ed6c770724eee466b43114b5b69c43591d313281";
  RSA.qinv = hex "744c79c4b9bea97c25e563c9407a2d09b57358afe09af67d71f8198cb7c956b8"
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
    Random.pseudo_rng (hex "5b5e50dc5b6eaf5346eba8244e5666ac4dcd5409") in
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

(* Diffie-Hellman *)

let _ =
  testing_function "Diffie-Hellman";
  let prng =
    Random.pseudo_rng (hex "5b5e50dc5b6eaf5346eba8244e5666ac4dcd5409") in
  let param = DH.new_parameters ~rng:prng 1024 in
  let ps1 = DH.private_secret ~rng:prng param
  and ps2 = DH.private_secret ~rng:prng param in
  let msg1 = DH.message param ps1
  and msg2 = DH.message param ps2 in
  let ss1 = DH.shared_secret param ps1 msg2
  and ss2 = DH.shared_secret param ps2 msg1 in
  test 1 ss1 ss2

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
  let binarytext = String.init 256 Char.chr in
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
  try
    test 1 text (transform_string (Zlib.uncompress()) (transform_string (Zlib.compress()) text));
    let c = Zlib.compress() and u = Zlib.uncompress() in
    c#put_string text; c#flush; u#put_string c#get_string; u#flush;
    test 2 text u#get_string;
    c#put_string text; c#finish; u#put_string c#get_string; u#finish;
    test 3 text u#get_string
  with Error Compression_not_supported ->
    printf " (not supported)"

(* Random numbers *)
(* This is not a serious statistical test of Cryptokit's RNGs
   (use Dieharder or TestU01 for this).  Rather, it's a simplistic
   test intended to detect obvious bugs such as providing
   fewer random bytes than requested. *)
   
let chisquare b =
  let n = Bytes.length b in
  let r = 256 in
  let freq = Array.make r 0 in
  for i = 0 to n - 1 do
    let t = Char.code (Bytes.get b i) in
    freq.(t) <- freq.(t) + 1
  done;
  let expected = float n /. float r in
  let t =
    Array.fold_left
      (fun s x -> let d = float x -. expected in d *. d +. s)
      0.0 freq in
  let chi2 = t /. expected in
  let degfree = float r -. 1.0 in
  (* The degree of freedom is high, so we approximate as a normal
     distribution with mean equal to degfree and variance 2 * degfree.
     Four sigmas correspond to a 99.9936% confidence interval. *)
  chi2 <= degfree +. 4.0 *. sqrt (2.0 *. degfree)

let test_rng ?(len = 10000) (r: Random.rng) =
  let b = Bytes.make len '\000' in
  r#random_bytes b 0 len;
  r#wipe;
  printf "chi^2 %s\n"
    (if chisquare b
     then "plausible"
     else (error_occurred := true; "BROKEN? rerun test!"))

let _ =
  testing_function "Random number generation";
  printf " 1. PRNG: ";
  test_rng (Random.pseudo_rng "abcdefghijklmnopqrstuvwxyz");
  printf " 2. PRNG based on AES CTR: ";
  test_rng (Random.pseudo_rng_aes_ctr "abcdefghijklmnopqrstuvwxyz");
  printf " 3. /dev/urandom: ";
  begin try
    test_rng (Random.device_rng "/dev/urandom")
  with Unix.Unix_error _ ->
    printf "not available\n"
  end;
  printf " 4. Hardware RNG: ";
  begin try
    test_rng (Random.hardware_rng ())
  with Error No_entropy_source ->
    printf "not available\n"
  end;
  printf " 5. System RNG: ";
  begin try
    test_rng (Random.system_rng ())
  with Error No_entropy_source ->
    printf "not available\n"
  end

(* Miscellaneous functions *)

let test_equal_data = [ ""; "a"; "b"; "aa"; "ab"; "ba"; "abc" ]

let test_equal (of_string: string -> 'a) (f: 'a -> 'a -> bool) =
  List.fold_left
    (fun acc s1 ->
       List.fold_left
         (fun acc s2 ->
            acc && (f (of_string s1) (of_string s2) = String.equal s1 s2))
         acc test_equal_data)
    true test_equal_data

let _ =
  testing_function "Comparison functions";
  test 1 (test_equal (fun x -> x) Cryptokit.string_equal) true;
  test 2 (test_equal Bytes.of_string Cryptokit.bytes_equal) true

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

