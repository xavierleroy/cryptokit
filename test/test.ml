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
    42L;
  (* From RFC 7539 *)
  do_test 7 8
    "00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f"
    "00 00 00 00 00 00 00 4a 00 00 00 00"
    "4c 61 64 69 65 73 20 61 6e 64 20 47 65 6e 74 6c
     65 6d 65 6e 20 6f 66 20 74 68 65 20 63 6c 61 73
     73 20 6f 66 20 27 39 39 3a 20 49 66 20 49 20 63
     6f 75 6c 64 20 6f 66 66 65 72 20 79 6f 75 20 6f
     6e 6c 79 20 6f 6e 65 20 74 69 70 20 66 6f 72 20
     74 68 65 20 66 75 74 75 72 65 2c 20 73 75 6e 73
     63 72 65 65 6e 20 77 6f 75 6c 64 20 62 65 20 69
     74 2e"
    "6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
     e9 7e 7a ec 1d 43 60 c2 0a 27 af cc fd 9f ae 0b
     f9 1b 65 c5 52 47 33 ab 8f 59 3d ab cd 62 b3 57
     16 39 d6 24 e6 51 52 ab 8f 53 0c 35 9f 08 61 d8
     07 ca 0d bf 50 0d 6a 61 56 a3 8e 08 8a 22 b6 5e
     52 bc 51 4d 16 cc f8 06 81 8c e9 1a b7 79 37 36
     5a f9 0b bf 74 a3 5b e6 b4 0b 8e ed f2 78 5e 42
     87 4d"
    1L

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

(* AES-GCM *)

let _ =
  testing_function "AES-GCM";
  let testcnt = ref 0 in
  let do_test (key, plain, header, iv, cipher, tag) =
    let key = hex key
    and plain = hex plain
    and header = hex header
    and iv = hex iv
    and cipher = hex cipher
    and tag = hex tag in
    let c = AEAD.(aes_gcm ~header ~iv key Encrypt) in
    let ct = auth_transform_string c plain in
    incr testcnt; test !testcnt ct (cipher ^ tag);
    let d = AEAD.(aes_gcm ~header ~iv key Decrypt) in
    let pp = auth_check_transform_string d ct in
    incr testcnt; test !testcnt pp (Some plain) in
  List.iter do_test [
    ("00000000000000000000000000000000",
      "", "",
      "000000000000000000000000",
      "",
      "58e2fccefa7e3061367f1d57a4e7455a");
    ("00000000000000000000000000000000",
     "00000000000000000000000000000000", "",
     "000000000000000000000000",
     "0388dace60b6a392f328c2b971b2fe78",
     "ab6e47d42cec13bdf53a67b21257bddf");
    ("feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255", "",
     "cafebabefacedbaddecaf888",
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
     "4d5c2af327cd64a62cf35abd2ba6fab4");
    ("feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "cafebabefacedbaddecaf888",
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
     "5bc94fbc3221a5db94fae95ae7121a47");
    ("feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "cafebabefacedbaddecaf888",
     "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
     "5bc94fbc3221a5db94fae95ae7121a47");
    ("feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "cafebabefacedbad",
     "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c742373806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
     "3612d2e79e3b0785561be14aaca2fccb");
    ("feffe9928665731c6d6a8f9467308308",
     "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39", "feedfacedeadbeeffeedfacedeadbeefabaddad2",
     "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b",
     "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca701e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
     "619cc5aefffe0bfa462af43c1699d050")
  ]

(* Chacha20-Poly1305 *)

let _ =
  testing_function "Chacha20-Poly1305";
  let testcnt = ref 0 in
  let do_test (key, iv, plain, header, cipher, tag) =
    let key = hex key
    and iv = hex iv
    and cipher = hex cipher
    and tag = hex tag in
    let c = AEAD.(chacha20_poly1305 ~header ~iv key Encrypt) in
    let ct = auth_transform_string c plain in
    incr testcnt; test !testcnt ct (cipher ^ tag);
    let d = AEAD.(chacha20_poly1305 ~header ~iv key Decrypt) in
    let pp = auth_check_transform_string d ct in
    incr testcnt; test !testcnt pp (Some plain) in
  List.iter do_test [
    (* From RFC 7539 *)
    ("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
     "070000004041424344454647",
     "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.",
     hex "50515253c0c1c2c3c4c5c6c7",
     "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
     "1ae10b594f09e26a7e902ecbd0600691");
    (* From BoringSSL *)
    (* Test padding AD with 15 zeros in the tag calculation. *)
    ("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
     "070000004041424344454647",
     "123456789abcdef0",
     "1",
     "ae49da6934cb77822c83ed9852e46c9e",
     "dac9c841c168379dcf8f2bb8e22d6da2");
    (* Test padding IN with 15 zeros in the tag calculation. *)
    ("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
     "070000004041424344454647",
     "1",
     "123456789abcdef0",
     "ae",
     "3ed2f824f901a8994052f852127c196a");
    (* Test padding AD with 1 zero in the tag calculation. *)
    ("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
     "070000004041424344454647",
     "123456789abcdef0",
     "123456789abcdef",
     "ae49da6934cb77822c83ed9852e46c9e",
     "2e9c9b1689adb5ec444002eb920efb66");
    (*  Test padding IN with 1 zero in the tag calculation. *)
    ("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
     "070000004041424344454647",
     "123456789abcdef",
     "123456789abcdef0",
     "ae49da6934cb77822c83ed9852e46c",
     "05b2937f8bbc64fed21f0fb74cd7147c");
    (* Test maximal nonce value. *)
    ("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
     "ffffffffffffffffffffffff",
     "123456789abcdef0",
     "123456789abcdef0",
     "e275aeb341e1fc9a70c4fd4496fc7cdb",
     "41acd0560ea6843d3e5d4e5babf6e946");
    (* Empty text *)
    ("9a97f65b9b4c721b960a672145fca8d4e32e67f9111ea979ce9c4826806aeee6",
     "000000003de9c0da2bd7f91e",
     "",
     "",
     "",
     "5a6e21f4ba6dbee57380e79e79c30def")
  ]

(* Input message: a million 'a' *)
let hash_million_a (h: hash) =
  for i = 1 to 10_000 do
    h#add_string "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  done;
  h#result

(* Input message: the extremely-long message "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmno" repeated 16,777,216 times: a bit string of length 2^{33} bits. This test is from the SHA-3 Candidate Algorithm Submissions document. *)
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

(* BLAKE3 *)

let _ =
  testing_function "BLAKE3";
  let key = "whats the Elvish word for friend" in
  let mktest (len, h, kh) =
    let input = String.init len (fun i -> Char.chr (i mod 251)) in
    let h = hex h and kh = hex kh in
    test len (hash_string (Hash.blake3 (8 * String.length h)) input) h;
    test len (hash_string (MAC.blake3 (8 * String.length kh) key) input) kh
  in
  List.iter mktest [
      (0,
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262e00f03e7b69af26b7faaf09fcd333050338ddfe085b8cc869ca98b206c08243a26f5487789e8f660afe6c99ef9e0c52b92e7393024a80459cf91f476f9ffdbda7001c22e159b402631f277ca96f2defdf1078282314e763699a31c5363165421cce14d",
      "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26b18171a2f22a4b94822c701f107153dba24918c4bae4d2945c20ece13387627d3b73cbf97b797d5e59948c7ef788f54372df45e45e4293c7dc18c1d41144a9758be58960856be1eabbe22c2653190de560ca3b2ac4aa692a9210694254c371e851bc8f");
      (1,
      "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213c3a6cb8bf623e20cdb535f8d1a5ffb86342d9c0b64aca3bce1d31f60adfa137b358ad4d79f97b47c3d5e79f179df87a3b9776ef8325f8329886ba42f07fb138bb502f4081cbcec3195c5871e6c23e2cc97d3c69a613eba131e5f1351f3f1da786545e5",
      "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b6568c0490609413006fbd428eb3fd14e7756d90f73a4725fad147f7bf70fd61c4e0cf7074885e92b0e3f125978b4154986d4fb202a3f331a3fb6cf349a3a70e49990f98fe4289761c8602c4e6ab1138d31d3b62218078b2f3ba9a88e1d08d0dd4cea11");
      (2,
      "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63d8386b22e2ddc05836b7c1bb693d92af006deb5ffbc4c70fb44d0195d0c6f252faac61659ef86523aa16517f87cb5f1340e723756ab65efb2f91964e14391de2a432263a6faf1d146937b35a33621c12d00be8223a7f1919cec0acd12097ff3ab00ab1",
      "5392ddae0e0a69d5f40160462cbd9bd889375082ff224ac9c758802b7a6fd20a9ffbf7efd13e989a6c246f96d3a96b9d279f2c4e63fb0bdff633957acf50ee1a5f658be144bab0f6f16500dee4aa5967fc2c586d85a04caddec90fffb7633f46a60786024353b9e5cebe277fcd9514217fee2267dcda8f7b31697b7c54fab6a939bf8f");
      (3,
      "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f5b49b82f805a538c68915c1ae8035c900fd1d4b13902920fd05e1450822f36de9454b7e9996de4900c8e723512883f93f4345f8a58bfe64ee38d3ad71ab027765d25cdd0e448328a8e7a683b9a6af8b0af94fa09010d9186890b096a08471e4230a134",
      "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9b9142d0fab08e1b161efdbb28d18afc64d8f72160c958e53a950cdecf91c1a1bbab1a9c0f01def762a77e2e8545d4dec241e98a89b6db2e9a5b070fc110caae2622690bd7b76c02ab60750a3ea75426a6bb8803c370ffe465f07fb57def95df772c39f");
      (4,
      "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f328f603ba4564453e06cdcee6cbe728a4519bbe6f0d41e8a14b5b225174a566dbfa61b56afb1e452dc08c804f8c3143c9e2cc4a31bb738bf8c1917b55830c6e65797211701dc0b98daa1faeaa6ee9e56ab606ce03a1a881e8f14e87a4acf4646272cfd12",
      "7671dde590c95d5ac9616651ff5aa0a27bee5913a348e053b8aa9108917fe070116c0acff3f0d1fa97ab38d813fd46506089118147d83393019b068a55d646251ecf81105f798d76a10ae413f3d925787d6216a7eb444e510fd56916f1d753a5544ecf0072134a146b2615b42f50c179f56b8fae0788008e3e27c67482349e249cb86a");
      (5,
      "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2ebcfdac6c5d32c31209e1f81a454751280db64942ce395104e1e4eaca62607de1c2ca748251754ea5bbe8c20150e7f47efd57012c63b3c6a6632dc1c7cd15f3e1c999904037d60fac2eb9397f2adbe458d7f264e64f1e73aa927b30988e2aed2f03620",
      "73ac69eecf286894d8102018a6fc729f4b1f4247d3703f69bdc6a5fe3e0c84616ab199d1f2f3e53bffb17f0a2209fe8b4f7d4c7bae59c2bc7d01f1ff94c67588cc6b38fa6024886f2c078bfe09b5d9e6584cd6c521c3bb52f4de7687b37117a2dbbec0d59e92fa9a8cc3240d4432f91757aabcae03e87431dac003e7d73574bfdd8218");
      (6,
      "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844611a30c4e4f37fe2fe23c0883cde5cf7059d88b657c7ed2087e3d210925ede716435d6d5d82597a1e52b9553919e804f5656278bd739880692c94bff2824d8e0b48cac1d24682699e4883389dc4f2faa2eb3b4db6e39debd5061ff3609916f3e07529a",
      "82d3199d0013035682cc7f2a399d4c212544376a839aa863a0f4c91220ca7a6dc2ffb3aa05f2631f0fa9ac19b6e97eb7e6669e5ec254799350c8b8d189e8807800842a5383c4d907c932f34490aaf00064de8cdb157357bde37c1504d2960034930887603abc5ccb9f5247f79224baff6120a3c622a46d7b1bcaee02c5025460941256");
      (7,
      "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe66036ef6e6d1a8f54baa9fed1fc11c77cfb9cff65bae915045027046ebe0c01bf5a941f3bb0f73791d3fc0b84370f9f30af0cd5b0fc334dd61f70feb60dad785f070fef1f343ed933b49a5ca0d16a503f599a365a4296739248b28d1a20b0e2cc8975c",
      "af0a7ec382aedc0cfd626e49e7628bc7a353a4cb108855541a5651bf64fbb28a7c5035ba0f48a9c73dabb2be0533d02e8fd5d0d5639a18b2803ba6bf527e1d145d5fd6406c437b79bcaad6c7bdf1cf4bd56a893c3eb9510335a7a798548c6753f74617bede88bef924ba4b334f8852476d90b26c5dc4c3668a2519266a562c6c8034a6");
      (8,
      "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb725d6d46ceed8f785ab9f2f9b06acfe398c6699c6129da084cb531177445a682894f9685eaf836999221d17c9a64a3a057000524cd2823986db378b074290a1a9b93a22e135ed2c14c7e20c6d045cd00b903400374126676ea78874d79f2dd7883cf5c",
      "be2f5495c61cba1bb348a34948c004045e3bd4dae8f0fe82bf44d0da245a060048eb5e68ce6dea1eb0229e144f578b3aa7e9f4f85febd135df8525e6fe40c6f0340d13dd09b255ccd5112a94238f2be3c0b5b7ecde06580426a93e0708555a265305abf86d874e34b4995b788e37a823491f25127a502fe0704baa6bfdf04e76c13276");
      (63,
      "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b1197012b1e7d9af4d7cb7bdd1f3bb49a90a9b5dec3ea2bbc6eaebce77f4e470cbf4687093b5352f04e4a4570fba233164e6acc36900e35d185886a827f7ea9bdc1e5c3ce88b095a200e62c10c043b3e9bc6cb9b6ac4dfa51794b02ace9f98779040755",
      "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37aea05a63d74a840aecd514f654f080e51ac50fd617d22610d91780fe6b07a26b0847abb38291058c97474ef6ddd190d30fc318185c09ca1589d2024f0a6f16d45f11678377483fa5c005b2a107cb9943e5da634e7046855eaa888663de55d6471371d55d");
      (64,
      "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98fc9cc56cb831ffe33ea8e7e1d1df09b26efd2767670066aa82d023b1dfe8ab1b2b7fbb5b97592d46ffe3e05a6a9b592e2949c74160e4674301bc3f97e04903f8c6cf95b863174c33228924cdef7ae47559b10b294acd660666c4538833582b43f82d74",
      "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e68244c26010afc3f762615bbac552a1ca909e67c83e2fd5478cf46b9e811efccc93f77a21b17a152ebaca1695733fdb086e23cd0eb48c41c034d52523fc21236e5d8c9255306e48d52ba40b4dac24256460d56573d1312319afcf3ed39d72d0bfc69acb");
      (65,
      "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee0e16e0a4749d6811dd1d6d1265c29729b1b75a9ac346cf93f0e1d7296dfcfd4313b3a227faaaaf7757cc95b4e87a49be3b8a270a12020233509b1c3632b3485eef309d0abc4a4a696c9decc6e90454b53b000f456a3f10079072baaf7a981653221f2c",
      "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72d5e795f46a596b02d3d4bfb43abad1e5d19211152722ec1f20fef2cd413e3c22f2fc5da3d73041275be6ede3517b3b9f0fc67ade5956a672b8b75d96cb43294b9041497de92637ed3f2439225e683910cb3ae923374449ca788fb0f9bea92731bc26ad");
      (127,
      "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640de3137d477156d1fde56b0cf36f8ef18b44b2d79897bece12227539ac9ae0a5119da47644d934d26e74dc316145dcb8bb69ac3f2e05c242dd6ee06484fcb0e956dc44355b452c5e2bbb5e2b66e99f5dd443d0cbcaaafd4beebaed24ae2f8bb672bcef78",
      "c64200ae7dfaf35577ac5a9521c47863fb71514a3bcad18819218b818de85818ee7a317aaccc1458f78d6f65f3427ec97d9c0adb0d6dacd4471374b621b7b5f35cd54663c64dbe0b9e2d95632f84c611313ea5bd90b71ce97b3cf645776f3adc11e27d135cbadb9875c2bf8d3ae6b02f8a0206aba0c35bfe42574011931c9a255ce6dc");
      (128,
      "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45efa69faba091427f9c5c4caa873aa07828651f19c55bad85c47d1368b11c6fd99e47ecba5820a0325984d74fe3e4058494ca12e3f1d3293d0010a9722f7dee64f71246f75e9361f44cc8e214a100650db1313ff76a9f93ec6e84edb7add1cb4a95019b0c",
      "b04fe15577457267ff3b6f3c947d93be581e7e3a4b018679125eaf86f6a628ecd86bbe0001f10bda47e6077b735016fca8119da11348d93ca302bbd125bde0db2b50edbe728a620bb9d3e6f706286aedea973425c0b9eedf8a38873544cf91badf49ad92a635a93f71ddfcee1eae536c25d1b270956be16588ef1cfef2f1d15f650bd5");
      (129,
      "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12f96ffa7b36dd78ba321be7e842d364a62a42e3746681c8bace18a4a8a79649285c7127bf8febf125be9de39586d251f0d41da20980b70d35e3dac0eee59e468a894fa7e6a07129aaad09855f6ad4801512a116ba2b7841e6cfc99ad77594a8f2d181a7",
      "d4a64dae6cdccbac1e5287f54f17c5f985105457c1a2ec1878ebd4b57e20d38f1c9db018541eec241b748f87725665b7b1ace3e0065b29c3bcb232c90e37897fa5aaee7e1e8a2ecfcd9b51463e42238cfdd7fee1aecb3267fa7f2128079176132a412cd8aaf0791276f6b98ff67359bd8652ef3a203976d5ff1cd41885573487bcd683");
      (1023,
      "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11a182d27a591b05592b15607500e1e8dd56bc6c7fc063715b7a1d737df5bad3339c56778957d870eb9717b57ea3d9fb68d1b55127bba6a906a4a24bbd5acb2d123a37b28f9e9a81bbaae360d58f85e5fc9d75f7c370a0cc09b6522d9c8d822f2f28f485",
      "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e890316d2e6d8b8c25b0a5b2180f94fb1a158ef508c3cde45e2966bd796a696d3e13efd86259d756387d9becf5c8bf1ce2192b87025152907b6d8cc33d17826d8b7b9bc97e38c3c85108ef09f013e01c229c20a83d9e8efac5b37470da28575fd755a10");
      (1024,
      "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8107265ecdaf8505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404756f6eeae7883b446b70ebb144527c2075ab8ab204c0086bb22b7c93d465efc57f8d917f0b385c6df265e77003b85102967486ed57db5c5ca170ba441427ed9afa684e",
      "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4a78bc838c72852d4f49c864acb7adafe2478e824afe51c8919d06168414c265f298a8094b1ad813a9b8614acabac321f24ce61c5a5346eb519520d38ecc43e89b5000236df0597243e4d2493fd626730e2ba17ac4d8824d09d1a4a8f57b8227778e2de");
      (1025,
      "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bfe332b0ef84b409108cda080e6269ed4b3e2c3f7d722aa4cdc98d16deb554e5627be8f955c98e1d5f9565a9194cad0c4285f93700062d9595adb992ae68ff12800ab67a",
      "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69362396b77fdc0d2634a552970843722066c3c15902ae5097e00ff53f1e116f1cd5352720113a837ab2452cafbde4d54085d9cf5d21ca613071551b25d52e69d6c81123872b6f19cd3bc1333edf0c52b94de23ba772cf82636cff4542540a7738d5b930");
      (2048,
      "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a9a60bf80001410ec9eea6698cd537939fad4749edd484cb541aced55cd9bf54764d063f23f6f1e32e12958ba5cfeb1bf618ad094266d4fc3c968c2088f677454c288c67ba0dba337b9d91c7e1ba586dc9a5bc2d5e90c14f53a8863ac75655461cea8f9",
      "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd10173b961cd574288194b23ece278c330fbb8585485e74967f31352a8183aa782b2b22f26cdcadb61eed1a5bc144b8198fbb0c13abbf8e3192c145d0a5c21633b0ef86054f42809df823389ee40811a5910dcbd1018af31c3b43aa55201ed4edaac74fe");
      (2049,
      "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b687952256303096de31d71d74103403822a2e0bc1eb193e7aecc9643a76b7bbc0c9f9c52e8783aae98764ca468962b5c2ec92f0c74eb5448d519713e09413719431c802f948dd5d90425a4ecdadece9eb178d80f26efccae630734dff63340285adec2aed3b51073ad3",
      "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5f9a88abfefdfa1e00b418971f2b39c64ca621e8eb37fceac57fd0c8fc8e117d43b81447be22d5d8186f8f5919ba6bcc6846bd7d50726c06d245672c2ad4f61702c646499ee1173daa061ffe15bf45a631e2946d616a4c345822f1151284712f76b2b0e");
      (3072,
      "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd29a3f6b0b978d6608335c09dc94ccf682f9951cdfc501bfe47b9c9189a6fc7b404d120258506341a6d802857322fbd20d3e5dae05b95c88793fa83db1cb08e7d8008d1599b6209d78336e24839724c191b2a52a80448306e0daa84a3fdb566661a37e11",
      "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df19177022f302d0529e4174cc507c463671217975e81dab02b8fdeb0d7ccc7568dd22574c783a76be215441b32e91b9a904be8ea81f7a0afd14bad8ee7c8efc305ace5d3dd61b996febe8da4f56ca0919359a7533216e2999fc87ff7d8f176fbecb3d6f34278b");
      (3073,
      "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd39a27ae3b79d68d89da9bf25bc27139ae65a324918a5f9b7828181e52cf373c84f35b639b7fccbb985b6f2fa56aea0c18f531203497b8bbd3a07ceb5926f1cab74d14bd66486d9a91eba99059a98bd1cd25876b2af5a76c3e9eed554ed72ea952b603bf",
      "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a96d6da3fe985054d3478865be9a092250839a697bbda74e279e8a9e69f0025e4cfddd6cfb434b1cd9543aaf97c635d1b451a4386041e4bb100f5e45407cbbc24fa53ea2de3536ccb329e4eb9466ec37093a42cf62b82903c696a93a50b702c80f3c3c5");
      (4096,
      "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e9690289e9409ddb1b99768eafe1623da896faf7e1114bebeadc1be30829b6f8af707d85c298f4f0ff4d9438aef948335612ae921e76d411c3a9111df62d27eaf871959ae0062b5492a0feb98ef3ed4af277f5395172dbe5c311918ea0074ce0036454f620",
      "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0bbb64a36edb564e01e4b4aaf3b060092a6b838bea44afebd2deb8298fa562b7b597c757b9df4c911c3ca462e2ac89e9a787357aaf74c3b56d5c07bc93ce899568a3eb17d9250c20f6c5f6c1e792ec9a2dcb715398d5a6ec6d5c54f586a00403a1af1de");
      (4097,
      "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb99505f91b0b5600a11251652eacfa9497b31cd3c409ce2e45cfe6c0a016967316c426bd26f619eab5d70af9a418b845c608840390f361630bd497b1ab44019316357c61dbe091ce72fc16dc340ac3d6e009e050b3adac4b5b2c92e722cffdc46501531956",
      "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc606db4976cfdd266ae0abf667d9481831ff12e0caa268e7d3e57260c0824115a54ce595ccc897786d9dcbf495599cfd90157186a46ec800a6763f1c59e36197e9939e900809f7077c102f888caaf864b253bc41eea812656d46742e4ea42769f89b83f");
      (5120,
      "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833acc61c8fdc114a2010ce8038c853e121e1544985133fccdd0a2d507e8e615e611e9a0ba4f47915f49e53d721816a9198e8b30f12d20ec3689989175f1bf7a300eee0d9321fad8da232ece6efb8e9fd81b42ad161f6b9550a069e66b11b40487a5f5059",
      "2c493e48e9b9bf31e0553a22b23503c0a3388f035cece68eb438d22fa1943e209b4dc9209cd80ce7c1f7c9a744658e7e288465717ae6e56d5463d4f80cdb2ef56495f6a4f5487f69749af0c34c2cdfa857f3056bf8d807336a14d7b89bf62bef2fb54f9af6a546f818dc1e98b9e07f8a5834da50fa28fb5874af91bf06020d1bf0120e");
      (5121,
      "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff96adaab0613a6146cdaabe498c3a94e529d3fc1da2bd08edf54ed64d40dcd6777647eac51d8277d70219a9694334a68bc8f0f23e20b0ff70ada6f844542dfa32cd4204ca1846ef76d811cdb296f65e260227f477aa7aa008bac878f72257484f2b6c95",
      "6ccf1c34753e7a044db80798ecd0782a8f76f33563accaddbfbb2e0ea4b2d0240d07e63f13667a8d1490e5e04f13eb617aea16a8c8a5aaed1ef6fbde1b0515e3c81050b361af6ead126032998290b563e3caddeaebfab592e155f2e161fb7cba939092133f23f9e65245e58ec23457b78a2e8a125588aad6e07d7f11a85b88d375b72d");
      (6144,
      "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca2054d742022da6fdda444ebc384b04a54c3ac5839b49da7d39f6d8a9db03deab32aade156c1c0311e9b3435cde0ddba0dce7b26a376cad121294b689193508dd63151603c6ddb866ad16c2ee41585d1633a2cea093bea714f4c5d6b903522045b20395c83",
      "3d6b6d21281d0ade5b2b016ae4034c5dec10ca7e475f90f76eac7138e9bc8f1dc35754060091dc5caf3efabe0603c60f45e415bb3407db67e6beb3d11cf8e4f7907561f05dace0c15807f4b5f389c841eb114d81a82c02a00b57206b1d11fa6e803486b048a5ce87105a686dee041207e095323dfe172df73deb8c9532066d88f9da7e");
      (6145,
      "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f18a2cfdd73c6e39dd75ce7c1c6e3ef238fd54465f053b25d21044ccb2093beb015015532b108313b5829c3621ce324b8e14229091b7c93f32db2e4e63126a377d2a63a3597997d4f1cba59309cb4af240ba70cebff9a23d5e3ff0cdae2cfd54e070022",
      "9ac301e9e39e45e3250a7e3b3df701aa0fb6889fbd80eeecf28dbc6300fbc539f3c184ca2f59780e27a576c1d1fb9772e99fd17881d02ac7dfd39675aca918453283ed8c3169085ef4a466b91c1649cc341dfdee60e32231fc34c9c4e0b9a2ba87ca8f372589c744c15fd6f985eec15e98136f25beeb4b13c4e43dc84abcc79cd4646c");
      (7168,
      "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a5707c321c83361793b9af62a40f43b523df1c8633cecb4cd14d00bdc79c78fca5165b863893f6d38b02ff7236c5a9a8ad2dba87d24c547cab046c29fc5bc1ed142e1de4763613bb162a5a538e6ef05ed05199d751f9eb58d332791b8d73fb74e4fce95",
      "b42835e40e9d4a7f42ad8cc04f85a963a76e18198377ed84adddeaecacc6f3fca2f01d5277d69bb681c70fa8d36094f73ec06e452c80d2ff2257ed82e7ba348400989a65ee8daa7094ae0933e3d2210ac6395c4af24f91c2b590ef87d7788d7066ea3eaebca4c08a4f14b9a27644f99084c3543711b64a070b94f2c9d1d8a90d035d52");
      (7169,
      "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e781798a8b20534be1ca9eb2ae2df3fae2ea60e48c6fb0b850b1385b5de0fe460dbe9d9f9b0d8db4435da75c601156df9d047f4ede008732eb17adc05d96180f8a73548522840779e6062d643b79478a6e8dbce68927f36ebf676ffa7d72d5f68f050b119c8",
      "ed9b1a922c046fdb3d423ae34e143b05ca1bf28b710432857bf738bcedbfa5113c9e28d72fcbfc020814ce3f5d4fc867f01c8f5b6caf305b3ea8a8ba2da3ab69fabcb438f19ff11f5378ad4484d75c478de425fb8e6ee809b54eec9bdb184315dc856617c09f5340451bf42fd3270a7b0b6566169f242e533777604c118a6358250f54");
      (8192,
      "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a635fe51a27db045a567c1ad51be5aa34c01c6651c4d9b5b5ac5d0fd58cf18dd61a47778566b797a8c67df7b1d60b97b19288d2d877bb2df417ace009dcb0241ca1257d62712b6a4043b4ff33f690d849da91ea3bf711ed583cb7b7a7da2839ba71309bbf",
      "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a4834464159dcbc12a0ba0c6d6eb41bac0ed6585cabfe0aca36a375e6c5480c22afdc40785c170f5a6b8a1107dbee282318d00d915ac9ed1143ad40765ec120042ee121cd2baa36250c618adaf9e27260fda2f94dea8fb6f08c04f8f10c78292aa46102");
      (8193,
      "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3bb2282aa69be089359ea1154b9a9286c4a56af4de975a9aa4a5c497654914d279bea60bb6d2cf7225a2fa0ff5ef56bbe4b149f3ed15860f78b4e2ad04e158e375c1e0c0b551cd7dfc82f1b155c11b6b3ed51ec9edb30d133653bb5709d1dbd55f4e1ff6",
      "954a2a75420c8d6547e3ba5b98d963e6fa6491addc8c023189cc519821b4a1f5f03228648fd983aef045c2fa8290934b0866b615f585149587dda2299039965328835a2b18f1d63b7e300fc76ff260b571839fe44876a4eae66cbac8c67694411ed7e09df51068a22c6e67d6d3dd2cca8ff12e3275384006c80f4db68023f24eebba57");
      (16384,
      "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde49d764c270176e53e97bdffa58d549073f2c660be0e81293767ed4e4929f9ad34bbb39a529334c57c4a381ffd2a6d4bfdbf1482651b172aa883cc13408fa67758a3e47503f93f87720a3177325f7823251b85275f64636a8f1d599c2e49722f42e93893",
      "9e9fc4eb7cf081ea7c47d1807790ed211bfec56aa25bb7037784c13c4b707b0df9e601b101e4cf63a404dfe50f2e1865bb12edc8fca166579ce0c70dba5a5c0fc960ad6f3772183416a00bd29d4c6e651ea7620bb100c9449858bf14e1ddc9ecd35725581ca5b9160de04060045993d972571c3e8f71e9d0496bfa744656861b169d65");
      (31744,
      "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47860cc51f2b0c28a7b77304bd55fe73af663c02d3f52ea053ba43431ca5bab7bfea2f5e9d7121770d88f70ae9649ea713087d1914f7f312147e247f87eb2d4ffef0ac978bf7b6579d57d533355aa20b8b77b13fd09748728a5cc327a8ec470f4013226f",
      "efa53b389ab67c593dba624d898d0f7353ab99e4ac9d42302ee64cbf9939a4193a7258db2d9cd32a7a3ecfce46144114b15c2fcb68a618a976bd74515d47be08b628be420b5e830fade7c080e351a076fbc38641ad80c736c8a18fe3c66ce12f95c61c2462a9770d60d0f77115bbcd3782b593016a4e728d4c06cee4505cb0c08a42ec");
      (102400,
      "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085e01c59dab908c04c3342b816941a26d69c2605ebee5ec5291cc55e15b76146e6745f0601156c3596cb75065a9c57f35585a52e1ac70f69131c23d611ce11ee4ab1ec2c009012d236648e77be9295dd0426f29b764d65de58eb7d01dd42248204f45f8e",
      "1c35d1a5811083fd7119f5d5d1ba027b4d01c0c6c49fb6ff2cf75393ea5db4a7f9dbdd3e1d81dcbca3ba241bb18760f207710b751846faaeb9dff8262710999a59b2aa1aca298a032d94eacfadf1aa192418eb54808db23b56e34213266aa08499a16b354f018fc4967d05f8b9d2ad87a7278337be9693fc638a3bfdbe314574ee6fc4");
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

(* GHASH *)

module GHash = struct
  type t
  external init: string -> t = "caml_ghash_init"
  external mult: t -> bytes -> unit = "caml_ghash_mult"
  let mul x y =
    let g = init x and h = Bytes.of_string y in
    mult g h;
    Bytes.to_string h
  let _ =
    testing_function "GFmul";
    test 1 (mul (hex "dfa6bf4ded81db03ffcaff95f830f061")
                (hex "952b2a56a5604ac0b32b6656a05b40b6"))
           (hex "da53eb0ad2c55bb64fc4802cc3feda60")
end

(* Poly1305 *)

module Poly1305 = struct
  external poly1305_init: string -> bytes = "caml_poly1305_init"
  external poly1305_update: bytes -> bytes -> int -> int -> unit = "caml_poly1305_update"
  external poly1305_final: bytes -> string = "caml_poly1305_final"
  let _ =
    testing_function "Poly1305";
    let key = String.init 32 (fun i -> Char.chr (i + 221))
    and msg = Bytes.init  73 (fun i -> Char.chr (i + 121)) in
    let h = poly1305_init key in
    poly1305_update h msg 0 73;
    let mac = poly1305_final h in
    test 1 mac (hex "dd b9 da 7d dd 5e 52 79 27 30 ed 5c da 5f 90 a4")
end

(* SipHash *)

let testsip mac vectors =
  let key = String.init 16 Char.chr in
  List.iteri
    (fun i result ->
      let input = String.init i Char.chr in
      test i (hash_string (mac key) input) (hex result))
    vectors

let _ =
  testing_function "SipHash 64";
  testsip MAC.siphash [
  "310e0edd47db6f72";
  "fd67dc93c539f874";
  "5a4fa9d909806c0d";
  "2d7efbd796666785";
  "b7877127e09427cf";
  "8da699cd64557618";
  "cee3fe586e46c9cb";
  "37d1018bf50002ab";
  "6224939a79f5f593";
  "b0e4a90bdf82009e";
  "f3b9dd94c5bb5d7a";
  "a7ad6b22462fb3f4";
  "fbe50e86bc8f1e75";
  "903d84c02756ea14";
  "eef27a8e90ca23f7";
  "e545be4961ca29a1";
  "db9bc2577fcc2a3f";
  "9447be2cf5e99a69";
  "9cd38d96f0b3c14b";
  "bd6179a71dc96dbb";
  "98eea21af25cd6be";
  "c7673b2eb0cbf2d0";
  "883ea3e395675393";
  "c8ce5ccd8c030ca8";
  "94af49f6c650adb8";
  "eab8858ade92e1bc";
  "f315bb5bb835d817";
  "adcf6b0763612e2f";
  "a5c91da7acaa4dde";
  "716595876650a2a6";
  "28ef495c53a387ad";
  "42c341d8fa92d832";
  "ce7cf2722f512771";
  "e37859f94623f3a7";
  "381205bb1ab0e012";
  "ae97a10fd434e015";
  "b4a31508beff4d31";
  "81396229f0907902";
  "4d0cf49ee5d4dcca";
  "5c73336a76d8bf9a";
  "d0a704536ba93e0e";
  "925958fcd6420cad";
  "a915c29bc8067318";
  "952b79f3bc0aa6d4";
  "f21df2e41d4535f9";
  "87577519048f53a9";
  "10a56cf5dfcd9adb";
  "eb75095ccd986cd0";
  "51a9cb9ecba312e6";
  "96afadfc2ce666c7";
  "72fe52975a4364ee";
  "5a1645b276d592a1";
  "b274cb8ebf87870a";
  "6f9bb4203de7b381";
  "eaecb2a30b22a87f";
  "9924a43cc1315724";
  "bd838d3aafbf8db7";
  "0b1a2a3265d51aea";
  "135079a3231ce660";
  "932b2846e4d70666";
  "e1915f5cb1eca46c";
  "f325965ca16d629f";
  "575ff28e60381be5";
  "724506eb4c328a95"
  ];
  testing_function "SipHash 128";
  testsip MAC.siphash128 [
  "a3817f04ba25a8e66df67214c7550293";
  "da87c1d86b99af44347659119b22fc45";
  "8177228da4a45dc7fca38bdef60affe4";
  "9c70b60c5267a94e5f33b6b02985ed51";
  "f88164c12d9c8faf7d0f6e7c7bcd5579";
  "1368875980776f8854527a07690e9627";
  "14eeca338b208613485ea0308fd7a15e";
  "a1f1ebbed8dbc153c0b84aa61ff08239";
  "3b62a9ba6258f5610f83e264f31497b4";
  "264499060ad9baabc47f8b02bb6d71ed";
  "00110dc378146956c95447d3f3d0fbba";
  "0151c568386b6677a2b4dc6f81e5dc18";
  "d626b266905ef35882634df68532c125";
  "9869e247e9c08b10d029934fc4b952f7";
  "31fcefac66d7de9c7ec7485fe4494902";
  "5493e99933b0a8117e08ec0f97cfc3d9";
  "6ee2a4ca67b054bbfd3315bf85230577";
  "473d06e8738db89854c066c47ae47740";
  "a426e5e423bf4885294da481feaef723";
  "78017731cf65fab074d5208952512eb1";
  "9e25fc833f2290733e9344a5e83839eb";
  "568e495abe525a218a2214cd3e071d12";
  "4a29b54552d16b9a469c10528eff0aae";
  "c9d184ddd5a9f5e0cf8ce29a9abf691c";
  "2db479ae78bd50d8882a8a178a6132ad";
  "8ece5f042d5e447b5051b9eacb8d8f6f";
  "9c0b53b4b3c307e87eaee08678141f66";
  "abf248af69a6eae4bfd3eb2f129eeb94";
  "0664da1668574b88b935f3027358aef4";
  "aa4b9dc4bf337de90cd4fd3c467c6ab7";
  "ea5c7f471faf6bde2b1ad7d4686d2287";
  "2939b0183223fafc1723de4f52c43d35";
  "7c3956ca5eeafc3e363e9d556546eb68";
  "77c6077146f01c32b6b69d5f4ea9ffcf";
  "37a6986cb8847edf0925f0f1309b54de";
  "a705f0e69da9a8f907241a2e923c8cc8";
  "3dc47d1f29c448461e9e76ed904f6711";
  "0d62bf01e6fc0e1a0d3c4751c5d3692b";
  "8c03468bca7c669ee4fd5e084bbee7b5";
  "528a5bb93baf2c9c4473cce5d0d22bd9";
  "df6a301e95c95dad97ae0cc8c6913bd8";
  "801189902c857f39e73591285e70b6db";
  "e617346ac9c231bb3650ae34ccca0c5b";
  "27d93437efb721aa401821dcec5adf89";
  "89237d9ded9c5e78d8b1c9b166cc7342";
  "4a6d8091bf5e7d651189fa94a250b14c";
  "0e33f96055e7ae893ffc0e3dcf492902";
  "e61c432b720b19d18ec8d84bdc63151b";
  "f7e5aef549f782cf379055a608269b16";
  "438d030fd0b7a54fa837f2ad201a6403";
  "a590d3ee4fbf04e3247e0d27f286423f";
  "5fe2c1a172fe93c4b15cd37caef9f538";
  "2c97325cbd06b36eb2133dd08b3a017c";
  "92c814227a6bca949ff0659f002ad39e";
  "dce850110bd8328cfbd50841d6911d87";
  "67f14984c7da791248e32bb5922583da";
  "1938f2cf72d54ee97e94166fa91d2a36";
  "74481e9646ed49fe0f6224301604698e";
  "57fca5de98a9d6d8006438d0583d8a1d";
  "9fecde1cefdc1cbed4763674d9575359";
  "e3040c00eb28f15366ca73cbd872e740";
  "7697009a6a831dfecca91c5993670f7a";
  "5853542321f567a005d547a4f04759bd";
  "5150d1772f50834a503e069a973fbd7c";
  ]

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

let _ =
  testing_function "CTR_N";
  test_enc_dec 1 (des ~mode:(CTR_N 1)) "abcdefgh";
  let test_overflow len =
    try ignore(transform_string (des ~mode:(CTR_N 1) some_key Encrypt)
                                (String.make len 'x'));
        false
    with Error Message_too_long ->
        true
  in
  test 2 (test_overflow (256 * 8)) true;
  test 3 (test_overflow (255 * 8)) false

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

(* HMAC-SHA384 *)

let _ =
  testing_function "HMAC-SHA384";
  List.iter
    (fun (testno, hexkey, hexmsg, hexhash) ->
      test testno
        (hash_string (MAC.hmac_sha384 (hex hexkey)) (hex hexmsg))
        (hex hexhash))
 [(1,
   "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\
    0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\
    0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b\
    0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
   "4869205468657265",
   "51b2151ae771770f36cc6c5d63de41fc\
    febab0900a22b41cb81e12209215337e\
    5d5384201f6dc3ca9f92764c503380e6");
  (2,
   "4a6566654a6566654a6566654a656665\
    4a6566654a6566654a6566654a656665\
    4a6566654a6566654a6566654a656665\
    4a6566654a6566654a6566654a656665",
   "7768617420646f2079612077616e7420\
    666f72206e6f7468696e673f",
   "b57bd579eda34ac3f203e28660ed9992\
    f7400d147af77a297b8a8a052e0d7eaa\
    f54288f8a219dc55b49bb3147271f0b7");
  (3,
   "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\
    aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
   "dddddddddddddddddddddddddddddddd\
    dddddddddddddddddddddddddddddddd\
    dddddddddddddddddddddddddddddddd\
    dddd",
   "0b97cc8c49ef7ad3abd3e459c1084409\
    a1778f0bd832e2126d25c93f7524b272\
    a94f86587d874fefb80309910e70d958")]

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

