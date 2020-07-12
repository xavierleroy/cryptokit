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

let wipe_bytes s = Bytes.fill s 0 (Bytes.length s) '\000'
let wipe_string s = wipe_bytes (Bytes.unsafe_of_string s)

let shl1_bytes src soff dst doff len =
  let rec shl1 carry i =
    if i >= 0 then begin
      let n = Char.code (Bytes.get src (soff + i)) in
      Bytes.set dst (doff + i) (Char.unsafe_chr ((n lsl 1) lor carry));
      shl1 (n lsr 7) (i - 1)
    end
  in shl1 0 (len - 1)

type error =
  | Wrong_key_size
  | Wrong_IV_size
  | Wrong_data_length
  | Bad_padding
  | Output_buffer_overflow
  | Incompatible_block_size
  | Number_too_long
  | Seed_too_short
  | Message_too_long
  | Bad_encoding
  | Compression_error of string * string
  | No_entropy_source
  | Entropy_source_closed
  | Compression_not_supported

exception Error of error

let _ = Callback.register_exception "Cryptokit.Error" (Error Wrong_key_size)

(* Interface with C *)

type dir = Encrypt | Decrypt

external xor_bytes: bytes -> int -> bytes -> int -> int -> unit = "caml_xor_string"
external xor_string: string -> int -> bytes -> int -> int -> unit = "caml_xor_string"
external aes_cook_encrypt_key : string -> bytes = "caml_aes_cook_encrypt_key"
external aes_cook_decrypt_key : string -> bytes = "caml_aes_cook_decrypt_key"
external aes_encrypt : bytes -> bytes -> int -> bytes -> int -> unit = "caml_aes_encrypt"
external aes_decrypt : bytes -> bytes -> int -> bytes -> int -> unit = "caml_aes_decrypt"
external blowfish_cook_key : string -> bytes = "caml_blowfish_cook_key"
external blowfish_encrypt : bytes -> bytes -> int -> bytes -> int -> unit = "caml_blowfish_encrypt"
external blowfish_decrypt : bytes -> bytes -> int -> bytes -> int -> unit = "caml_blowfish_decrypt"
external des_cook_key : string -> int -> dir -> bytes = "caml_des_cook_key"
external des_transform : bytes -> bytes -> int -> bytes -> int -> unit = "caml_des_transform"
external arcfour_cook_key : string -> bytes = "caml_arcfour_cook_key"
external arcfour_transform : bytes -> bytes -> int -> bytes -> int -> int -> unit = "caml_arcfour_transform_bytecode" "caml_arcfour_transform"
external chacha20_cook_key : string -> bytes -> int64 -> bytes = "caml_chacha20_cook_key"
external chacha20_transform : bytes -> bytes -> int -> bytes -> int -> int -> unit = "caml_chacha20_transform_bytecode" "caml_chacha20_transform"
external chacha20_extract : bytes -> bytes -> int -> int -> unit = "caml_chacha20_extract"

external sha1_init: unit -> bytes = "caml_sha1_init"
external sha1_update: bytes -> bytes -> int -> int -> unit = "caml_sha1_update"
external sha1_final: bytes -> string = "caml_sha1_final"
external sha256_init: unit -> bytes = "caml_sha256_init"
external sha224_init: unit -> bytes = "caml_sha224_init"
external sha256_update: bytes -> bytes -> int -> int -> unit = "caml_sha256_update"
external sha256_final: bytes -> string = "caml_sha256_final"
external sha224_final: bytes -> string = "caml_sha224_final"
external sha512_init: unit -> bytes = "caml_sha512_init"
external sha384_init: unit -> bytes = "caml_sha384_init"
external sha512_update: bytes -> bytes -> int -> int -> unit = "caml_sha512_update"
external sha512_final: bytes -> string = "caml_sha512_final"
external sha384_final: bytes -> string = "caml_sha384_final"
type sha3_context
external sha3_init: int -> sha3_context = "caml_sha3_init"
external sha3_absorb: sha3_context -> bytes -> int -> int -> unit = "caml_sha3_absorb"
external sha3_extract: bool -> sha3_context -> string = "caml_sha3_extract"
external sha3_wipe: sha3_context -> unit = "caml_sha3_wipe"
external ripemd160_init: unit -> bytes = "caml_ripemd160_init"
external ripemd160_update: bytes -> bytes -> int -> int -> unit = "caml_ripemd160_update"
external ripemd160_final: bytes -> string = "caml_ripemd160_final"
external md5_init: unit -> bytes = "caml_md5_init"
external md5_update: bytes -> bytes -> int -> int -> unit = "caml_md5_update"
external md5_final: bytes -> string = "caml_md5_final"
external blake2b_init: int -> string -> bytes = "caml_blake2b_init"
external blake2b_update: bytes -> bytes -> int -> int -> unit = "caml_blake2b_update"
external blake2b_final: bytes -> int -> string = "caml_blake2b_final"
external blake2s_init: int -> string -> bytes = "caml_blake2s_init"
external blake2s_update: bytes -> bytes -> int -> int -> unit = "caml_blake2s_update"
external blake2s_final: bytes -> int -> string = "caml_blake2s_final"

(* Abstract transform type *)

class type transform =
  object
    method input_block_size: int
    method output_block_size: int

    method put_substring: bytes -> int -> int -> unit
    method put_string: string -> unit
    method put_char: char -> unit
    method put_byte: int -> unit

    method finish: unit
    method flush: unit

    method available_output: int

    method get_string: string
    method get_substring: bytes * int * int
    method get_char: char
    method get_byte: int

    method wipe: unit
  end

let transform_string tr s =
  tr#put_string s;
  tr#finish;
  let r = tr#get_string in tr#wipe; r

let transform_channel tr ?len ic oc =
  let ibuf = Bytes.create 256 in
  let rec transf_to_eof () =
    let r = input ic ibuf 0 256 in
    if r > 0 then begin
      tr#put_substring ibuf 0 r;
      let (obuf, opos, olen) = tr#get_substring in
      output oc obuf opos olen;
      transf_to_eof()
    end
  and transf_bounded numleft =
    if numleft > 0 then begin
      let r = input ic ibuf 0 (min 256 numleft) in
      if r = 0 then raise End_of_file;
      tr#put_substring ibuf 0 r;
      let (obuf, opos, olen) = tr#get_substring in
      output oc obuf opos olen;
      transf_bounded (numleft - r)
    end in
  begin match len with
      None -> transf_to_eof ()
    | Some l -> transf_bounded l
  end;
  wipe_bytes ibuf;
  tr#finish;
  let (obuf, opos, olen) = tr#get_substring in
  output oc obuf opos olen;
  tr#wipe  

class compose (tr1 : transform) (tr2 : transform) =
  object(self)
    method input_block_size = tr1#input_block_size
    method output_block_size = tr2#output_block_size

    method put_substring buf ofs len =
      tr1#put_substring buf ofs len; self#transfer
    method put_string s =
      tr1#put_string s; self#transfer
    method put_char c =
      tr1#put_char c; self#transfer
    method put_byte b =
      tr1#put_byte b; self#transfer

    method private transfer =
      let (buf, ofs, len) = tr1#get_substring in
      tr2#put_substring buf ofs len

    method available_output = tr2#available_output
    method get_string = tr2#get_string
    method get_substring = tr2#get_substring
    method get_char = tr2#get_char
    method get_byte = tr2#get_byte

    method flush = tr1#flush; self#transfer; tr2#flush
    method finish = tr1#finish; self#transfer; tr2#finish

    method wipe = tr1#wipe; tr2#wipe
  end

let compose tr1 tr2 = new compose tr1 tr2

class type hash =
  object
    method hash_size: int
    method add_substring: bytes -> int -> int -> unit
    method add_string: string -> unit
    method add_char: char -> unit
    method add_byte: int -> unit
    method result: string
    method wipe: unit
  end

let hash_string hash s =
  hash#add_string s;
  let r = hash#result in
  hash#wipe;
  r

let hash_channel hash ?len ic =
  let ibuf = Bytes.create 256 in
  let rec hash_to_eof () =
    let r = input ic ibuf 0 256 in
    if r > 0 then begin
      hash#add_substring ibuf 0 r;
      hash_to_eof()
    end
  and hash_bounded numleft =
    if numleft > 0 then begin
      let r = input ic ibuf 0 (min 256 numleft) in
      if r = 0 then raise End_of_file;
      hash#add_substring ibuf 0 r;
      hash_bounded (numleft - r)
    end in
  begin match len with
      None -> hash_to_eof ()
    | Some l -> hash_bounded l
  end;
  wipe_bytes ibuf;
  let res = hash#result in
  hash#wipe;
  res

(* Padding schemes *)

module Padding = struct

class type scheme =
  object
    method pad: bytes -> int -> unit
    method strip: bytes -> int
  end

class length =
  object
    method pad buffer used =
      let n = Bytes.length buffer - used in
      assert (n > 0 && n < 256);
      Bytes.fill buffer used n (Char.chr n)
    method strip buffer =
      let blocksize = Bytes.length buffer in
      let n = Char.code (Bytes.get buffer (blocksize - 1)) in
      if n = 0 || n > blocksize then raise (Error Bad_padding);
      (* Characters blocksize - n to blocksize - 1 must be equal to n *)
      for i = blocksize - n to blocksize - 2 do
        if Char.code (Bytes.get buffer i) <> n then raise (Error Bad_padding)
      done;
      blocksize - n
  end

let length = new length

class _8000 =
  object
    method pad buffer used =
      Bytes.set buffer used '\128';
      for i = used + 1 to Bytes.length buffer - 1 do
        Bytes.set buffer i '\000'
      done
    method strip buffer =
      let rec strip pos =
        if pos < 0 then raise (Error Bad_padding) else
          match Bytes.get buffer pos with
            '\128' -> pos
          | '\000' -> strip (pos - 1)
          |    _   -> raise (Error Bad_padding)
      in strip (Bytes.length buffer - 1)
  end

let _8000 = new _8000

end

(* Generic handling of output buffering *)

class buffered_output initial_buffer_size =
  object(self)
    val mutable obuf = Bytes.create initial_buffer_size
    val mutable obeg = 0
    val mutable oend = 0

    method private ensure_capacity n =
      let len = Bytes.length obuf in
      if oend + n > len then begin
        if oend - obeg + n < len then begin
          Bytes.blit obuf obeg obuf 0 (oend - obeg);
          oend <- oend - obeg;
          obeg <- 0
        end else begin
          let newlen = ref (2 * len) in
          while oend - obeg + n > (!newlen) do
            newlen := (!newlen) * 2
          done;
          if (!newlen) > Sys.max_string_length then begin
            if (oend - obeg + n) <= Sys.max_string_length then
              newlen := Sys.max_string_length
            else
              raise (Error Output_buffer_overflow)
          end;
          let newbuf = Bytes.create (!newlen) in
          Bytes.blit obuf obeg newbuf 0 (oend - obeg);
          obuf <- newbuf;
          oend <- oend - obeg;
          obeg <- 0
        end
      end

    method available_output = oend - obeg

    method get_substring =
      let res = (obuf, obeg, oend - obeg) in obeg <- 0; oend <- 0; res

    method get_string =
      let res = Bytes.sub_string obuf obeg (oend - obeg) in obeg <- 0; oend <- 0; res

    method get_char =
      if obeg >= oend then raise End_of_file;
      let r = Bytes.get obuf obeg in
      obeg <- obeg + 1;
      r

    method get_byte =
      Char.code self#get_char          

    method wipe =
      wipe_bytes obuf
  end

(* Block ciphers *)

module Block = struct

class type block_cipher =
  object
    method blocksize: int
    method transform: bytes -> int -> bytes -> int -> unit
    method wipe: unit
  end

class aes_encrypt key =
  object
    val ckey =
      let kl = String.length key in
      if kl = 16 || kl = 24 || kl = 32
      then aes_cook_encrypt_key key
      else raise(Error Wrong_key_size)
    method blocksize = 16
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs > Bytes.length src - 16
      || dst_ofs < 0 || dst_ofs > Bytes.length dst - 16
      then invalid_arg "aes#transform";
      aes_encrypt ckey src src_ofs dst dst_ofs
    method wipe =
      wipe_bytes ckey;
      Bytes.set ckey (Bytes.length ckey - 1) '\016'
  end

class aes_decrypt key =
  object
    val ckey =
      let kl = String.length key in
      if kl = 16 || kl = 24 || kl = 32
      then aes_cook_decrypt_key key
      else raise(Error Wrong_key_size)
    method blocksize = 16
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs > Bytes.length src - 16
      || dst_ofs < 0 || dst_ofs > Bytes.length dst - 16
      then invalid_arg "aes#transform";
      aes_decrypt ckey src src_ofs dst dst_ofs
    method wipe =
      wipe_bytes ckey;
      Bytes.set ckey (Bytes.length ckey - 1) '\016'
  end

class blowfish_encrypt key =
  object
    val ckey =
      let kl = String.length key in
      if kl >= 4 && kl <= 56
      then blowfish_cook_key key
      else raise(Error Wrong_key_size)
    method blocksize = 8
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs > Bytes.length src - 8
      || dst_ofs < 0 || dst_ofs > Bytes.length dst - 8
      then invalid_arg "blowfish#transform";
      blowfish_encrypt ckey src src_ofs dst dst_ofs
    method wipe =
      wipe_bytes ckey
  end

class blowfish_decrypt key =
  object
    val ckey =
      let kl = String.length key in
      if kl >= 4 && kl <= 56
      then blowfish_cook_key key
      else raise(Error Wrong_key_size)
    method blocksize = 8
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs > Bytes.length src - 8
      || dst_ofs < 0 || dst_ofs > Bytes.length dst - 8
      then invalid_arg "blowfish#transform";
      blowfish_decrypt ckey src src_ofs dst dst_ofs
    method wipe =
      wipe_bytes ckey
  end

class des direction key =
  object
    val ckey =
      if String.length key = 8
      then des_cook_key key 0 direction
      else raise(Error Wrong_key_size)
    method blocksize = 8
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs > Bytes.length src - 8
      || dst_ofs < 0 || dst_ofs > Bytes.length dst - 8
      then invalid_arg "des#transform";
      des_transform ckey src src_ofs dst dst_ofs
    method wipe =
      wipe_bytes ckey
  end

class des_encrypt = des Encrypt
class des_decrypt = des Decrypt

class triple_des_encrypt key =
  let _ =
    let kl = String.length key in
    if kl <> 16 && kl <> 24 then raise (Error Wrong_key_size) in
  let ckey1 =
    des_cook_key key 0 Encrypt in
  let ckey2 =
    des_cook_key key 8 Decrypt in
  let ckey3 =
    if String.length key = 24
    then des_cook_key key 16 Encrypt
    else ckey1 in
  object
    method blocksize = 8
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs > Bytes.length src - 8
      || dst_ofs < 0 || dst_ofs > Bytes.length dst - 8
      then invalid_arg "triple_des#transform";
      des_transform ckey1 src src_ofs dst dst_ofs;
      des_transform ckey2 dst dst_ofs dst dst_ofs;
      des_transform ckey3 dst dst_ofs dst dst_ofs
    method wipe =
      wipe_bytes ckey1;
      wipe_bytes ckey2;
      wipe_bytes ckey3
  end

class triple_des_decrypt key =
  let _ =
    let kl = String.length key in
    if kl <> 16 && kl <> 24 then raise (Error Wrong_key_size) in
  let ckey3 =
    des_cook_key key 0 Decrypt in
  let ckey2 =
    des_cook_key key 8 Encrypt in
  let ckey1 =
    if String.length key = 24
    then des_cook_key key 16 Decrypt
    else ckey3 in
  object
    method blocksize = 8
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs > Bytes.length src - 8
      || dst_ofs < 0 || dst_ofs > Bytes.length dst - 8
      then invalid_arg "triple_des#transform";
      des_transform ckey1 src src_ofs dst dst_ofs;
      des_transform ckey2 dst dst_ofs dst dst_ofs;
      des_transform ckey3 dst dst_ofs dst dst_ofs
    method wipe =
      wipe_bytes ckey1;
      wipe_bytes ckey2;
      wipe_bytes ckey3
  end

(* Chaining modes *)

let make_initial_iv blocksize = function
  | None ->
      Bytes.make blocksize '\000'
  | Some s ->
      if String.length s <> blocksize then raise (Error Wrong_IV_size);
      Bytes.of_string s

class cbc_encrypt ?iv:iv_init (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    method blocksize = blocksize
    method transform src src_off dst dst_off =
      xor_bytes src src_off iv 0 blocksize;
      cipher#transform iv 0 dst dst_off;
      Bytes.blit dst dst_off iv 0 blocksize
    method wipe =
      cipher#wipe;
      wipe_bytes iv
  end

class cbc_decrypt ?iv:iv_init (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    val next_iv = Bytes.create blocksize
    method blocksize = blocksize
    method transform src src_off dst dst_off =
      Bytes.blit src src_off next_iv 0 blocksize;
      cipher#transform src src_off dst dst_off;
      xor_bytes iv 0 dst dst_off blocksize;
      Bytes.blit next_iv 0 iv 0 blocksize
    method wipe =
      cipher#wipe;
      wipe_bytes iv;
      wipe_bytes next_iv
  end

class cfb_encrypt ?iv:iv_init chunksize (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  let _ = assert (chunksize > 0 && chunksize <= blocksize) in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    val out = Bytes.create blocksize
    method blocksize = chunksize
    method transform src src_off dst dst_off =
      cipher#transform iv 0 out 0;
      Bytes.blit src src_off dst dst_off chunksize;
      xor_bytes out 0 dst dst_off chunksize;
      Bytes.blit iv chunksize iv 0 (blocksize - chunksize);
      Bytes.blit dst dst_off iv (blocksize - chunksize) chunksize
    method wipe =
      cipher#wipe;
      wipe_bytes iv;
      wipe_bytes out
  end

class cfb_decrypt ?iv:iv_init chunksize (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  let _ = assert (chunksize > 0 && chunksize <= blocksize) in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    val out = Bytes.create blocksize
    method blocksize = chunksize
    method transform src src_off dst dst_off =
      cipher#transform iv 0 out 0;
      Bytes.blit iv chunksize iv 0 (blocksize - chunksize);
      Bytes.blit src src_off iv (blocksize - chunksize) chunksize;
      Bytes.blit src src_off dst dst_off chunksize;
      xor_bytes out 0 dst dst_off chunksize
    method wipe =
      cipher#wipe;
      wipe_bytes iv;
      wipe_bytes out
  end

class ofb ?iv:iv_init chunksize (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  let _ = assert (chunksize > 0 && chunksize <= blocksize) in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    method blocksize = chunksize
    method transform src src_off dst dst_off =
      cipher#transform iv 0 iv 0;
      Bytes.blit src src_off dst dst_off chunksize;
      xor_bytes iv 0 dst dst_off chunksize
    method wipe =
      cipher#wipe;
      wipe_bytes iv
  end

let rec increment_counter c lim pos =
  if pos >= lim then begin
    let i = 1 + Char.code (Bytes.get c pos) in
    Bytes.set c pos (Char.unsafe_chr i);
    if i = 0x100 then increment_counter c lim (pos - 1)
  end

class ctr ?iv:iv_init ?inc (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  let nincr =
    match inc with
    | None -> blocksize
    | Some n -> assert (n > 0 && n <= blocksize); n in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    val out = Bytes.create blocksize
    method blocksize = blocksize
    method transform src src_off dst dst_off =
      cipher#transform iv 0 out 0;
      Bytes.blit src src_off dst dst_off blocksize;
      xor_bytes out 0 dst dst_off blocksize;
      increment_counter iv (blocksize - nincr) (blocksize - 1)
    method wipe =
      cipher#wipe;
      wipe_bytes iv;
      wipe_bytes out
  end

(* Wrapping of a block cipher as a transform *)

class cipher (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  object(self)
    val ibuf = Bytes.create blocksize
    val mutable used = 0

    inherit buffered_output (max 256 (2 * blocksize)) as output_buffer

    method input_block_size = blocksize
    method output_block_size = blocksize

    method put_substring src ofs len =
      if len <= 0 then () else
      if used + len <= blocksize then begin
        (* Just accumulate len characters in ibuf *)
        Bytes.blit src ofs ibuf used len;
        used <- used + len
      end else begin
        (* Fill buffer and run it through cipher *)
        let n = blocksize - used in
        Bytes.blit src ofs ibuf used n;
        self#ensure_capacity blocksize;
        cipher#transform ibuf 0 obuf oend;
        oend <- oend + blocksize;
        used <- 0;
        (* Recurse on remainder of string *)
        self#put_substring src (ofs + n) (len - n)
      end

    method put_string s =
      self#put_substring (Bytes.unsafe_of_string s) 0 (String.length s)

    method put_char c =
      if used < blocksize then begin
        Bytes.set ibuf used c;
        used <- used + 1
      end else begin
        self#ensure_capacity blocksize;
        cipher#transform ibuf 0 obuf oend;
        oend <- oend + blocksize;
        Bytes.set ibuf 0 c;
        used <- 1
      end

    method put_byte b =
      self#put_char (Char.unsafe_chr b)

    method wipe =
      cipher#wipe;
      output_buffer#wipe;
      wipe_bytes ibuf

    method flush =
      if used = 0 then ()
      else if used = blocksize then begin
        self#ensure_capacity blocksize;
        cipher#transform ibuf 0 obuf oend;
        used <- 0;
        oend <- oend + blocksize
      end
      else raise (Error Wrong_data_length)

    method finish =
      self#flush
  end

(* Block cipher with padding *)

class cipher_padded_encrypt (padding : Padding.scheme)
                            (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  object(self)
    inherit cipher cipher
    method input_block_size = 1

    method finish =
      if used >= blocksize then begin
        self#ensure_capacity blocksize;
        cipher#transform ibuf 0 obuf oend;
        oend <- oend + blocksize;
        used <- 0
      end;
      padding#pad ibuf used;
      self#ensure_capacity blocksize;
      cipher#transform ibuf 0 obuf oend;
      oend <- oend + blocksize
  end

class cipher_padded_decrypt (padding : Padding.scheme)
                            (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  object(self)
    inherit cipher cipher
    method output_block_size = 1

    method finish =
      if used <> blocksize then raise (Error Wrong_data_length);
      cipher#transform ibuf 0 ibuf 0;
      let valid = padding#strip ibuf in
      self#ensure_capacity valid;
      Bytes.blit ibuf 0 obuf oend valid;
      oend <- oend + valid
  end

(* Wrapping of a block cipher as a MAC, using CBC mode *)

class mac ?iv:iv_init ?(pad: Padding.scheme option) (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    val buffer = Bytes.create blocksize
    val mutable used = 0

    method hash_size = blocksize

    method add_substring src src_ofs len =
      let rec add src_ofs len =
        if len <= 0 then () else
        if used + len <= blocksize then begin
          (* Just accumulate len characters in buffer *)
          Bytes.blit src src_ofs buffer used len;
          used <- used + len
        end else begin
          (* Fill buffer and run it through cipher *)
          let n = blocksize - used in
          Bytes.blit src src_ofs buffer used n;
          xor_bytes iv 0 buffer 0 blocksize;
          cipher#transform buffer 0 iv 0;
          used <- 0;
          (* Recurse on remainder of string *)
          add (src_ofs + n) (len - n)
        end
      in add src_ofs len

    method add_string s =
      self#add_substring (Bytes.unsafe_of_string s) 0 (String.length s)

    method add_char c =
      if used < blocksize then begin
        Bytes.set buffer used c;
        used <- used + 1
      end else begin
        xor_bytes iv 0 buffer 0 blocksize;
        cipher#transform buffer 0 iv 0;
        Bytes.set buffer 0 c;
        used <- 1
      end

    method add_byte b =
      self#add_char (Char.unsafe_chr b)

    method wipe =
      cipher#wipe;
      wipe_bytes buffer;
      wipe_bytes iv

    method result =
      if used = blocksize then begin
        xor_bytes iv 0 buffer 0 blocksize;
        cipher#transform buffer 0 iv 0;
        used <- 0
      end;
      begin match pad with
        None ->
          if used <> 0 then raise (Error Wrong_data_length)
      | Some p ->
          p#pad buffer used;
          xor_bytes iv 0 buffer 0 blocksize;
          cipher#transform buffer 0 iv 0;
          used <- 0
      end;
      Bytes.to_string iv
  end

class mac_final_triple ?iv ?pad (cipher1 : block_cipher)
                                (cipher2 : block_cipher)
                                (cipher3 : block_cipher) =
  let _ = if cipher1#blocksize <> cipher2#blocksize
          || cipher2#blocksize <> cipher3#blocksize
          then raise(Error Incompatible_block_size) in
  object
    inherit mac ?iv ?pad cipher1 as super
    method result =
      let r = Bytes.of_string super#result in
      cipher2#transform r 0 r 0;
      cipher3#transform r 0 r 0;
      Bytes.unsafe_to_string r
    method wipe =
      super#wipe; cipher2#wipe; cipher3#wipe
  end

(* Wrapping of a block ciper as a MAC, in CMAC mode (a.k.a. OMAC1) *)

class cmac ?iv:iv_init (cipher : block_cipher) k1 k2 =
  object (self)
    inherit mac ?iv:iv_init cipher as super

    method result =
      let blocksize = cipher#blocksize in
      let k' =
        if used = blocksize then k1 else (Padding._8000#pad buffer used; k2) in
      xor_bytes iv 0 buffer 0 blocksize;
      xor_bytes k' 0 buffer 0 blocksize;
      cipher#transform buffer 0 iv 0;
      used <- 0; (* really useful? *)
      Bytes.to_string iv

    method wipe =
      super#wipe;
      wipe_bytes k1;
      wipe_bytes k2
  end
end

(* Stream ciphers *)

module Stream = struct

class type stream_cipher =
  object
    method transform: bytes -> int -> bytes -> int -> int -> unit
    method wipe: unit
  end

class arcfour key =
  object
    val ckey =
      if String.length key > 0 && String.length key <= 256
      then arcfour_cook_key key
      else raise(Error Wrong_key_size)
    method transform src src_ofs dst dst_ofs len =
      if len < 0
      || src_ofs < 0 || src_ofs > Bytes.length src - len
      || dst_ofs < 0 || dst_ofs > Bytes.length dst - len
      then invalid_arg "arcfour#transform";
      arcfour_transform ckey src src_ofs dst dst_ofs len
    method wipe =
      wipe_bytes ckey
  end

class chacha20 ?iv ?(ctr = 0L) key =
  object
    val ckey =
      let iv = Block.make_initial_iv 8 iv in
      if String.length key = 16 || String.length key = 32
      then chacha20_cook_key key iv ctr
      else raise(Error Wrong_key_size)
    method transform src src_ofs dst dst_ofs len =
      if len < 0
      || src_ofs < 0 || src_ofs > Bytes.length src - len
      || dst_ofs < 0 || dst_ofs > Bytes.length dst - len
      then invalid_arg "chacha20#transform";
      chacha20_transform ckey src src_ofs dst dst_ofs len
    method wipe =
      wipe_bytes ckey
  end

(* Wrapping of a stream cipher as a cipher *)

class cipher (cipher : stream_cipher) =
  object(self)
    val charbuf = Bytes.create 1

    inherit buffered_output 256 as output_buffer
    method input_block_size = 1
    method output_block_size = 1

    method put_substring src ofs len =
      self#ensure_capacity len;
      cipher#transform src ofs obuf oend len;
      oend <- oend + len

    method put_string s =
      self#put_substring (Bytes.unsafe_of_string s) 0 (String.length s)

    method put_char c =
      Bytes.set charbuf 0 c;
      self#ensure_capacity 1;
      cipher#transform charbuf 0 obuf oend 1;
      oend <- oend + 1

    method put_byte b =
      self#put_char (Char.unsafe_chr b)

    method flush = ()
    method finish = ()

    method wipe =
      cipher#wipe;
      output_buffer#wipe;
      wipe_bytes charbuf
  end

end

(* Hash functions *)

module Hash = struct

class sha1 =
  object(self)
    val context = sha1_init()
    method hash_size = 20
    method add_substring src ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length src - len
      then invalid_arg "sha1#add_substring";
      sha1_update context src ofs len
    method add_string src =
      sha1_update context (Bytes.unsafe_of_string src) 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result =
      sha1_final context
    method wipe =
      wipe_bytes context
  end

let sha1 () = new sha1

class sha224 =
  object(self)
    val context = sha224_init()
    method hash_size = 24
    method add_substring src ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length src - len
      then invalid_arg "sha224#add_substring";
      sha256_update context src ofs len
    method add_string src =
      sha256_update context (Bytes.unsafe_of_string src) 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result =
      sha224_final context
    method wipe =
      wipe_bytes context
  end

let sha224 () = new sha224

class sha256 =
  object(self)
    val context = sha256_init()
    method hash_size = 32
    method add_substring src ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length src - len
      then invalid_arg "sha256#add_substring";
      sha256_update context src ofs len
    method add_string src =
      sha256_update context (Bytes.unsafe_of_string src) 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result =
      sha256_final context
    method wipe =
      wipe_bytes context
  end

let sha256 () = new sha256

class sha384 =
  object(self)
    val context = sha384_init()
    method hash_size = 48
    method add_substring src ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length src - len
      then invalid_arg "sha384#add_substring";
      sha512_update context src ofs len
    method add_string src =
      sha512_update context (Bytes.unsafe_of_string src) 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result =
      sha384_final context
    method wipe =
      wipe_bytes context
  end

let sha384 () = new sha384

class sha512 =
  object(self)
    val context = sha512_init()
    method hash_size = 64
    method add_substring src ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length src - len
      then invalid_arg "sha512#add_substring";
      sha512_update context src ofs len
    method add_string src =
      sha512_update context (Bytes.unsafe_of_string src) 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result =
      sha512_final context
    method wipe =
      wipe_bytes context
  end

let sha512 () = new sha512

let sha2 sz =
  match sz with
  | 224 -> new sha224
  | 256 -> new sha256
  | 384 -> new sha384
  | 512 -> new sha512
  |  _  -> raise (Error Wrong_key_size)

class sha3 sz official =
  object(self)
    val context =
      if sz = 224 || sz = 256 || sz = 384 || sz = 512
      then sha3_init sz
      else raise (Error Wrong_key_size)
    method hash_size = sz / 8
    method add_substring src ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length src - len
      then invalid_arg ((if official then "sha3" else "keccak")^"#add_substring");
      sha3_absorb context src ofs len
    method add_string src =
      sha3_absorb context (Bytes.unsafe_of_string src) 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result = sha3_extract official context
    method wipe =
      sha3_wipe context
  end

let sha3 sz = new sha3 sz true

let keccak sz = new sha3 sz false

class ripemd160 =
  object(self)
    val context = ripemd160_init()
    method hash_size = 32
    method add_substring src ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length src - len
      then invalid_arg "ripemd160#add_substring";
      ripemd160_update context src ofs len
    method add_string src =
      ripemd160_update context (Bytes.unsafe_of_string src) 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result =
      ripemd160_final context
    method wipe =
      wipe_bytes context
  end

let ripemd160 () = new ripemd160

class md5 =
  object(self)
    val context = md5_init()
    method hash_size = 16
    method add_substring src ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length src - len
      then invalid_arg "md5#add_substring";
      md5_update context src ofs len
    method add_string src =
      md5_update context (Bytes.unsafe_of_string src) 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result =
      md5_final context
    method wipe =
      wipe_bytes context
  end

let md5 () = new md5

class blake2b sz key =
  object(self)
    val context =
      if sz >= 8 && sz <= 512 && sz mod 8 = 0 && String.length key <= 64
      then blake2b_init (sz / 8) key
      else raise (Error Wrong_key_size)
    method hash_size = sz / 8
    method add_substring src ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length src - len
      then invalid_arg "blake2b#add_substring";
      blake2b_update context src ofs len
    method add_string src =
      blake2b_update context (Bytes.unsafe_of_string src) 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result = blake2b_final context (sz / 8)
    method wipe =
      wipe_bytes context
  end

let blake2b sz = new blake2b sz ""
let blake2b512 () = new blake2b 512 ""

class blake2s sz key =
  object(self)
    val context =
      if sz >= 8 && sz <= 256 && sz mod 8 = 0 && String.length key <= 32
      then blake2s_init (sz / 8) key
      else raise (Error Wrong_key_size)
    method hash_size = sz / 8
    method add_substring src ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length src - len
      then invalid_arg "blake2s#add_substring";
      blake2s_update context src ofs len
    method add_string src =
      blake2s_update context (Bytes.unsafe_of_string src) 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result = blake2s_final context (sz / 8)
    method wipe =
      wipe_bytes context
  end

let blake2s sz = new blake2s sz ""
let blake2s256 () = new blake2s 256 ""

end

(* High-level entry points for ciphers *)

module Cipher = struct

type direction = dir = Encrypt | Decrypt

type chaining_mode =
    ECB
  | CBC
  | CFB of int
  | OFB of int
  | CTR
  | CTR_N of int

let make_block_cipher ?(mode = CBC) ?pad ?iv dir block_cipher =
  let chained_cipher =
    match (mode, dir) with
      (ECB, _) -> block_cipher
    | (CBC, Encrypt) -> new Block.cbc_encrypt ?iv block_cipher
    | (CBC, Decrypt) -> new Block.cbc_decrypt ?iv block_cipher

    | (CFB n, Encrypt) -> new Block.cfb_encrypt ?iv n block_cipher
    | (CFB n, Decrypt) -> new Block.cfb_decrypt ?iv n block_cipher
    | (OFB n, _) -> new Block.ofb ?iv n block_cipher
    | (CTR, _) -> new Block.ctr ?iv block_cipher
    | (CTR_N n, _) -> new Block.ctr ?iv ~inc:n block_cipher in
  match pad with
    None -> new Block.cipher chained_cipher
  | Some p ->
      match dir with
        Encrypt -> new Block.cipher_padded_encrypt p chained_cipher
      | Decrypt -> new Block.cipher_padded_decrypt p chained_cipher

let normalize_dir mode dir =
  match mode with
  | Some(CFB _) | Some(OFB _) | Some(CTR) | Some(CTR_N _) -> Encrypt
  | _ -> dir

let aes ?mode ?pad ?iv key dir =
  make_block_cipher ?mode ?pad ?iv dir
   (match normalize_dir mode dir with
      Encrypt -> new Block.aes_encrypt key
    | Decrypt -> new Block.aes_decrypt key)

let blowfish ?mode ?pad ?iv key dir =
  make_block_cipher ?mode ?pad ?iv dir
   (match normalize_dir mode dir with
      Encrypt -> new Block.blowfish_encrypt key
    | Decrypt -> new Block.blowfish_decrypt key)

let des ?mode ?pad ?iv key dir =
  make_block_cipher ?mode ?pad ?iv dir
    (new Block.des (normalize_dir mode dir) key)

let triple_des ?mode ?pad ?iv key dir =
  make_block_cipher ?mode ?pad ?iv dir
   (match normalize_dir mode dir with
      Encrypt -> new Block.triple_des_encrypt key
    | Decrypt -> new Block.triple_des_decrypt key)

let arcfour key dir = new Stream.cipher (new Stream.arcfour key)

let chacha20 ?iv ?ctr key dir =
  new Stream.cipher (new Stream.chacha20 key ?iv ?ctr)

end

(* The hmac construction *)

module HMAC(H: sig class h: hash  val blocksize: int end) =
  struct
    let hmac_pad key byte =
      let key =
        if String.length key > H.blocksize
        then hash_string (new H.h) key
        else key in
      let r = Bytes.make H.blocksize (Char.chr byte) in
      xor_string key 0 r 0 (String.length key);
      r
    class hmac key =
      object(self)
        inherit H.h as super
        initializer
          (let b = hmac_pad key 0x36 in
           self#add_substring b 0 (Bytes.length b);
           wipe_bytes b)
        method result =
          let h' = new H.h in
          let b = hmac_pad key 0x5C in
          h'#add_substring b 0 (Bytes.length b);
          wipe_bytes b;
          h'#add_string (super#result);
          let r = h'#result in
          h'#wipe;
          r
      end
  end

(* High-level entry points for MACs *)

module MAC = struct

module HMAC_SHA1 =
  HMAC(struct class h = Hash.sha1  let blocksize = 64 end)
module HMAC_SHA256 =
  HMAC(struct class h = Hash.sha256  let blocksize = 64 end)
module HMAC_SHA512 =
  HMAC(struct class h = Hash.sha512  let blocksize = 128 end)
module HMAC_RIPEMD160 = 
  HMAC(struct class h = Hash.ripemd160  let blocksize = 64 end)
module HMAC_MD5 =
  HMAC(struct class h = Hash.md5  let blocksize = 64 end)

let hmac_sha1 key = new HMAC_SHA1.hmac key
let hmac_sha256 key = new HMAC_SHA256.hmac key
let hmac_sha512 key = new HMAC_SHA512.hmac key
let hmac_ripemd160 key = new HMAC_RIPEMD160.hmac key
let hmac_md5 key = new HMAC_MD5.hmac key

let blake2b sz key = new Hash.blake2b sz key
let blake2b512 key = new Hash.blake2b 512 key

let blake2s sz key = new Hash.blake2s sz key
let blake2s256 key = new Hash.blake2s 256 key

let aes ?iv ?pad key =
  new Block.mac ?iv ?pad (new Block.aes_encrypt key)
let des ?iv ?pad key =
  new Block.mac ?iv ?pad (new Block.des_encrypt key)
let triple_des ?iv ?pad key =
  new Block.mac ?iv ?pad (new Block.triple_des_encrypt key)
let des_final_triple_des ?iv ?pad key =
  let kl = String.length key in
  if kl <> 16 && kl <> 24 then raise (Error Wrong_key_size);
  let k1 = String.sub key 0 8 in
  let k2 = String.sub key 8 8 in
  let k3 = if kl = 24 then String.sub key 16 8 else k1 in
  let c1 = new Block.des_encrypt k1
  and c2 = new Block.des_decrypt k2
  and c3 = new Block.des_encrypt k3 in
  wipe_string k1; wipe_string k2; wipe_string k3;
  new Block.mac_final_triple ?iv ?pad c1 c2 c3

let aes_cmac ?iv key =
  let cipher = new Block.aes_encrypt key in
  let b = Bytes.make 16 '\000' in
  let l = Bytes.create 16 in
  cipher#transform b 0 l 0;           (* l = AES-128(K, 000...000 *)
  Bytes.set b 15 '\x87';              (* b = the Rb constant *)
  let k1 = Bytes.create 16 in
  shl1_bytes l 0 k1 0 16;
  if Char.code (Bytes.get l 0) land 0x80 > 0 then xor_bytes b 0 k1 0 16;
  let k2 = Bytes.create 16 in
  shl1_bytes k1 0 k2 0 16;
  if Char.code (Bytes.get k1 0) land 0x80 > 0 then xor_bytes b 0 k2 0 16;
  wipe_bytes l;
  new Block.cmac ?iv cipher k1 k2
end

(* Random number generation *)

module Random = struct

class type rng =
  object
    method random_bytes: bytes -> int -> int -> unit
    method wipe: unit
  end

let string rng len =
  let res = Bytes.create len in
  rng#random_bytes res 0 len;
  Bytes.unsafe_to_string res

type system_rng_handle
external get_system_rng: unit -> system_rng_handle = "caml_get_system_rng"
external close_system_rng: system_rng_handle -> unit = "caml_close_system_rng"
external system_rng_random_bytes: 
  system_rng_handle -> bytes -> int -> int -> bool
  = "caml_system_rng_random_bytes"

class system_rng =
  object(self)
    val h = get_system_rng ()
    method random_bytes buf ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length buf - len
      then invalid_arg "random_bytes";
      if system_rng_random_bytes h buf ofs len
      then ()
      else raise(Error Entropy_source_closed)
    method wipe =
      close_system_rng h
  end

let system_rng () =
  try new system_rng with Not_found -> raise(Error No_entropy_source)

class device_rng filename =
  object(self)
    val fd = Unix.openfile filename [Unix.O_RDONLY] 0
    method random_bytes buf ofs len =
      if len > 0 then begin    
        let n = Unix.read fd buf ofs len in
        if n = 0 then raise(Error Entropy_source_closed);
        if n < len then self#random_bytes buf (ofs + n) (len - n)
      end
    method wipe =
      Unix.close fd
  end

let device_rng filename = new device_rng filename

class egd_rng socketname =
  object(self)
    val fd =
      let s = Unix.socket Unix.PF_UNIX Unix.SOCK_STREAM 0 in
      try
        Unix.connect s (Unix.ADDR_UNIX socketname); s
      with exn ->
        Unix.close s; raise exn
    method random_bytes buf ofs len =
      if len > 0 then begin    
        let reqd = min 255 len in
        let msg = Bytes.create 2 in
        Bytes.set msg 0 '\002'; (* read entropy blocking *)
        Bytes.set msg 1 (Char.chr reqd);
        ignore (Unix.write fd msg 0 2);
        let rec do_read ofs len =
          if len > 0 then begin
            let r = Unix.read fd buf ofs len in
            if r = 0 then raise(Error Entropy_source_closed);
            do_read (ofs + r) (len - r)
          end in
        do_read ofs reqd;
        if reqd < len then self#random_bytes buf (ofs + reqd) (len - reqd)
      end
    method wipe =
      Unix.close fd
  end

let egd_rng socketname = new egd_rng socketname

external hardware_rng_available: unit -> bool = "caml_hardware_rng_available"
external hardware_rng_random_bytes: bytes -> int -> int -> bool = "caml_hardware_rng_random_bytes"

class hardware_rng =
  object
    method random_bytes buf ofs len =
      if ofs < 0 || len < 0 || ofs > Bytes.length buf - len      
      then invalid_arg "hardware_rng#random_bytes";
      if not (hardware_rng_random_bytes buf ofs len)
      then raise (Error Entropy_source_closed)
    method wipe =
      ()
  end

let hardware_rng () =
  if hardware_rng_available ()
  then new hardware_rng
  else raise (Error No_entropy_source)

class no_rng =
  object
    method random_bytes (buf:bytes) (ofs:int) (len:int) : unit = 
      raise (Error No_entropy_source)
    method wipe = ()
  end

let secure_rng =
  try
    new system_rng
  with Not_found ->
  try
    new device_rng "/dev/random"
  with Unix.Unix_error(_,_,_) ->
  try
    new egd_rng (Sys.getenv "EGD_SOCKET")
  with Not_found | Unix.Unix_error(_,_,_) ->
  try
    new egd_rng (Filename.concat (Sys.getenv "HOME") ".gnupg/entropy")
  with Not_found | Unix.Unix_error(_,_,_) ->
  try
    new egd_rng "/var/run/egd-pool"
  with Unix.Unix_error(_,_,_) ->
  try
    new egd_rng "/dev/egd-pool"
  with Unix.Unix_error(_,_,_) ->
  try
    new egd_rng "/etc/egd-pool"
  with Unix.Unix_error(_,_,_) ->
    new no_rng

class pseudo_rng seed =
  let _ = if String.length seed < 16 then raise (Error Seed_too_short) in
  object (self)
    val ckey =
      let l = String.length seed in
      chacha20_cook_key 
        (if l >= 32 then String.sub seed 0 32
         else if l > 16 then seed ^ String.make (32 - l) '\000'
         else seed)
        (Bytes.make 8 '\000') 0L
    method random_bytes buf ofs len =
      if len < 0 || ofs < 0 || ofs > Bytes.length buf - len
      then invalid_arg "pseudo_rng#random_bytes"
      else chacha20_extract ckey buf ofs len
    method wipe =
      wipe_bytes ckey; wipe_string seed
end

let pseudo_rng seed = new pseudo_rng seed

class pseudo_rng_aes_ctr seed =
  let _ = if String.length seed < 16 then raise (Error Seed_too_short) in
  object (self)
    val cipher = new Block.aes_encrypt (String.sub seed 0 16)
    val ctr = Bytes.make 16 '\000'
    val obuf = Bytes.create 16
    val mutable opos = 16

    method random_bytes buf ofs len =
      if len > 0 then begin
        if opos >= 16 then begin
          (* Encrypt the counter *)
          cipher#transform ctr 0 obuf 0;
          (* Increment the counter *)
          Block.increment_counter ctr 0 15;
          (* We have 16 fresh bytes of pseudo-random data *)
          opos <- 0
        end;
        let r = min (16 - opos) len in
        Bytes.blit obuf opos buf ofs r;
        opos <- opos + r;
        if r < len then self#random_bytes buf (ofs + r) (len - r)
      end

    method wipe =
      wipe_bytes obuf; wipe_string seed
  end

let pseudo_rng_aes_ctr seed = new pseudo_rng_aes_ctr seed

end

(* RSA operations *)

module Bn = CryptokitBignum

module RSA = struct

type key =
  { size: int;
    n: string;
    e: string;
    d: string;
    p: string;
    q: string;
    dp: string;
    dq: string;
    qinv: string }

let wipe_key k =
  wipe_string k.n;
  wipe_string k.e;
  wipe_string k.d;
  wipe_string k.p;
  wipe_string k.q;
  wipe_string k.dp;
  wipe_string k.dq;
  wipe_string k.qinv

let encrypt key msg =
  let msg = Bn.of_bytes msg in
  let n = Bn.of_bytes key.n in
  let e = Bn.of_bytes key.e in
  if Bn.compare msg n >= 0 then raise (Error Message_too_long);
  let r = Bn.mod_power msg e n in
  let s = Bn.to_bytes ~numbits:key.size r in
  Bn.wipe msg; Bn.wipe n; Bn.wipe e; Bn.wipe r;
  s

let unwrap_signature = encrypt

let decrypt key msg =
  let msg = Bn.of_bytes msg in
  let n = Bn.of_bytes key.n in
  let d = Bn.of_bytes key.d in
  if Bn.compare msg n >= 0 then raise (Error Message_too_long);
  let r = Bn.mod_power msg d n in
  let s = Bn.to_bytes ~numbits:key.size r in
  Bn.wipe msg; Bn.wipe n; Bn.wipe d; Bn.wipe r;
  s

let sign = decrypt

let decrypt_CRT key msg =
  let msg = Bn.of_bytes msg in
  let n = Bn.of_bytes key.n in
  let p = Bn.of_bytes key.p in
  let q = Bn.of_bytes key.q in
  let dp = Bn.of_bytes key.dp in
  let dq = Bn.of_bytes key.dq in
  let qinv = Bn.of_bytes key.qinv in
  if Bn.compare msg n >= 0 then raise (Error Message_too_long);
  let r = Bn.mod_power_CRT msg p q dp dq qinv in
  let s = Bn.to_bytes ~numbits:key.size r in
  Bn.wipe msg; Bn.wipe n; Bn.wipe p; Bn.wipe q;
  Bn.wipe dp; Bn.wipe dq; Bn.wipe qinv; Bn.wipe r;
  s

let sign_CRT = decrypt_CRT

let new_key ?(rng = Random.secure_rng) ?e numbits =
  if numbits < 32 || numbits land 1 > 0 then raise(Error Wrong_key_size);
  let numbits2 = numbits / 2 in
  (* Generate primes p, q with numbits / 2 digits.
     If fixed exponent e, make sure gcd(p-1,e) = 1 and
     gcd(q-1,e) = 1. *)
  let rec gen_factor nbits =
    let n = Bn.random_prime ~rng:(rng#random_bytes) nbits in
    match e with
      None -> n
    | Some e ->
        if Bn.relative_prime (Bn.sub n Bn.one) (Bn.of_int e)
        then n
        else gen_factor nbits in
  (* Make sure p > q *)
  let rec gen_factors nbits =
    let p = gen_factor nbits
    and q = gen_factor nbits in
    let cmp = Bn.compare p q in
    if cmp = 0 then gen_factors nbits else
    if cmp < 0 then (q, p) else (p, q) in
  let (p, q) = gen_factors numbits2 in
  (* p1 = p - 1 and q1 = q - 1 *)
  let p1 = Bn.sub p Bn.one
  and q1 = Bn.sub q Bn.one in
  (* If no fixed exponent specified, generate random exponent e such that
     gcd(p-1,e) = 1 and gcd(q-1,e) = 1 *)
  let e =
    match e with
      Some e -> Bn.of_int e
    | None ->
        let rec gen_exponent () =
          let n = Bn.random ~rng:(rng#random_bytes) numbits in
          if Bn.relative_prime n p1 && Bn.relative_prime n q1
          then n
          else gen_exponent () in
        gen_exponent () in
  (* n = pq *)
  let n = Bn.mult p q in
  (* d = e^-1 mod (p-1)(q-1) *)
  let d = Bn.mod_inv e (Bn.mult p1 q1) in
  (* dp = d mod p-1 and dq = d mod q-1 *)
  let dp = Bn.mod_ d p1 and dq = Bn.mod_ d q1 in
  (* qinv = q^-1 mod p *)
  let qinv = Bn.mod_inv q p in
  (* Build key *)
  let res =
    { size = numbits;
      n = Bn.to_bytes ~numbits:numbits n;
      e = Bn.to_bytes ~numbits:numbits e;
      d = Bn.to_bytes ~numbits:numbits d;
      p = Bn.to_bytes ~numbits:numbits2 p;
      q = Bn.to_bytes ~numbits:numbits2 q;
      dp = Bn.to_bytes ~numbits:numbits2 dp;
      dq = Bn.to_bytes ~numbits:numbits2 dq;
      qinv = Bn.to_bytes ~numbits:numbits2 qinv } in
  Bn.wipe n; Bn.wipe e; Bn.wipe d;
  Bn.wipe p; Bn.wipe q;
  Bn.wipe p1; Bn.wipe q1;
  Bn.wipe dp; Bn.wipe dq; Bn.wipe qinv;
  res

end

(* Diffie-Hellman key agreement *)

module DH = struct

type parameters =
  { p: string;
    g: string;
    privlen: int }

let new_parameters ?(rng = Random.secure_rng) ?(privlen = 160) numbits =
  if numbits < 32 || numbits <= privlen then raise(Error Wrong_key_size);
  let np = Bn.random_prime ~rng:(rng#random_bytes) numbits in
  let rec find_generator () =
    let g = Bn.random ~rng:(rng#random_bytes) (numbits - 1) in
    if Bn.compare g Bn.one <= 0 then find_generator() else g in
  let ng = find_generator () in
  { p = Bn.to_bytes ~numbits np;
    g = Bn.to_bytes ~numbits ng;
    privlen = privlen }

type private_secret = Bn.t

let private_secret ?(rng = Random.secure_rng) params =
  Bn.random ~rng:(rng#random_bytes) params.privlen

let message params privsec =
  Bn.to_bytes ~numbits:(String.length params.p * 8)
    (Bn.mod_power (Bn.of_bytes params.g) privsec (Bn.of_bytes params.p))

let shared_secret params privsec othermsg =
  let res =
    Bn.to_bytes ~numbits:(String.length params.p * 8)
      (Bn.mod_power (Bn.of_bytes othermsg) privsec (Bn.of_bytes params.p))
  in Bn.wipe privsec; res

let derive_key ?(diversification = "") sharedsec numbytes =
  let result = Bytes.create numbytes in
  let rec derive pos counter =
    if pos < numbytes then begin
      let h =
        hash_string (Hash.sha256()) 
                    (diversification ^ sharedsec ^ string_of_int counter) in
      String.blit h 0 result pos (min (String.length h) (numbytes - pos));
      wipe_string h;
      derive (pos + String.length h) (counter + 1)
    end in
  derive 0 1;
  Bytes.unsafe_to_string result

end

(* Base64 encoding *)

module Base64 = struct

let base64_conv_table =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

class encode multiline padding =
  object (self)
    method input_block_size = 1
    method output_block_size = 1

    inherit buffered_output 256 as output_buffer

    val ibuf = Bytes.create 3
    val mutable ipos = 0
    val mutable ocolumn = 0

    method put_char c =
      Bytes.set ibuf ipos c;
      ipos <- ipos + 1;
      if ipos = 3 then begin
        let b0 = Char.code (Bytes.get ibuf 0)
        and b1 = Char.code (Bytes.get ibuf 1)
        and b2 = Char.code (Bytes.get ibuf 2) in
        self#ensure_capacity 4;
        Bytes.set obuf oend     base64_conv_table.[b0 lsr 2];
        Bytes.set obuf (oend+1) base64_conv_table.[(b0 land 3) lsl 4 + (b1 lsr 4)];
        Bytes.set obuf (oend+2) base64_conv_table.[(b1 land 15) lsl 2 + (b2 lsr 6)];
        Bytes.set obuf (oend+3) base64_conv_table.[b2 land 63];
        oend <- oend + 4;
        ipos <- 0;
        ocolumn <- ocolumn + 4;
        if multiline && ocolumn >= 72 then begin
          self#ensure_capacity 1;
          Bytes.set obuf oend '\n';
          oend <- oend + 1;
          ocolumn <- 0
        end 
      end

    method put_substring s ofs len =
      for i = ofs to ofs + len - 1 do self#put_char (Bytes.get s i) done

    method put_string s =
      String.iter self#put_char s

    method put_byte b = self#put_char (Char.chr b)

    method flush : unit = raise (Error Wrong_data_length)

    method finish =
      begin match ipos with
        1 ->
          self#ensure_capacity 2;
          let b0 = Char.code (Bytes.get ibuf 0) in
          Bytes.set obuf oend     base64_conv_table.[b0 lsr 2];
          Bytes.set obuf (oend+1) base64_conv_table.[(b0 land 3) lsl 4];
          oend <- oend + 2
      | 2 ->
          self#ensure_capacity 3;
          let b0 = Char.code (Bytes.get ibuf 0)
          and b1 = Char.code (Bytes.get ibuf 1) in
          Bytes.set obuf oend     base64_conv_table.[b0 lsr 2];
          Bytes.set obuf (oend+1) base64_conv_table.[(b0 land 3) lsl 4 + (b1 lsr 4)];
          Bytes.set obuf (oend+2) (base64_conv_table.[(b1 land 15) lsl 2]);
          oend <- oend + 3
      | _ -> ()
      end;
      if multiline || padding then begin
        let num_equals =
          match ipos with 1 -> 2 | 2 -> 1 | _ -> 0 in
        self#ensure_capacity num_equals;
        Bytes.fill obuf oend num_equals '=';
        oend <- oend + num_equals
      end;
      if multiline && ocolumn > 0 then begin
        self#ensure_capacity 1;
        Bytes.set obuf oend '\n';
        oend <- oend + 1
      end;
      ocolumn <- 0

    method wipe =
      wipe_bytes ibuf; output_buffer#wipe
  end

let encode_multiline () = new encode true true
let encode_compact () = new  encode false false
let encode_compact_pad () = new encode false true

let base64_decode_char c =
  match c with
    'A' .. 'Z' -> Char.code c - 65
  | 'a' .. 'z' -> Char.code c - 97 + 26
  | '0' .. '9' -> Char.code c - 48 + 52
  | '+' -> 62
  | '/' -> 63
  | ' '|'\t'|'\n'|'\r' -> -1
  | _   -> raise (Error Bad_encoding)

class decode =
  object (self)
    inherit buffered_output 256 as output_buffer

    method input_block_size = 1
    method output_block_size = 1

    val ibuf = Array.make 4 0
    val mutable ipos = 0
    val mutable finished = false

    method put_char c =
      if c = '=' then finished <- true else begin
        let n = base64_decode_char c in
        if n >= 0 then begin
          if finished then raise(Error Bad_encoding);
          ibuf.(ipos) <- n;
          ipos <- ipos + 1;
          if ipos = 4 then begin
            self#ensure_capacity 3;
            Bytes.set obuf oend     (Char.chr(ibuf.(0) lsl 2 + ibuf.(1) lsr 4));
            Bytes.set obuf (oend+1) (Char.chr((ibuf.(1) land 15) lsl 4 + ibuf.(2) lsr 2));
            Bytes.set obuf (oend+2) (Char.chr((ibuf.(2) land 3) lsl 6 + ibuf.(3)));
            oend <- oend + 3;
            ipos <- 0
          end
        end
      end

    method put_substring s ofs len =
      for i = ofs to ofs + len - 1 do self#put_char (Bytes.get s i) done

    method put_string s =
      String.iter self#put_char s

    method put_byte b = self#put_char (Char.chr b)

    method flush : unit = raise (Error Wrong_data_length)

    method finish =
      finished <- true;
      match ipos with
      | 1 -> raise(Error Bad_encoding)
      | 2 ->
          self#ensure_capacity 1;
          Bytes.set obuf oend     (Char.chr(ibuf.(0) lsl 2 + ibuf.(1) lsr 4));
          oend <- oend + 1
      | 3 ->
          self#ensure_capacity 2;
          Bytes.set obuf oend     (Char.chr(ibuf.(0) lsl 2 + ibuf.(1) lsr 4));
          Bytes.set obuf (oend+1) (Char.chr((ibuf.(1) land 15) lsl 4 + ibuf.(2) lsr 2));
          oend <- oend + 2
      | _ -> ()

    method wipe =
      Array.fill ibuf 0 4 0; output_buffer#wipe
  end

let decode () = new decode

end

(* Hexadecimal encoding *)

module Hexa = struct

let hex_conv_table = "0123456789abcdef"

class encode =
  object (self)
    method input_block_size = 1
    method output_block_size = 1

    inherit buffered_output 256 as output_buffer

    method put_byte b =
      self#ensure_capacity 2;
      Bytes.set obuf oend     (hex_conv_table.[b lsr 4]);
      Bytes.set obuf (oend+1) (hex_conv_table.[b land 0xF]);
      oend <- oend + 2

    method put_char c = self#put_byte (Char.code c)

    method put_substring s ofs len =
      for i = ofs to ofs + len - 1 do self#put_char (Bytes.get s i) done

    method put_string s =
      String.iter self#put_char s

    method flush = ()
    method finish = ()

    method wipe = output_buffer#wipe
  end

let encode () = new encode

let hex_decode_char c =
  match c with
  | '0' .. '9' -> Char.code c - 48
  | 'A' .. 'F' -> Char.code c - 65 + 10
  | 'a' .. 'f' -> Char.code c - 97 + 10
  | ' '|'\t'|'\n'|'\r' -> -1
  | _   -> raise (Error Bad_encoding)

class decode =
  object (self)
    inherit buffered_output 256 as output_buffer

    method input_block_size = 1
    method output_block_size = 1

    val ibuf = Array.make 2 0
    val mutable ipos = 0

    method put_char c =
      let n = hex_decode_char c in
      if n >= 0 then begin
        ibuf.(ipos) <- n;
        ipos <- ipos + 1;
        if ipos = 2 then begin
          self#ensure_capacity 1;
          Bytes.set obuf oend (Char.chr(ibuf.(0) lsl 4 lor ibuf.(1)));
          oend <- oend + 1;
          ipos <- 0
        end
      end

    method put_substring s ofs len =
      for i = ofs to ofs + len - 1 do self#put_char (Bytes.get s i) done

    method put_string s =
      String.iter self#put_char s

    method put_byte b = self#put_char (Char.chr b)

    method flush =
      if ipos <> 0 then raise(Error Wrong_data_length)

    method finish =
      if ipos <> 0 then raise(Error Bad_encoding)

    method wipe =
      Array.fill ibuf 0 2 0; output_buffer#wipe
  end

let decode () = new decode

end

(* Compression *)

module Zlib = struct

type stream

type flush_command =
    Z_NO_FLUSH
  | Z_SYNC_FLUSH
  | Z_FULL_FLUSH
  | Z_FINISH

external deflate_init: int -> bool -> stream = "caml_zlib_deflateInit"
external deflate:
  stream -> bytes -> int -> int -> bytes -> int -> int -> flush_command
         -> bool * int * int
  = "caml_zlib_deflate_bytecode" "caml_zlib_deflate"
external deflate_end: stream -> unit = "caml_zlib_deflateEnd"

external inflate_init: bool -> stream = "caml_zlib_inflateInit"
external inflate:
  stream -> bytes -> int -> int -> bytes -> int -> int -> flush_command
         -> bool * int * int
  = "caml_zlib_inflate_bytecode" "caml_zlib_inflate"
external inflate_end: stream -> unit = "caml_zlib_inflateEnd"

class compress level write_zlib_header =
  object(self)
    val zs = deflate_init level write_zlib_header
    
    inherit buffered_output 512 as output_buffer

    method input_block_size = 1
    method output_block_size = 1

    method put_substring src ofs len =
      if len > 0 then begin
        self#ensure_capacity 256;
        let (_, used_in, used_out) =
          deflate zs
                  src ofs len
                  obuf oend (Bytes.length obuf - oend)
                  Z_NO_FLUSH in
        oend <- oend + used_out;
        if used_in < len
        then self#put_substring src (ofs + used_in) (len - used_in)
      end

    method put_string s =
      self#put_substring (Bytes.unsafe_of_string s) 0 (String.length s)

    method put_char c = self#put_string (String.make 1 c)

    method put_byte b = self#put_char (Char.chr b)

    method flush =
      self#ensure_capacity 256;
      let (_, _, used_out) =
         deflate zs
                 (Bytes.unsafe_of_string "") 0 0
                 obuf oend (Bytes.length obuf - oend)
                 Z_SYNC_FLUSH in
      oend <- oend + used_out;
      if oend = Bytes.length obuf then self#flush

    method finish =
      self#ensure_capacity 256;
      let (finished, _, used_out) =
         deflate zs
                 (Bytes.unsafe_of_string "") 0 0
                 obuf oend (Bytes.length obuf - oend)
                 Z_FINISH in
      oend <- oend + used_out;
      if finished then deflate_end zs else self#finish

    method wipe =
      output_buffer#wipe
end

let compress ?(level = 6) ?(write_zlib_header = false) () = new compress level write_zlib_header 

class uncompress expect_zlib_header =
  object(self)
    val zs = inflate_init expect_zlib_header
    
    inherit buffered_output 512 as output_buffer

    method input_block_size = 1
    method output_block_size = 1

    method put_substring src ofs len =
      if len > 0 then begin
        self#ensure_capacity 256;
        let (finished, used_in, used_out) =
          inflate zs
                  src ofs len
                  obuf oend (Bytes.length obuf - oend)
                  Z_SYNC_FLUSH in
        oend <- oend + used_out;
        if used_in < len then begin
          if finished then
            raise(Error(Compression_error("Zlib.uncompress",
               "garbage at end of compressed data")));
          self#put_substring src (ofs + used_in) (len - used_in)
        end
      end

    method put_string s =
      self#put_substring (Bytes.unsafe_of_string s) 0 (String.length s)

    method put_char c = self#put_string (String.make 1 c)

    method put_byte b = self#put_char (Char.chr b)

    method flush = ()

    method finish =
      let rec do_finish first_finish =
        self#ensure_capacity 256;
        let (finished, _, used_out) =
           inflate zs
                   (Bytes.unsafe_of_string " ") 0 (if first_finish then 1 else 0)
                   obuf oend (Bytes.length obuf - oend)
                   Z_SYNC_FLUSH in
        oend <- oend + used_out;
        if not finished then do_finish false in
      do_finish true; inflate_end zs

    method wipe =
      output_buffer#wipe
end

let uncompress ?(expect_zlib_header = false) () = new uncompress expect_zlib_header

end

(* Utilities *)

let seq_equal (len: 'a -> int) (get: 'a -> int -> char) (s1: 'a) (s2: 'a) =
  let l = len s1 in
  let rec equal i accu =
    if i >= l
    then accu = 0
    else equal (i + 1)
               (accu lor ((Char.code (get s1 i)) lxor (Char.code (get s2 i))))
  in
    l = len s2 && equal 0 0

let string_equal = seq_equal String.length String.get
let bytes_equal = seq_equal Bytes.length Bytes.get

let xor_bytes src src_ofs dst dst_ofs len =
  if len < 0
  || src_ofs < 0 || src_ofs > Bytes.length src - len
  || dst_ofs < 0 || dst_ofs > Bytes.length dst - len
  then invalid_arg "xor_bytes";
  xor_bytes src src_ofs dst dst_ofs len
  
let xor_string src src_ofs dst dst_ofs len =
  if len < 0
  || src_ofs < 0 || src_ofs > String.length src - len
  || dst_ofs < 0 || dst_ofs > Bytes.length dst - len
  then invalid_arg "xor_string";
  xor_string src src_ofs dst dst_ofs len
  
let mod_power a b c =
  Bn.to_bytes ~numbits:(String.length c * 8)
    (Bn.mod_power (Bn.of_bytes a) (Bn.of_bytes b) (Bn.of_bytes c))
let mod_mult a b c =
  Bn.to_bytes ~numbits:(String.length c * 8)
    (Bn.mod_ (Bn.mult (Bn.of_bytes a) (Bn.of_bytes b))
             (Bn.of_bytes c))
