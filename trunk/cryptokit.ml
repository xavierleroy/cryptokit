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

open Nat

let wipe_string s = String.fill s 0 (String.length s) '\000'
let wipe_nat n = set_to_zero_nat n 0 (length_nat n)

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

exception Error of error

let _ = Callback.register_exception "Cryptokit.Error" (Error Wrong_key_size)

(* Interface with C *)

type dir = Encrypt | Decrypt

external xor_string: string -> int -> string -> int -> int -> unit = "caml_xor_string"

external aes_cook_encrypt_key : string -> string = "caml_aes_cook_encrypt_key"
external aes_cook_decrypt_key : string -> string = "caml_aes_cook_decrypt_key"
external aes_encrypt : string -> string -> int -> string -> int -> unit = "caml_aes_encrypt"
external aes_decrypt : string -> string -> int -> string -> int -> unit = "caml_aes_decrypt"
external des_cook_key : string -> dir -> string = "caml_des_cook_key"
external des_transform : string -> string -> int -> string -> int -> unit = "caml_des_transform"
external arcfour_cook_key : string -> string = "caml_arcfour_cook_key"
external arcfour_transform : string -> string -> int -> string -> int -> int -> unit = "caml_arcfour_transform_bytecode" "caml_arcfour_transform"

external sha1_init: unit -> string = "caml_sha1_init"
external sha1_update: string -> string -> int -> int -> unit = "caml_sha1_update"
external sha1_final: string -> string = "caml_sha1_final"
external md5_init: unit -> string = "caml_md5_init"
external md5_update: string -> string -> int -> int -> unit = "caml_md5_update"
external md5_final: string -> string = "caml_md5_final"

(* Abstract transform type *)

class type transform =
  object
    method input_block_size: int
    method output_block_size: int

    method put_substring: string -> int -> int -> unit
    method put_string: string -> unit
    method put_char: char -> unit
    method put_byte: int -> unit

    method finish: unit

    method available_output: int

    method get_string: string
    method get_substring: string * int * int
    method get_char: char
    method get_byte: int

    method wipe: unit
  end

let transform_string tr s =
  tr#put_string s;
  tr#finish;
  let r = tr#get_string in tr#wipe; r

let transform_channel tr ?len ic oc =
  let ibuf = String.create 256 in
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
  wipe_string ibuf;
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

    method finish = tr1#finish; self#transfer; tr2#finish

    method wipe = tr1#wipe; tr2#wipe
  end

let compose tr1 tr2 = new compose tr1 tr2

class type hash =
  object
    method hash_size: int
    method add_substring: string -> int -> int -> unit
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
  let ibuf = String.create 256 in
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
  wipe_string ibuf;
  let res = hash#result in
  hash#wipe;
  res

(* Padding schemes *)

module Padding = struct

class type scheme =
  object
    method pad: string -> int -> unit
    method strip: string -> int
  end

class length =
  object
    method pad buffer used =
      let n = String.length buffer - used in
      assert (n > 0 && n < 256);
      String.fill buffer used n (Char.chr n)
    method strip buffer =
      let blocksize = String.length buffer in
      let n = Char.code buffer.[blocksize - 1] in
      if n = 0 || n > blocksize then raise (Error Bad_padding);
      (* Characters blocksize - n to blocksize - 1 must be equal to n *)
      for i = blocksize - n to blocksize - 2 do
        if Char.code buffer.[i] <> n then raise (Error Bad_padding)
      done;
      blocksize - n
  end

let length = new length

class _8000 =
  object
    method pad buffer used =
      buffer.[used] <- '\128';
      for i = used + 1 to String.length buffer - 1 do
        buffer.[i] <- '\000'
      done
    method strip buffer =
      let rec strip pos =
        if pos < 0 then raise (Error Bad_padding) else
          match buffer.[pos] with
            '\128' -> pos
          | '\000' -> strip (pos - 1)
          |    _   -> raise (Error Bad_padding)
      in strip (String.length buffer - 1)
  end

let _8000 = new _8000

end

(* Generic handling of output buffering *)

class buffered_output initial_buffer_size =
  object(self)
    val mutable obuf = String.create initial_buffer_size
    val mutable obeg = 0
    val mutable oend = 0

    method private ensure_capacity n =
      let len = String.length obuf in
      if oend + n > len then begin
        if oend - obeg + n < len then begin
          String.blit obuf obeg obuf 0 (oend - obeg);
          oend <- oend - obeg;
          obeg <- 0
        end else begin
          let newlen = min (2 * len) Sys.max_string_length in
          if oend - obeg + n > newlen then raise(Error Output_buffer_overflow);
          let newbuf = String.create newlen in
          String.blit obuf obeg newbuf 0 (oend - obeg);
          obuf <- newbuf;
          oend <- oend - obeg;
          obeg <- 0
        end
      end

    method available_output = oend - obeg

    method get_substring =
      let res = (obuf, obeg, oend - obeg) in obeg <- 0; oend <- 0; res

    method get_string =
      let res = String.sub obuf obeg (oend - obeg) in obeg <- 0; oend <- 0; res

    method get_char =
      if obeg >= oend then raise End_of_file;
      let r = obuf.[obeg] in
      obeg <- obeg + 1;
      r

    method get_byte =
      Char.code self#get_char          

    method wipe =
      wipe_string obuf
  end

(* Block ciphers *)

module Block = struct

class type block_cipher =
  object
    method blocksize: int
    method transform: string -> int -> string -> int -> unit
    method wipe: unit
  end

class aes_encrypt key =
  object
    val ckey =
      if String.length key = 16
      then aes_cook_encrypt_key key
      else raise(Error Wrong_key_size)
    method blocksize = 16
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs + 16 > String.length src
      || dst_ofs < 0 || dst_ofs + 16 > String.length dst
      then invalid_arg "aes#transform";
      aes_encrypt ckey src src_ofs dst dst_ofs
    method wipe =
      wipe_string ckey
  end

class aes_decrypt key =
  object
    val ckey =
      if String.length key = 16
      then aes_cook_decrypt_key key
      else raise(Error Wrong_key_size)
    method blocksize = 16
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs + 16 > String.length src
      || dst_ofs < 0 || dst_ofs + 16 > String.length dst
      then invalid_arg "aes#transform";
      aes_decrypt ckey src src_ofs dst dst_ofs
    method wipe =
      wipe_string ckey
  end

class des direction key =
  object
    val ckey =
      if String.length key = 8
      then des_cook_key key direction
      else raise(Error Wrong_key_size)
    method blocksize = 8
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs + 8 > String.length src
      || dst_ofs < 0 || dst_ofs + 8 > String.length dst
      then invalid_arg "des#transform";
      des_transform ckey src src_ofs dst dst_ofs
    method wipe =
      wipe_string ckey
  end

class des_encrypt = des Encrypt
class des_decrypt = des Decrypt

class triple_des dir key =
  let _ = if String.length key <> 16 then raise(Error Wrong_key_size) in
  object
    val ckey1 =
      des_cook_key key dir
    val ckey2 =
      des_cook_key (String.sub key 8 8)
                   (match dir with Encrypt -> Decrypt | Decrypt -> Encrypt)
    method blocksize = 8
    method transform src src_ofs dst dst_ofs =
      if src_ofs < 0 || src_ofs + 8 > String.length src
      || dst_ofs < 0 || dst_ofs + 8 > String.length dst
      then invalid_arg "triple_des#transform";
      des_transform ckey1 src src_ofs dst dst_ofs;
      des_transform ckey2 dst dst_ofs dst dst_ofs;
      des_transform ckey1 dst dst_ofs dst dst_ofs
    method wipe =
      wipe_string ckey1;
      wipe_string ckey2
  end

class triple_des_encrypt = triple_des Encrypt
class triple_des_decrypt = triple_des Decrypt

(* Chaining modes *)

let make_initial_iv blocksize = function
  | None ->
      String.make blocksize '\000'
  | Some s ->
      if String.length s <> blocksize then raise (Error Wrong_IV_size);
      String.copy s

class cbc_encrypt ?iv:iv_init (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    method blocksize = blocksize
    method transform src src_off dst dst_off =
      xor_string src src_off iv 0 blocksize;
      cipher#transform iv 0 dst dst_off;
      String.blit dst dst_off iv 0 blocksize
    method wipe =
      cipher#wipe;
      wipe_string iv
  end

class cbc_decrypt ?iv:iv_init (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    val next_iv = String.create blocksize
    method blocksize = blocksize
    method transform src src_off dst dst_off =
      String.blit src src_off next_iv 0 blocksize;
      cipher#transform src src_off dst dst_off;
      xor_string iv 0 dst dst_off blocksize;
      String.blit next_iv 0 iv 0 blocksize
    method wipe =
      cipher#wipe;
      wipe_string iv;
      wipe_string next_iv
  end

class cfb_encrypt ?iv:iv_init chunksize (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  let _ = assert (chunksize > 0 && chunksize <= blocksize) in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    val out = String.create blocksize
    method blocksize = chunksize
    method transform src src_off dst dst_off =
      cipher#transform iv 0 out 0;
      String.blit src src_off dst dst_off chunksize;
      xor_string out 0 dst dst_off chunksize;
      String.blit iv chunksize iv 0 (blocksize - chunksize);
      String.blit dst dst_off iv (blocksize - chunksize) chunksize
    method wipe =
      cipher#wipe;
      wipe_string iv;
      wipe_string out
  end

class cfb_decrypt ?iv:iv_init chunksize (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  let _ = assert (chunksize > 0 && chunksize <= blocksize) in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    val out = String.create blocksize
    method blocksize = chunksize
    method transform src src_off dst dst_off =
      cipher#transform iv 0 out 0;
      String.blit iv chunksize iv 0 (blocksize - chunksize);
      String.blit src src_off iv (blocksize - chunksize) chunksize;
      String.blit src src_off dst dst_off chunksize;
      xor_string out 0 dst dst_off chunksize
    method wipe =
      cipher#wipe;
      wipe_string iv;
      wipe_string out
  end

class ofb ?iv:iv_init chunksize (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  let _ = assert (chunksize > 0 && chunksize <= blocksize) in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    method blocksize = chunksize
    method transform src src_off dst dst_off =
      cipher#transform iv 0 iv 0;
      String.blit src src_off dst dst_off chunksize;
      xor_string iv 0 dst dst_off chunksize
    method wipe =
      cipher#wipe;
      wipe_string iv
  end

(* Wrapping of a block cipher as a transform *)

class cipher (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  object(self)
    val ibuf = String.create blocksize
    val mutable used = 0

    inherit buffered_output (max 256 (2 * blocksize)) as output_buffer

    method input_block_size = blocksize
    method output_block_size = blocksize

    method put_substring src ofs len =
      if len <= 0 then () else
      if used + len <= blocksize then begin
        (* Just accumulate len characters in ibuf *)
        String.blit src ofs ibuf used len;
        used <- used + len
      end else begin
        (* Fill buffer and run it through cipher *)
        let n = blocksize - used in
        String.blit src ofs ibuf used n;
        self#ensure_capacity blocksize;
        cipher#transform ibuf 0 obuf oend;
        oend <- oend + blocksize;
        used <- 0;
        (* Recurse on remainder of string *)
        self#put_substring src (ofs + n) (len - n)
      end

    method put_string s =
      self#put_substring s 0 (String.length s)

    method put_char c =
      if used < blocksize then begin
        ibuf.[used] <- c;
        used <- used + 1
      end else begin
        self#ensure_capacity blocksize;
        cipher#transform ibuf 0 obuf oend;
        oend <- oend + blocksize;
        ibuf.[0] <- c;
        used <- 1
      end

    method put_byte b =
      self#put_char (Char.unsafe_chr b)

    method wipe =
      cipher#wipe;
      output_buffer#wipe;
      wipe_string ibuf

    method finish =
      if used = 0 then ()
      else if used = blocksize then begin
        self#ensure_capacity blocksize;
        cipher#transform ibuf 0 obuf oend;
        used <- 0;
        oend <- oend + blocksize
      end
      else raise (Error Wrong_data_length)
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
      String.blit ibuf 0 obuf oend valid;
      oend <- oend + valid
  end

(* Wrapping of a block cipher as a MAC *)

class mac ?iv:iv_init ?(pad: Padding.scheme option) (cipher : block_cipher) =
  let blocksize = cipher#blocksize in
  object(self)
    val iv = make_initial_iv blocksize iv_init
    val buffer = String.create blocksize
    val mutable used = 0

    method hash_size = blocksize

    method add_substring src src_ofs len =
      let rec add src_ofs len =
        if len <= 0 then () else
        if used + len <= blocksize then begin
          (* Just accumulate len characters in buffer *)
          String.blit src src_ofs buffer used len;
          used <- used + len
        end else begin
          (* Fill buffer and run it through cipher *)
          let n = blocksize - used in
          String.blit src src_ofs buffer used n;
          xor_string iv 0 buffer 0 blocksize;
          cipher#transform buffer 0 iv 0;
          used <- 0;
          (* Recurse on remainder of string *)
          add (src_ofs + n) (len - n)
        end
      in add src_ofs len

    method add_string s =
      self#add_substring s 0 (String.length s)

    method add_char c =
      if used < blocksize then begin
        buffer.[used] <- c;
        used <- used + 1
      end else begin
        xor_string iv 0 buffer 0 blocksize;
        cipher#transform buffer 0 iv 0;
        buffer.[0] <- c;
        used <- 1
      end

    method add_byte b =
      self#add_char (Char.unsafe_chr b)

    method wipe =
      cipher#wipe;
      wipe_string buffer;
      wipe_string iv

    method result =
      if used = blocksize then begin
        xor_string iv 0 buffer 0 blocksize;
        cipher#transform buffer 0 iv 0;
        used <- 0
      end;
      begin match pad with
        None ->
          if used <> 0 then raise (Error Wrong_data_length)
      | Some p ->
          p#pad buffer used;
          xor_string iv 0 buffer 0 blocksize;
          cipher#transform buffer 0 iv 0;
          used <- 0
      end;
      String.copy iv
  end

class mac_final_triple ?iv ?pad (cipher1 : block_cipher)
                                (cipher2 : block_cipher) =
  let _ = if cipher1#blocksize <> cipher2#blocksize
          then raise(Error Incompatible_block_size) in
  object
    inherit mac ?iv ?pad cipher1 as super
    method result =
      let r = super#result in
      cipher2#transform r 0 r 0;
      cipher1#transform r 0 r 0;
      r
  end

end

(* Stream ciphers *)

module Stream = struct

class type stream_cipher =
  object
    method transform: string -> int -> string -> int -> int -> unit
    method wipe: unit
  end

class arcfour key =
  object
    val ckey =
      if String.length key > 0 && String.length key <= 16
      then arcfour_cook_key key
      else raise(Error Wrong_key_size)
    method transform src src_ofs dst dst_ofs len =
      if src_ofs < 0 || src_ofs + len > String.length src
      || dst_ofs < 0 || dst_ofs + len > String.length dst
      then invalid_arg "arcfour#transform";
      arcfour_transform ckey src src_ofs dst dst_ofs len
    method wipe =
      wipe_string ckey
  end

(* Wrapping of a stream cipher as a cipher *)

class cipher (cipher : stream_cipher) =
  object(self)
    val charbuf = String.create 1

    inherit buffered_output 256 as output_buffer
    method input_block_size = 1
    method output_block_size = 1

    method put_substring src ofs len =
      self#ensure_capacity len;
      cipher#transform src ofs obuf oend len;
      oend <- oend + len

    method put_string s =
      self#put_substring s 0 (String.length s)

    method put_char c =
      charbuf.[0] <- c;
      self#ensure_capacity 1;
      cipher#transform charbuf 0 obuf oend 1;
      oend <- oend + 1

    method put_byte b =
      self#put_char (Char.unsafe_chr b)

    method finish = ()

    method wipe =
      cipher#wipe;
      output_buffer#wipe;
      wipe_string charbuf
  end

end

(* Hash functions *)

module Hash = struct

class sha1 =
  object(self)
    val context = sha1_init()
    method hash_size = 20
    method add_substring src ofs len =
      if ofs < 0 || ofs + len > String.length src
      then invalid_arg "sha1#add_substring";
      sha1_update context src ofs len
    method add_string src =
      sha1_update context src 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result =
      sha1_final context
    method wipe =
      wipe_string context
  end

let sha1 () = new sha1

class md5 =
  object(self)
    val context = md5_init()
    method hash_size = 16
    method add_substring src ofs len =
      if ofs < 0 || ofs + len > String.length src
      then invalid_arg "md5#add_substring";
      md5_update context src ofs len
    method add_string src =
      md5_update context src 0 (String.length src)
    method add_char c =
      self#add_string (String.make 1 c)
    method add_byte b =
      self#add_char (Char.unsafe_chr b)
    method result =
      md5_final context
    method wipe =
      wipe_string context
  end

let md5 () = new md5

end

(* High-level entry points for ciphers *)

module Cipher = struct

type direction = dir = Encrypt | Decrypt

type chaining_mode =
    ECB
  | CBC
  | CFB of int
  | OFB of int

let make_block_cipher ?(mode = CBC) ?pad ?iv dir block_cipher =
  let chained_cipher =
    match (mode, dir) with
      (ECB, _) -> block_cipher
    | (CBC, Encrypt) -> new Block.cbc_encrypt ?iv block_cipher
    | (CBC, Decrypt) -> new Block.cbc_decrypt ?iv block_cipher
    | (CFB n, Encrypt) -> new Block.cfb_encrypt ?iv n block_cipher
    | (CFB n, Decrypt) -> new Block.cfb_decrypt ?iv n block_cipher
    | (OFB n, _) -> new Block.ofb ?iv n block_cipher in
  match pad with
    None -> new Block.cipher chained_cipher
  | Some p ->
      match dir with
        Encrypt -> new Block.cipher_padded_encrypt p chained_cipher
      | Decrypt -> new Block.cipher_padded_decrypt p chained_cipher

let normalize_dir mode dir =
  match mode with
    Some(CFB _) | Some(OFB _) -> Encrypt
  | _ -> dir

let aes ?mode ?pad ?iv key dir =
  make_block_cipher ?mode ?pad ?iv dir
   (match normalize_dir mode dir with
      Encrypt -> new Block.aes_encrypt key
    | Decrypt -> new Block.aes_decrypt key)

let des ?mode ?pad ?iv key dir =
  make_block_cipher ?mode ?pad ?iv dir
    (new Block.des (normalize_dir mode dir) key)

let triple_des ?mode ?pad ?iv key dir =
  make_block_cipher ?mode ?pad ?iv dir
    (new Block.triple_des (normalize_dir mode dir) key)

let arcfour key dir = new Stream.cipher (new Stream.arcfour key)

end

(* High-level entry points for MACs *)

module MAC = struct

let aes ?iv ?pad key =
  new Block.mac ?iv ?pad (new Block.aes_encrypt key)
let des ?iv ?pad key =
  new Block.mac ?iv ?pad (new Block.des_encrypt key)
let triple_des ?iv ?pad key =
  new Block.mac ?iv ?pad (new Block.triple_des_encrypt key)
let des_final_triple_des ?iv ?pad key =
  new Block.mac_final_triple ?iv ?pad
      (new Block.des_encrypt (String.sub key 0 8))
      (new Block.des_decrypt (String.sub key 8 8))

end

(* Random number generation *)

module Random = struct

class type rng =
  object
    method random_bytes: string -> int -> int -> unit
    method wipe: unit
  end

let string rng len =
  let res = String.create len in
  rng#random_bytes res 0 len;
  res

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
        let msg = String.create 2 in
        msg.[0] <- '\002'; (* read entropy blocking *)
        msg.[1] <- Char.chr reqd;
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

class no_rng =
  object
    method random_bytes (buf:string) (ofs:int) (len:int) : unit = 
      raise (Error No_entropy_source)
    method wipe = ()
  end

let secure_rng =
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
    val cipher =
      new Block.cbc_encrypt (new Block.aes_encrypt (String.sub seed 0 16))
    val state =
      let s = String.make 71 '\001' in
      String.blit seed 0 s 0 (min 55 (String.length seed));
      s
    val obuf = String.create 16
    val mutable opos = 16

    method random_bytes buf ofs len =
      if len > 0 then begin
        if opos >= 16 then begin
          (* Clock the lagged Fibonacci generator 16 times *)
          for i = 55 to 70 do
            state.[i] <- Char.unsafe_chr(Char.code state.[i-55] +
                                         Char.code state.[i-24])
          done;
          (* Encrypt resulting 16 bytes *)
          cipher#transform state 55 obuf 0;
          (* Shift Fibonacci generator by 16 bytes *)
          String.blit state 16 state 0 55;
          (* We have 16 fresh bytes of pseudo-random data *)
          opos <- 0
        end;
        let r = min (16 - opos) len in
        String.blit obuf opos buf ofs r;
        opos <- opos + r;
        if r < len then self#random_bytes buf (ofs + r) (len - r)
      end

    method wipe =
      wipe_string obuf; wipe_string seed
  end

  let pseudo_rng seed = new pseudo_rng seed

end

(* Arithmetic on big integers *)

module Bn = struct

  let zero = nat_of_int 0
  let one = nat_of_int 1

  let compare a b =
    compare_nat a 0 (length_nat a) b 0 (length_nat b)

  let num_digits a = num_digits_nat a 0 (length_nat a)

  let num_bits a =
    let ndigits = num_digits a in
    ndigits * length_of_digit - num_leading_zero_bits_in_digit a (ndigits-1)

  let copy a = copy_nat a 0 (num_digits a)

  let add a b =
    let la = num_digits a and lb = num_digits b in
    if la >= lb then begin
      let r = create_nat (la + 1) in
      blit_nat r 0 a 0 la;
      set_digit_nat r la 0;
      ignore(add_nat r 0 (la + 1) b 0 lb 0);
      r
    end else begin
      let r = create_nat (lb + 1) in
      blit_nat r 0 b 0 lb;
      set_digit_nat r lb 0;
      ignore(add_nat r 0 (lb + 1) a 0 la 0);
      r
    end

  let sub a b =
    let la = num_digits a
    and lb = num_digits b in
    let lr = max la lb in
    let r = create_nat lr in
    blit_nat r 0 a 0 la;
    set_to_zero_nat r la (lr - la);
    let carry = sub_nat r 0 lr b 0 lb 1 in
    assert (carry = 1);
    r

  let sub_mod a b c =
    let la = num_digits a
    and lb = num_digits b
    and lc = num_digits c in
    let lr = max (max la lb) lc in
    let r = create_nat lr in
    blit_nat r 0 a 0 la;
    set_to_zero_nat r la (lr - la);
    if sub_nat r 0 lr b 0 lb 1 = 0 then ignore (add_nat r 0 lr c 0 lc 0);
    r

  let mult a b =
    let la = num_digits a and lb = num_digits b in
    let r = make_nat (la + lb) in
    ignore(mult_nat r 0 (la + lb) a 0 la b 0 lb);
    r

  let mult_add a b c =
    let la = num_digits a
    and lb = num_digits b
    and lc = num_digits c in
    let lr = 1 + max (la + lb) lc in
    let r = create_nat lr in
    blit_nat r 0 c 0 lc;
    set_to_zero_nat r lc (lr - lc);
    ignore(mult_nat r 0 lr a 0 la b 0 lb);
    r

  let mod_ a b =
    let la = num_digits a and lb = num_digits b in
    let ltmp = max la lb + 1 in
    let tmp = create_nat ltmp in
    blit_nat tmp 0 a 0 la;
    set_to_zero_nat tmp la (ltmp - la);
    div_nat tmp 0 ltmp b 0 lb;
    let lres = num_digits_nat tmp 0 lb in
    let res = create_nat lres in
    blit_nat res 0 tmp 0 lres;
    wipe_nat tmp;
    res

  let quo_mod a b =
    let la = num_digits a and lb = num_digits b in
    let ltmp = max la lb + 1 in
    let tmp = create_nat ltmp in
    blit_nat tmp 0 a 0 la;
    set_to_zero_nat tmp la (ltmp - la);
    div_nat tmp 0 ltmp b 0 lb;
    let lq = num_digits_nat tmp lb (ltmp - lb) in
    let lm = num_digits_nat tmp 0 lb in
    let q = create_nat lq in
    let m = create_nat lm in
    blit_nat q 0 tmp lb lq;
    blit_nat m 0 tmp 0 lm;
    wipe_nat tmp;
    (q, m)

  let relative_prime a b =
    let la = num_digits a and lb = num_digits b in
    let ltmp = max la lb in
    let tmp = create_nat ltmp in
    blit_nat tmp 0 a 0 la;
    set_to_zero_nat tmp la (ltmp - la);
    let lgcd = gcd_nat tmp 0 la b 0 lb in
    let res =  lgcd = 1 && is_digit_int tmp 0 && nth_digit_nat tmp 0 = 1 in
    wipe_nat tmp;
    res

  (* Compute a^b mod c.  Must have [a < c]. *)

  let mod_power a b c =
    let la = num_digits a
    and lb = num_digits b
    and lc = num_digits c in
    let res = make_nat lc in set_digit_nat res 0 1;  (* res = 1 initially *)
    let prod = create_nat (lc + lc + 1) in
    let window = create_nat 2 in
    (* For each bit of b, from MSB to LSB... *)
    for i = lb - 1 downto 0 do
      blit_nat window 0 b i 1;
      for j = length_of_digit downto 1 do
        (* res <- res ^ 2 mod c *)
        set_to_zero_nat prod 0 (lc + lc + 1);
        ignore(square_nat prod 0 (lc + lc) res 0 lc);
        (* prod[lc+lc] = 0 < c[lc-1] != 0 *)
        div_nat prod 0 (lc + lc + 1) c 0 lc;
        (* remainder is in (prod,0,lc) *)
        blit_nat res 0 prod 0 lc;
        (* shift window[0] left 1 bit and test carry out;
           that is, test bit number j of b[i] *)
        shift_left_nat window 0 1 window 1 1;
        if is_digit_odd window 1 then begin
          (* res <- res * a mod c *)
          set_to_zero_nat prod 0 (lc + la + 1);
          ignore(mult_nat prod 0 (lc + la) res 0 lc a 0 la);
          (* prod[lc+la] = 0 < c[lc-1] != 0 *)
          div_nat prod 0 (lc + la + 1) c 0 lc;
          (* remainder in (prod,0,lc) *)
          blit_nat res 0 prod 0 lc;
        end
      done
    done;
    wipe_nat prod; wipe_nat window;
    res

  (* Modular exponentiation via the Chinese Remainder Theorem.
     Compute a ^ d mod pq, where d is defined by
     dp = d mod (p-1) and dq = d mod (q-1).
     qinv is q^-1 mod p.
     Formula:
       mp = (a mod p)^dp mod p
       mq = (a mod q)^dq mod q
       m = ((((mp - mq) mod p) * qInv) mod p) * q + mq
  *)

  let mod_power_CRT a p q dp dq qinv =
    let amodp = mod_ a p and amodq = mod_ a q in
    let mp = mod_power amodp dp p and mq = mod_power amodq dq q in
    let diff = sub_mod mp mq p in
    let diff_qinv = mult diff qinv in
    let diff_qinv_mod_p = mod_ diff_qinv p in
    let res = mult_add q diff_qinv_mod_p mq in
    wipe_nat amodp; wipe_nat amodq; wipe_nat mp; wipe_nat mq;
    wipe_nat diff; wipe_nat diff_qinv; wipe_nat diff_qinv_mod_p;
    res

  (* Modular inverse.  Return u such that n.u mod m = 1, or raise 
     Not_invertible if no such u exists (i.e. gcd(n,m) <> 1).
     Must have [n < m]. *)

  exception Not_invertible

  let mod_inv b c =
    let rec extended_euclid u1 v1 u3 v3 sign =
      if compare v3 zero = 0 then
        if compare u3 one = 0 then begin
          wipe_nat v1;
          if sign < 0
          then sub c u1
          else u1
        end else begin
          wipe_nat u1; wipe_nat v1; wipe_nat u3;
          raise Not_invertible
        end
      else begin
        let (q,r) = quo_mod u3 v3 in
        let t1 = mult_add q v1 u1 in
        wipe_nat u3; wipe_nat q; wipe_nat u1;
        extended_euclid v1 t1 v3 r (-sign)
      end in
    extended_euclid (nat_of_int 1) (nat_of_int 0) (copy b) (copy c) 1

end

(* Conversions between nats and strings *)

let bytes_per_digit = length_of_digit / 8

let nat_of_bytes s =
  let l = String.length s in
  if l = 0 then make_nat 1 else begin
    let n = make_nat ((l + bytes_per_digit - 1) / bytes_per_digit) in
    let tmp = create_nat 2 in
    for i = 0 to l - 1 do
      let pos = i / bytes_per_digit
      and shift = (i mod bytes_per_digit) * 8 in
      set_digit_nat tmp 0 (Char.code s.[l-1-i]);
      shift_left_nat tmp 0 1 tmp 1 shift;
      lor_digit_nat n pos tmp 0
    done;
    wipe_nat tmp;
    n
  end

let bytes_of_nat ?numbits n =
  let nbits = Bn.num_bits n in
  begin match numbits with
    None -> ()
  | Some n -> if nbits > n then raise(Error Number_too_long)
  end;
  let l = ((nbits + 7) / 8) in
  let s = String.create ((nbits + 7) / 8) in
  let tmp = create_nat 2 in
  for i = 0 to l - 1 do
    let pos = i / bytes_per_digit
    and shift = (i mod bytes_per_digit) * 8 in
    blit_nat tmp 0 n pos 1;
    shift_right_nat tmp 0 1 tmp 1 shift;
    s.[l-1-i] <- Char.unsafe_chr(nth_digit_nat tmp 0)
  done;
  wipe_nat tmp;
  match numbits with
    None -> s
  | Some n ->
      let l' = ((n + 7) / 8) in
      if l = l' then s else String.make (l' - l) '\000' ^ s

(* RSA operations *)

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
  let msg = nat_of_bytes msg in
  let n = nat_of_bytes key.n in
  let e = nat_of_bytes key.e in
  if Bn.compare msg n >= 0 then raise (Error Message_too_long);
  let r = Bn.mod_power msg e n in
  let s = bytes_of_nat ~numbits:key.size r in
  wipe_nat msg; wipe_nat n; wipe_nat e; wipe_nat r;
  s

let unwrap_signature = encrypt

let decrypt key msg =
  let msg = nat_of_bytes msg in
  let n = nat_of_bytes key.n in
  let d = nat_of_bytes key.d in
  if Bn.compare msg n >= 0 then raise (Error Message_too_long);
  let r = Bn.mod_power msg d n in
  let s = bytes_of_nat ~numbits:key.size r in
  wipe_nat msg; wipe_nat n; wipe_nat d; wipe_nat r;
  s

let sign = decrypt

let decrypt_CRT key msg =
  let msg = nat_of_bytes msg in
  let n = nat_of_bytes key.n in
  let p = nat_of_bytes key.p in
  let q = nat_of_bytes key.q in
  let dp = nat_of_bytes key.dp in
  let dq = nat_of_bytes key.dq in
  let qinv = nat_of_bytes key.qinv in
  if Bn.compare msg n >= 0 then raise (Error Message_too_long);
  let r = Bn.mod_power_CRT msg p q dp dq qinv in
  let s = bytes_of_nat ~numbits:key.size r in
  wipe_nat msg; wipe_nat n; wipe_nat p; wipe_nat q;
  wipe_nat dp; wipe_nat dq; wipe_nat qinv; wipe_nat r;
  s

let sign_CRT = decrypt_CRT

let random_nat ?(rng = Random.secure_rng) ?(lowbits = 0) numbits =
  let numdigits = ((numbits + length_of_digit - 1) / length_of_digit) in
  let buf = String.create (numdigits * length_of_digit / 8) in
  rng#random_bytes buf 0 (String.length buf);
  (* move them to a nat *)
  let n = nat_of_bytes buf in
  wipe_string buf;
  let tmp = create_nat 2 in
  (* adjust low digit of n if requested *)
  if lowbits <> 0 then begin
    set_digit_nat tmp 0 lowbits;
    lor_digit_nat n 0 tmp 0
  end;
  (* adjust high digit of n so that it is exactly numbits long *)
  shift_left_nat tmp 0 1 tmp 1 ((numbits - 1) land (length_of_digit - 1));
  ignore(decr_nat tmp 0 1 0);
  land_digit_nat n (numdigits - 1) tmp 0;
  ignore(incr_nat tmp 0 1 1);
  lor_digit_nat n (numdigits - 1) tmp 0;
  (* done *)
  n

let small_primes = [
    2; 3; 5; 7; 11; 13; 17; 19;
    23; 29; 31; 37; 41; 43; 47; 53;
    59; 61; 67; 71; 73; 79; 83; 89;
    97; 101; 103; 107; 109; 113; 127; 131;
    137; 139; 149; 151; 157; 163; 167; 173;
    179; 181; 191; 193; 197; 199; 211; 223;
    227; 229; 233; 239; 241; 251; 257; 263;
    269; 271; 277; 281; 283; 293; 307; 311;
    313; 317; 331; 337; 347; 349; 353; 359;
    367; 373; 379; 383; 389; 397; 401; 409;
    419; 421; 431; 433; 439; 443; 449; 457;
    461; 463; 467; 479; 487; 491; 499; 503;
    509; 521; 523; 541; 547; 557; 563; 569;
    571; 577; 587; 593; 599; 601; 607; 613;
    617; 619; 631; 641; 643; 647; 653; 659;
    661; 673; 677; 683; 691; 701; 709; 719;
    727; 733; 739; 743; 751; 757; 761; 769;
    773; 787; 797; 809; 811; 821; 823; 827;
    829; 839; 853; 857; 859; 863; 877; 881;
    883; 887; 907; 911; 919; 929; 937; 941;
    947; 953; 967; 971; 977; 983; 991; 997;
    1009; 1013; 1019; 1021; 1031; 1033; 1039; 1049;
    1051; 1061; 1063; 1069; 1087; 1091; 1093; 1097;
    1103; 1109; 1117; 1123; 1129; 1151; 1153; 1163;
    1171; 1181; 1187; 1193; 1201; 1213; 1217; 1223;
    1229; 1231; 1237; 1249; 1259; 1277; 1279; 1283;
    1289; 1291; 1297; 1301; 1303; 1307; 1319; 1321;
    1327; 1361; 1367; 1373; 1381; 1399; 1409; 1423;
    1427; 1429; 1433; 1439; 1447; 1451; 1453; 1459;
    1471; 1481; 1483; 1487; 1489; 1493; 1499; 1511;
    1523; 1531; 1543; 1549; 1553; 1559; 1567; 1571;
    1579; 1583; 1597; 1601; 1607; 1609; 1613; 1619;
    1621; 1627; 1637; 1657; 1663; 1667; 1669; 1693;
    1697; 1699; 1709; 1721; 1723; 1733; 1741; 1747;
    1753; 1759; 1777; 1783; 1787; 1789; 1801; 1811;
    1823; 1831; 1847; 1861; 1867; 1871; 1873; 1877;
    1879; 1889; 1901; 1907; 1913; 1931; 1933; 1949;
    1951; 1973; 1979; 1987; 1993; 1997; 1999; 2003;
    2011; 2017; 2027; 2029; 2039; 2053; 2063; 2069;
    2081; 2083; 2087; 2089; 2099; 2111; 2113; 2129;
    2131; 2137; 2141; 2143; 2153; 2161; 2179; 2203;
    2207; 2213; 2221; 2237; 2239; 2243; 2251; 2267;
    2269; 2273; 2281; 2287; 2293; 2297; 2309; 2311;
    2333; 2339; 2341; 2347; 2351; 2357; 2371; 2377;
    2381; 2383; 2389; 2393; 2399; 2411; 2417; 2423;
    2437; 2441; 2447; 2459; 2467; 2473; 2477; 2503;
    2521; 2531; 2539; 2543; 2549; 2551; 2557; 2579;
    2591; 2593; 2609; 2617; 2621; 2633; 2647; 2657;
    2659; 2663; 2671; 2677; 2683; 2687; 2689; 2693;
    2699; 2707; 2711; 2713; 2719; 2729; 2731; 2741;
    2749; 2753; 2767; 2777; 2789; 2791; 2797; 2801;
    2803; 2819; 2833; 2837; 2843; 2851; 2857; 2861;
    2879; 2887; 2897; 2903; 2909; 2917; 2927; 2939;
    2953; 2957; 2963; 2969; 2971; 2999; 3001; 3011;
    3019; 3023; 3037; 3041; 3049; 3061; 3067; 3079;
    3083; 3089; 3109; 3119; 3121; 3137; 3163; 3167;
    3169; 3181; 3187; 3191; 3203; 3209; 3217; 3221;
    3229; 3251; 3253; 3257; 3259; 3271; 3299; 3301;
    3307; 3313; 3319; 3323; 3329; 3331; 3343; 3347;
    3359; 3361; 3371; 3373; 3389; 3391; 3407; 3413;
    3433; 3449; 3457; 3461; 3463; 3467; 3469; 3491;
    3499; 3511; 3517; 3527; 3529; 3533; 3539; 3541;
    3547; 3557; 3559; 3571; 3581; 3583; 3593; 3607;
    3613; 3617; 3623; 3631; 3637; 3643; 3659; 3671;
    3673; 3677; 3691; 3697; 3701; 3709; 3719; 3727;
    3733; 3739; 3761; 3767; 3769; 3779; 3793; 3797;
    3803; 3821; 3823; 3833; 3847; 3851; 3853; 3863;
    3877; 3881; 3889; 3907; 3911; 3917; 3919; 3923;
    3929; 3931; 3943; 3947; 3967; 3989; 4001; 4003;
    4007; 4013; 4019; 4021; 4027; 4049; 4051; 4057;
    4073; 4079; 4091; 4093; 4099; 4111; 4127; 4129;
    4133; 4139; 4153; 4157; 4159; 4177; 4201; 4211;
    4217; 4219; 4229; 4231; 4241; 4243; 4253; 4259;
    4261; 4271; 4273; 4283; 4289; 4297; 4327; 4337;
    4339; 4349; 4357; 4363; 4373; 4391; 4397; 4409;
    4421; 4423; 4441; 4447; 4451; 4457; 4463; 4481;
    4483; 4493; 4507; 4513; 4517; 4519; 4523; 4547;
    4549; 4561; 4567; 4583; 4591; 4597; 4603; 4621;
    4637; 4639; 4643; 4649; 4651; 4657; 4663; 4673;
    4679; 4691; 4703; 4721; 4723; 4729; 4733; 4751;
    4759; 4783; 4787; 4789; 4793; 4799; 4801; 4813;
    4817; 4831; 4861; 4871; 4877; 4889; 4903; 4909;
    4919; 4931; 4933; 4937; 4943; 4951; 4957; 4967;
    4969; 4973; 4987; 4993; 4999; 5003; 5009; 5011;
    5021; 5023; 5039; 5051; 5059; 5077; 5081; 5087;
    5099; 5101; 5107; 5113; 5119; 5147; 5153; 5167;
    5171; 5179; 5189; 5197; 5209; 5227; 5231; 5233;
    5237; 5261; 5273; 5279; 5281; 5297; 5303; 5309;
    5323; 5333; 5347; 5351; 5381; 5387; 5393; 5399;
    5407; 5413; 5417; 5419; 5431; 5437; 5441; 5443;
    5449; 5471; 5477; 5479; 5483; 5501; 5503; 5507;
    5519; 5521; 5527; 5531; 5557; 5563; 5569; 5573;
    5581; 5591; 5623; 5639; 5641; 5647; 5651; 5653;
    5657; 5659; 5669; 5683; 5689; 5693; 5701; 5711;
    5717; 5737; 5741; 5743; 5749; 5779; 5783; 5791;
    5801; 5807; 5813; 5821; 5827; 5839; 5843; 5849;
    5851; 5857; 5861; 5867; 5869; 5879; 5881; 5897;
    5903; 5923; 5927; 5939; 5953; 5981; 5987; 6007;
    6011; 6029; 6037; 6043; 6047; 6053; 6067; 6073;
    6079; 6089; 6091; 6101; 6113; 6121; 6131; 6133;
    6143; 6151; 6163; 6173; 6197; 6199; 6203; 6211;
    6217; 6221; 6229; 6247; 6257; 6263; 6269; 6271;
    6277; 6287; 6299; 6301; 6311; 6317; 6323; 6329;
    6337; 6343; 6353; 6359; 6361; 6367; 6373; 6379;
    6389; 6397; 6421; 6427; 6449; 6451; 6469; 6473;
    6481; 6491; 6521; 6529; 6547; 6551; 6553; 6563;
    6569; 6571; 6577; 6581; 6599; 6607; 6619; 6637;
    6653; 6659; 6661; 6673; 6679; 6689; 6691; 6701;
    6703; 6709; 6719; 6733; 6737; 6761; 6763; 6779;
    6781; 6791; 6793; 6803; 6823; 6827; 6829; 6833;
    6841; 6857; 6863; 6869; 6871; 6883; 6899; 6907;
    6911; 6917; 6947; 6949; 6959; 6961; 6967; 6971;
    6977; 6983; 6991; 6997; 7001; 7013; 7019; 7027;
    7039; 7043; 7057; 7069; 7079; 7103; 7109; 7121;
    7127; 7129; 7151; 7159; 7177; 7187; 7193; 7207;
    7211; 7213; 7219; 7229; 7237; 7243; 7247; 7253;
    7283; 7297; 7307; 7309; 7321; 7331; 7333; 7349;
    7351; 7369; 7393; 7411; 7417; 7433; 7451; 7457;
    7459; 7477; 7481; 7487; 7489; 7499; 7507; 7517;
    7523; 7529; 7537; 7541; 7547; 7549; 7559; 7561;
    7573; 7577; 7583; 7589; 7591; 7603; 7607; 7621;
    7639; 7643; 7649; 7669; 7673; 7681; 7687; 7691;
    7699; 7703; 7717; 7723; 7727; 7741; 7753; 7757;
    7759; 7789; 7793; 7817; 7823; 7829; 7841; 7853;
    7867; 7873; 7877; 7879; 7883; 7901; 7907; 7919;
    7927; 7933; 7937; 7949; 7951; 7963; 7993; 8009;
    8011; 8017; 8039; 8053; 8059; 8069; 8081; 8087;
    8089; 8093; 8101; 8111; 8117; 8123; 8147; 8161;
    8167; 8171; 8179; 8191
]

let moduli_small_primes n =
  let ln = Bn.num_digits n in
  let dend = create_nat (ln + 1)
  and dsor = create_nat 1
  and quot = create_nat ln
  and rem = create_nat 1 in
  let res =
    List.map
      (fun p ->
        (* Compute m = n mod p *)
        blit_nat dend 0 n 0 ln;
        set_digit_nat dend ln 0;
        set_digit_nat dsor 0 p;
        div_digit_nat quot 0 rem 0 dend 0 (ln + 1) dsor 0;
        nth_digit_nat rem 0)
      small_primes in
  wipe_nat dend; wipe_nat dsor; wipe_nat quot; wipe_nat rem;
  res

let is_divisible_by_small_prime delta remainders =
  List.exists2
    (fun p m -> (m + delta) mod p = 0)
    small_primes remainders

let pseudoprime_test_values = [2;3;5;7;11;13;17;19]

let is_pseudoprime p =
  let p1 = Bn.sub p Bn.one in
  let res =
    List.for_all
      (fun x ->
        let q = Bn.mod_power (nat_of_int x) p1 p in
        let r = Bn.compare q Bn.one in
        wipe_nat q;
        r = 0)
      pseudoprime_test_values in
  wipe_nat p1;
  res

let rec random_prime ?rng numbits =
  (* Generate random odd number *)
  let n = random_nat ?rng ~lowbits:1 numbits in
  (* Precompute moduli with small primes *)
  let moduli = moduli_small_primes n in
  (* Search from n *)
  let rec find_prime delta =
    if is_divisible_by_small_prime delta moduli then
      find_prime (delta + 2)
    else begin    
      let n' = Bn.add n (nat_of_int delta) in
      if is_pseudoprime n' then
        if Bn.num_bits n' = numbits then begin
          wipe_nat n; n'
        end else begin
          wipe_nat n; wipe_nat n'; random_prime numbits
        end
      else
        find_prime (delta + 2)
    end in
  find_prime 0

let new_key ?rng ?e numbits =
  if numbits < 32 || numbits land 1 > 0 then raise(Error Wrong_key_size);
  let numbits2 = numbits / 2 in
  (* Generate primes p, q with numbits / 2 digits.
     If fixed exponent e, make sure gcd(p-1,e) = 1 and
     gcd(q-1,e) = 1. *)
  let rec gen_factor nbits =
    let n = random_prime ?rng nbits in
    match e with
      None -> n
    | Some e ->
        if Bn.relative_prime (Bn.sub n Bn.one) (nat_of_int e)
        then n
        else gen_factor nbits in
  let p = gen_factor numbits2
  and q = gen_factor numbits2 in
  (* Make sure p >= q *)
  let (p, q) =
    if Bn.compare p q < 0 then (q, p) else (p, q) in
  (* p1 = p - 1 and q1 = q - 1 *)
  let p1 = Bn.sub p Bn.one
  and q1 = Bn.sub q Bn.one in
  (* If no fixed exponent specified, generate random exponent e such that
     gcd(p-1,e) = 1 and gcd(q-1,e) = 1 *)
  let e =
    match e with
      Some e -> nat_of_int e
    | None ->
        let rec gen_exponent () =
          let n = random_nat ?rng numbits in
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
  (* qinv = q^1 mod p *)
  let qinv = Bn.mod_inv q p in
  (* Build key *)
  let res =
    { size = numbits;
      n = bytes_of_nat ~numbits:numbits n;
      e = bytes_of_nat ~numbits:numbits e;
      d = bytes_of_nat ~numbits:numbits d;
      p = bytes_of_nat ~numbits:numbits2 p;
      q = bytes_of_nat ~numbits:numbits2 q;
      dp = bytes_of_nat ~numbits:numbits2 dp;
      dq = bytes_of_nat ~numbits:numbits2 dq;
      qinv = bytes_of_nat ~numbits:numbits2 qinv } in
  wipe_nat n; wipe_nat e; wipe_nat d;
  wipe_nat p; wipe_nat q;
  wipe_nat p1; wipe_nat q1;
  wipe_nat dp; wipe_nat dq; wipe_nat qinv;
  res

end

(* Base64 encoding *)

module Base64 = struct

let base64_conv_table =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

class encode multiline =
  object (self)
    method input_block_size = 1
    method output_block_size = 1

    inherit buffered_output 256 as output_buffer

    val ibuf = String.create 3
    val mutable ipos = 0
    val mutable ocolumn = 0

    method put_char c =
      ibuf.[ipos] <- c;
      ipos <- ipos + 1;
      if ipos = 3 then begin
        let b0 = Char.code ibuf.[0]
        and b1 = Char.code ibuf.[1]
        and b2 = Char.code ibuf.[2] in
        self#ensure_capacity 4;
        obuf.[oend]   <- base64_conv_table.[b0 lsr 2];
        obuf.[oend+1] <- base64_conv_table.[(b0 land 3) lsl 4 + (b1 lsr 4)];
        obuf.[oend+2] <- base64_conv_table.[(b1 land 15) lsl 2 + (b2 lsr 6)];
        obuf.[oend+3] <- base64_conv_table.[b2 land 63];
        oend <- oend + 4;
        ipos <- 0;
        ocolumn <- ocolumn + 4;
        if multiline && ocolumn >= 72 then begin
          self#ensure_capacity 1;
          obuf.[oend] <- '\n';
          oend <- oend + 1;
          ocolumn <- 0
        end 
      end

    method put_substring s ofs len =
      for i = ofs to ofs + len - 1 do self#put_char s.[i] done

    method put_string s =
      self#put_substring s 0 (String.length s)

    method put_byte b = self#put_char (Char.chr b)

    method finish =
      begin match ipos with
        1 ->
          self#ensure_capacity 2;
          let b0 = Char.code ibuf.[0] in
          obuf.[oend]   <- base64_conv_table.[b0 lsr 2];
          obuf.[oend+1] <- base64_conv_table.[(b0 land 3) lsl 4];
          oend <- oend + 2
      | 2 ->
          self#ensure_capacity 3;
          let b0 = Char.code ibuf.[0]
          and b1 = Char.code ibuf.[1] in
          obuf.[oend]   <- base64_conv_table.[b0 lsr 2];
          obuf.[oend+1] <- base64_conv_table.[(b0 land 3) lsl 4 + (b1 lsr 4)];
          obuf.[oend+2] <- base64_conv_table.[(b1 land 15) lsl 2];
          oend <- oend + 3
      | _ -> ()
      end;
      if multiline then begin
        let num_equals =
          match ipos with 1 -> 2 | 2 -> 1 | _ -> 0 in
        self#ensure_capacity num_equals;
        String.fill obuf oend num_equals '=';
        oend <- oend + num_equals
      end;
      if multiline && ocolumn > 0 then begin
        self#ensure_capacity 1;
        obuf.[oend] <- '\n';
        oend <- oend + 1
      end;
      ocolumn <- 0

    method wipe =
      wipe_string ibuf; output_buffer#wipe
  end

let encode_multiline () = new encode true
let encode_compact () = new  encode false

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

    val ibuf = Array.create 4 0
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
            obuf.[oend]   <- Char.chr(ibuf.(0) lsl 2 + ibuf.(1) lsr 4);
            obuf.[oend+1] <- Char.chr((ibuf.(1) land 15) lsl 4 + ibuf.(2) lsr 2);
            obuf.[oend+2] <- Char.chr((ibuf.(2) land 3) lsl 6 + ibuf.(3));
            oend <- oend + 3;
            ipos <- 0
          end
        end
      end

    method put_substring s ofs len =
      for i = ofs to ofs + len - 1 do self#put_char s.[i] done

    method put_string s =
      self#put_substring s 0 (String.length s)

    method put_byte b = self#put_char (Char.chr b)

    method finish =
      finished <- true;
      match ipos with
      | 1 -> raise(Error Bad_encoding)
      | 2 ->
          self#ensure_capacity 1;
          obuf.[oend]   <- Char.chr(ibuf.(0) lsl 2 + ibuf.(1) lsr 4);
          oend <- oend + 1
      | 3 ->
          self#ensure_capacity 2;
          obuf.[oend]   <- Char.chr(ibuf.(0) lsl 2 + ibuf.(1) lsr 4);
          obuf.[oend+1] <- Char.chr((ibuf.(1) land 15) lsl 4 + ibuf.(2) lsr 2);
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
      obuf.[oend] <- hex_conv_table.[b lsr 4];
      obuf.[oend + 1] <- hex_conv_table.[b land 0xF];
      oend <- oend + 2

    method put_char c = self#put_byte (Char.code c)

    method put_substring s ofs len =
      for i = ofs to ofs + len - 1 do self#put_char s.[i] done

    method put_string s =
      self#put_substring s 0 (String.length s)

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

    val ibuf = Array.create 2 0
    val mutable ipos = 0

    method put_char c =
      let n = hex_decode_char c in
      if n >= 0 then begin
        ibuf.(ipos) <- n;
        ipos <- ipos + 1;
        if ipos = 2 then begin
          self#ensure_capacity 1;
          obuf.[oend]   <- Char.chr(ibuf.(0) lsl 4 lor ibuf.(1));
          oend <- oend + 1;
          ipos <- 0
        end
      end

    method put_substring s ofs len =
      for i = ofs to ofs + len - 1 do self#put_char s.[i] done

    method put_string s =
      self#put_substring s 0 (String.length s)

    method put_byte b = self#put_char (Char.chr b)

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
  stream -> string -> int -> int -> string -> int -> int -> flush_command
         -> bool * int * int
  = "caml_zlib_deflate_bytecode" "caml_zlib_deflate"
external deflate_end: stream -> unit = "caml_zlib_deflateEnd"

external inflate_init: bool -> stream = "caml_zlib_inflateInit"
external inflate:
  stream -> string -> int -> int -> string -> int -> int -> flush_command
         -> bool * int * int
  = "caml_zlib_inflate_bytecode" "caml_zlib_inflate"
external inflate_end: stream -> unit = "caml_zlib_inflateEnd"

class compress level =
  object(self)
    val zs = deflate_init level false
    
    inherit buffered_output 256 as output_buffer

    method input_block_size = 1
    method output_block_size = 1

    method put_substring src ofs len =
      if len > 0 then begin
        self#ensure_capacity 64;
        let (_, used_in, used_out) =
          deflate zs
                  src ofs len
                  obuf oend (String.length obuf - oend)
                  Z_NO_FLUSH in
        oend <- oend + used_out;
        if used_in < len
        then self#put_substring src (ofs + used_in) (len - used_in)
      end

    method put_string s = self#put_substring s 0 (String.length s)

    method put_char c = self#put_string (String.make 1 c)

    method put_byte b = self#put_char (Char.chr b)

    method finish =
      self#ensure_capacity 64;
      let (finished, _, used_out) =
         deflate zs
                 "" 0 0
                 obuf oend (String.length obuf - oend)
                 Z_FINISH in
      oend <- oend + used_out;
      if finished then deflate_end zs else self#finish

    method wipe =
      output_buffer#wipe
end

let compress ?(level = 6) () = new compress level

class uncompress =
  object(self)
    val zs = inflate_init false
    
    inherit buffered_output 256 as output_buffer

    method input_block_size = 1
    method output_block_size = 1

    method put_substring src ofs len =
      if len > 0 then begin
        self#ensure_capacity 64;
        let (_, used_in, used_out) =
          inflate zs
                  src ofs len
                  obuf oend (String.length obuf - oend)
                  Z_SYNC_FLUSH in
        oend <- oend + used_out;
        if used_in < len
        then self#put_substring src (ofs + used_in) (len - used_in)
      end

    method put_string s = self#put_substring s 0 (String.length s)

    method put_char c = self#put_string (String.make 1 c)

    method put_byte b = self#put_char (Char.chr b)

    method finish =
      let rec do_finish first_finish =
        self#ensure_capacity 64;
        let (finished, _, used_out) =
           inflate zs
                   " " 0 (if first_finish then 1 else 0)
                   obuf oend (String.length obuf - oend)
                   Z_FINISH in
        oend <- oend + used_out;
        if not finished then do_finish false in
      do_finish true; inflate_end zs

    method wipe =
      output_buffer#wipe
end

let uncompress () = new uncompress

end

(* Utilities *)

let xor_string src src_ofs dst dst_ofs len =
  if src_ofs < 0 || src_ofs + len > String.length src
  || dst_ofs < 0 || dst_ofs + len > String.length dst
  then invalid_arg "xor_string";
  xor_string src src_ofs dst dst_ofs len
  
