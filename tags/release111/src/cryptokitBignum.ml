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

(* Arithmetic on big integers, based on the ZArith library. *)

type t = Z.t

external wipe: t -> unit = "caml_wipe_z"

let zero = Z.zero
let one = Z.one

let of_int = Z.of_int

let compare = Z.compare

let add = Z.add
let sub = Z.sub
let mult = Z.mul
let mod_ = Z.rem

let relative_prime a b =
  Z.equal (Z.gcd a b) Z.one

let mod_power = Z.powm_sec

let sub_mod a b p =
  let d = Z.sub a b in
  if Z.sign d < 0 then Z.add d p else d

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
  let amodp = Z.rem a p and amodq = Z.rem a q in
  let mp = mod_power amodp dp p and mq = mod_power amodq dq q in
  let diff = sub_mod mp mq p in
  let diff_qinv = Z.mul diff qinv in
  let diff_qinv_mod_p = Z.rem diff_qinv p in
  let res = Z.(add (mul q diff_qinv_mod_p) mq) in
  wipe amodp; wipe amodq;
  (* It is possible that res == mq, so we cannot wipe mq.
     For consistency we don't wipe any of the intermediate results
     besides amodp and amodq. *)
  res

let mod_inv = Z.invert

let wipe_bytes s = Bytes.fill s 0 (Bytes.length s) '\000'
  
let of_bytes s =
  let l = String.length s in
  let t = Bytes.create l in
  for i = 0 to l - 1 do Bytes.set t i s.[l - 1 - i] done;
  let n = Z.of_bits (Bytes.unsafe_to_string t) in
  wipe_bytes t;
  n

let to_bytes ?numbits n =
  let s = Z.to_bits n in
  let l =
    match numbits with
    | None -> String.length s
    | Some nb -> assert (Z.numbits n <= nb); (nb + 7) / 8 in
  let t = Bytes.make l '\000' in
  for i = 0 to String.length s - 1 do
    Bytes.set t (l - 1 - i) s.[i]
  done;
  wipe_bytes (Bytes.unsafe_of_string s);
  Bytes.unsafe_to_string t

let change_byte s i f =
  Bytes.set s i (Char.chr (f (Char.code (Bytes.get s i))))

let random ~rng ?(odd = false) numbits =
  let numbytes = (numbits + 7) / 8 in
  let buf = Bytes.create numbytes in
  rng buf 0 numbytes;
  (* adjust low byte if requested *)
  if odd then
    change_byte buf 0 (fun b -> b lor 1);
  (* adjust high byte so that the number is exactly numbits long *)
  let mask = 1 lsl ((numbits - 1) land 7) in
  change_byte buf (numbytes - 1)
    (fun b -> (b land (mask - 1)) lor mask);
  (* convert to a number *)
  let n = Z.of_bits (Bytes.unsafe_to_string buf) in
  wipe_bytes buf;
  assert (Z.numbits n = numbits);
  if odd then assert (Z.is_odd n);
  n

let rec random_prime ~rng numbits =
  (* Generate random odd number *)
  let n = random ~rng ~odd:true numbits in
  (* Find next prime above n *)
  let p = Z.nextprime n in
  (* Make sure it has the right number of bits *)
  if Z.numbits p = numbits then p else random_prime ~rng numbits

