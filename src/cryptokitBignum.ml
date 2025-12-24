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

(* This is no longer used in Cryptokit.  Kept for backward compatibility. *)

let zero = Z.zero
let one = Z.one
let of_int = Z.of_int
let compare = Z.compare
let add = Z.add
let sub = Z.sub
let mult = Z.mul
let div = Z.div
let mod_ = Z.rem
let lcm = Z.lcm
let mod_power = Z.powm_sec
let sub_mod a b p =
  let d = Z.sub a b in
  if Z.sign d < 0 then Z.add d p else d
let mod_inv = Z.invert

(* This is still used. *)

let relative_prime a b =
  Z.equal (Z.gcd a b) Z.one

(* Modular arithmetic *)

let addm a b q = Z.(erem (a + b) q)
let subm a b q = Z.(erem (a - b) q)
let mulm a b q = Z.(erem (a * b) q)
let sqrm a q = Z.(erem (a * a) q)
let invm = Z.invert
let divm a b q = mulm a (Z.invert b q) q
let powm = Z.powm

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

(* Modular square root.  Tonnelli-Shanks algorithm. *)

let sqrtm n p =
  let p12 = Z.(pred p asr 1) in
  let is_quadratic_residue x =
    (* Euler's criterion *)
    powm x p12 p = Z.one in
  let rec find_nonquadratic_residue z =
    if is_quadratic_residue z
    then find_nonquadratic_residue (Z.succ z)
    else z in
  let rec repsquare i t =
    if t = Z.one then i else repsquare (i + 1) (mulm t t p) in
  let rec loop m c t r =
    if t = Z.one then Some r else begin
      let i = repsquare 1 (sqrm t p) in
      let b = powm c (Z.shift_left Z.one (m - i - 1)) p in
      let bb = sqrm b p in
      loop i bb (mulm t bb p) (mulm r b p)
    end in
  if n = Z.zero then Some Z.zero else
  if not (is_quadratic_residue n) then None else begin
    let s = Z.trailing_zeros (Z.pred p) in
    let q = Z.shift_right (Z.pred p) s in
    let z = find_nonquadratic_residue (Z.of_int 2) in
    loop s (powm z q p) (powm n q p) (powm n Z.(succ q asr 1) p)
  end

(* Conversions *)

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

(* Random number generation *)

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

