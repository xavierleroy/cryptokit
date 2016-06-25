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

(* Arithmetic on big integers *)

type t

val zero : t
val one : t
val of_int : int -> t

val compare : t -> t -> int

val add : t -> t -> t
val sub : t -> t -> t
val mult : t -> t -> t
val mod_ : t -> t -> t

val relative_prime : t -> t -> bool
val mod_power : t -> t -> t -> t
val mod_power_CRT : t -> t -> t -> t -> t -> t -> t
val mod_inv : t -> t -> t

val of_bytes : string -> t
val to_bytes : ?numbits:int -> t -> string

val random : rng:(bytes -> int -> int -> unit) -> ?odd:bool -> int -> t
val random_prime : rng:(bytes -> int -> int -> unit) -> int -> t

val wipe : t -> unit

