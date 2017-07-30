(***********************************************************************)
(*                                                                     *)
(*                      The Cryptokit library                          *)
(*                                                                     *)
(*            Xavier Leroy, projet Gallium, INRIA Paris                *)
(*                                                                     *)
(*  Copyright 2017 Institut National de Recherche en Informatique et   *)
(*  en Automatique.  All rights reserved.  This file is distributed    *)
(*  under the terms of the GNU Library General Public License, with    *)
(*  the special exception on linking described in file LICENSE.        *)
(*                                                                     *)
(***********************************************************************)

(* Generate pseudorandom data on stdout, for testing with "dieharder" *)

open Cryptokit

let output_pr_data rng =
  let b = Bytes.create 64 in
  while true do
    rng#random_bytes b 0 64;
    output stdout b 0 64
  done

let usage() =
  prerr_string {|Usage:
    ./prngtest.native aes-ctr  | dieharder -a -g 200
    ./prngtest.native chacha20 | dieharder -a -g 200
    ./prngtest.native hardware | dieharder -a -g 200
Warning: each dieharder run takes a long time.
|};
  exit 2

let _ =
  let seed =
    if Array.length Sys.argv > 2
    then Sys.argv.(2)
    else "Supercalifragilistusexpialidolcius" in
  let rng =
    if Array.length Sys.argv > 1 then begin
      match Sys.argv.(1) with
      | "aes-ctr"  -> Random.pseudo_rng_aes_ctr seed
      | "chacha20" -> Random.pseudo_rng seed
      | "hardware" -> Random.hardware_rng ()
      | _          -> usage()
    end else usage() in
  output_pr_data rng

  
