(* Compute compilation and linking flags *)

module Configurator = Configurator.V1

(* Compile and link a dummy C program with the given flags. *)
let test ~c_flags ~link_flags =
  let test_program = "int main() { return 0; }" in
  let c = Configurator.create "cryptokit" in
  Configurator.c_test c test_program ~c_flags ~link_flags

let compute_flags ~os_type ~system ~architecture =
  let zlib = os_type <> "Win32" in
  let hardwaresupport =
    (architecture = "amd64" || architecture = "i386")
    && test ~c_flags:[ "-maes" ] ~link_flags:[]
  in
  let append_if c y x = if c then x @ [ y ] else x in
  let flags =
    []
    |> append_if zlib "-DHAVE_ZLIB"
    |> append_if hardwaresupport "-maes"
  in
  let library_flags =
    []
    |> append_if (zlib && (system = "win32" || system = "win64")) "zlib.lib"
    |> append_if (zlib && system <> "win32" && system <> "win64") "-lz"
    |> append_if (system = "win32" || system = "win64") "advapi32.lib"
    |> append_if (system = "mingw" || system = "mingw64") "-ladvapi32"
  in
  Configurator.Flags.write_sexp "flags.sexp" flags;
  Configurator.Flags.write_sexp "library_flags.sexp" library_flags

let () =
  match Sys.argv with
  | [| _; "-os_type"; os_type;
          "-system"; system;
          "-architecture"; architecture;
    |] -> compute_flags ~os_type ~system ~architecture
  | _ -> failwith "unexpected command line arguments"
