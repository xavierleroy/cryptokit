(* Compute compilation and linking flags *)

let write_sexp file list =
  let oc = open_out file in
  let content = List.map (Printf.sprintf "%S") list |> String.concat " " in
  Printf.fprintf oc "(%s)" content;
  close_out oc

(* We could also allow the user to override [zlib] and [hardwaresupport]. *)
let compute_flags ~os_type ~system ~architecture =
  let zlib = os_type <> "Win32" in
  let hardwaresupport =
    (architecture = "amd64" || architecture = "i386") && os_type <> "Win32"
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
  write_sexp "flags.sexp" flags;
  write_sexp "library_flags.sexp" library_flags

let () =
  match Sys.argv with
  | [|
   _; "-os_type"; os_type; "-system"; system; "-architecture"; architecture;
  |] ->
      compute_flags ~os_type ~system ~architecture
  | _ -> failwith "unexpected command line arguments"
