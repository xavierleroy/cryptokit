open Base
open Stdio

let () =
  Configurator.main ~name:"cryptokit" (fun t ->
      let arch = Configurator.ocaml_config_var_exn t "architecture" in
      let system = Configurator.ocaml_config_var_exn t "system" in
      let os_type = Configurator.ocaml_config_var_exn t "os_type" in
      let zlib = not Sys.win32 in
      let open String in
      let hardware_support =
        (arch = "amd64" || arch = "i386") && (os_type <> "Win32") in

      let (cflags, libs) =
        if zlib then
          (["-DHAVE_ZLIB"],
           [if system = "win32" || system = "win64" then
              "zlib.lib"
            else
              "-lz"])
        else
          ([], []) in
      let libs =
        if system = "win32" || system = "win64" then
          libs @ ["advapi32.lib"]
        else if system = "mingw" || system = "mingw64" then
          libs @ ["-ladvapi32"]
        else
          libs in
      let cflags =
        if hardware_support then
          cflags @ ["-maes"]
        else
          cflags in

      let write_sexp file sexp =
        Out_channel.write_all file ~data:(Sexp.to_string sexp) in
      write_sexp "c_flags.sexp" (sexp_of_list sexp_of_string cflags);
      write_sexp "c_library_flags.sexp" (sexp_of_list sexp_of_string libs)
    )
