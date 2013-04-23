
bootstrap = require("bootstrap")

bootstrap.init()

ci = require("ci")
godi = require("godi")

ci.init()
godi.init()

godi.bootstrap("3.12")
godi.update()
godi.upgrade()
godi.build("godi-findlib")

ci.exec("ocaml", "setup.ml", "-configure")
ci.exec("ocaml", "setup.ml", "-build")
ci.exec("ocaml", "setup.ml", "-test")
