
include ../Makefile.conf

test: test.byt
	$(OCAMLRUN) -I ../src ./test.byt

VPATH=../src
test.byt: libcryptokit.a cryptokit.cma test.ml
	$(OCAMLC) -I ../src -o test.byt unix.cma nums.cma cryptokit.cma test.ml

clean::
	-$(RM) test.byt

speedtest: libcryptokit.a cryptokit.cmxa speedtest.ml
	$(OCAMLOPT) -o speedtest -I ../src -ccopt -L../src \
                unix.cmxa nums.cmxa cryptokit.cmxa speedtest.ml

clean::
	-$(RM) speedtest

clean::
	-$(RM) *.cmi *.cmo *.cmx
