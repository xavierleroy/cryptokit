# Modify to reflect the location of the include file <zlib.h>
ZLIBINCLUDE=-I/usr/include
# Modify to reflect the location and name of the zlib library libz.a or libz.so
ZLIBLIB=-lz

OCAMLC=ocamlc -g
OCAMLOPT=ocamlopt
OCAMLDEP=ocamldep
MKLIB=ocamlmklib
CFLAGS=-O $(ZLIBINCLUDE)

C_OBJS=\
  rijndael-alg-fst.o stubs-aes.o \
  d3des.o stubs-des.o \
  arcfour.o stubs-arcfour.o \
  sha1.o stubs-sha1.o \
  stubs-md5.o \
  stubs-zlib.o \
  stubs-misc.o

CAML_OBJS=cryptokit.cmo

all: libcryptokit.a cryptokit.cmi cryptokit.cma 

allopt: libcryptokit.a cryptokit.cmi cryptokit.cmxa 

libcryptokit.a: $(C_OBJS)
	$(MKLIB) -o cryptokit $(C_OBJS) $(ZLIBLIB)

cryptokit.cma: $(CAML_OBJS)
	$(MKLIB) -o cryptokit $(CAML_OBJS)

cryptokit.cmxa: $(CAML_OBJS:.cmo=.cmx)
	$(MKLIB) -o cryptokit $(CAML_OBJS:.cmo=.cmx) $(ZLIBLIB)

test: libcryptokit.a cryptokit.cma test.ml
	$(OCAMLC) -o test unix.cma nums.cma cryptokit.cma test.ml

clean::
	rm -f test

speedtest: libcryptokit.a cryptokit.cmxa speedtest.ml
	$(OCAMLOPT) -o speedtest -ccopt -L. \
                unix.cmxa nums.cmxa cryptokit.cmxa speedtest.ml

clean::
	rm -f speedtest

.SUFFIXES: .ml .mli .cmo .cmi .cmx

.mli.cmi:
	$(OCAMLC) -c $(COMPFLAGS) $<

.ml.cmo:
	$(OCAMLC) -c $(COMPFLAGS) $<

.ml.cmx:
	$(OCAMLOPT) -c $(COMPFLAGS) $<

.c.o:
	$(OCAMLC) -c -ccopt "$(CFLAGS)" $<

clean::
	rm -f *.cm* *.o *.a *.so

depend:
	gcc -MM *.c > .depend
	$(OCAMLDEP) *.mli *.ml >> .depend

include .depend
