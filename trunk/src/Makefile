
include ../Makefile.conf

C_OBJS=\
  rijndael-alg-fst.o stubs-aes.o \
  d3des.o stubs-des.o \
  blowfish.o stubs-blowfish.o \
  arcfour.o stubs-arcfour.o \
  sha1.o stubs-sha1.o \
  sha256.o stubs-sha256.o \
  ripemd160.o stubs-ripemd160.o \
  stubs-md5.o \
  stubs-zlib.o \
  stubs-misc.o \
  stubs-rng.o

CAML_OBJS=cryptokit.cmo

all: libcryptokit.a cryptokit.cmi cryptokit.cma 

allopt: libcryptokit.a cryptokit.cmi cryptokit.cmxa 

libcryptokit.a: $(C_OBJS)
	$(MKLIB) -o cryptokit $(C_OBJS) -L$(ZLIB_LIBDIR) $(ZLIB_LIB)

cryptokit.cma: $(CAML_OBJS)
	$(MKLIB) -o cryptokit $(CAML_OBJS) -L$(ZLIB_LIBDIR) $(ZLIB_LIB)

cryptokit.cmxa: $(CAML_OBJS:.cmo=.cmx)
	$(MKLIB) -o cryptokit $(CAML_OBJS:.cmo=.cmx) -L$(ZLIB_LIBDIR) $(ZLIB_LIB)

install:
	cp cryptokit.cmi cryptokit.cma cryptokit.mli $(INSTALLDIR)
	cp libcryptokit.a $(INSTALLDIR)
	if test -f dllcryptokit.so; then cp dllcryptokit.so $(INSTALLDIR)/stublibs; fi
	if test -f cryptokit.cmxa; then cp cryptokit.cmxa cryptokit.cmx cryptokit.a $(INSTALLDIR); fi

doc: FORCE
	$(OCAMLDOC) -html -d ../doc cryptokit.mli

FORCE:

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
	-$(RM) *.cm* *.o *.a *.so

depend:
	gcc -MM -I `$(OCAMLC) -where` -isystem `$(OCAMLC) -where ` *.c > .depend
	$(OCAMLDEP) *.mli *.ml >> .depend

include .depend
