
MKFILE=Makefile

depend:
	$(MAKE) -f $(MKFILE) -C src $@

all:
	$(MAKE) -f $(MKFILE) -C src $@

allopt:
	$(MAKE) -f $(MKFILE) -C src $@

test:
	$(MAKE) -f $(MKFILE) -C test $@ 

install:
	$(MAKE) -f $(MKFILE) -C src $@

clean:
	$(MAKE) -f $(MKFILE) -C src clean
	$(MAKE) -f $(MKFILE) -C test clean

doc:
	$(MAKE) -f $(MKFILE) -C src doc

.PHONY: depend all allopt test install clean doc
