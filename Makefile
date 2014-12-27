BUILDFLAGS=-classic-display
# OASIS_START
# DO NOT EDIT (digest: a3c674b4239234cbbe53afe090018954)

SETUP = ocaml setup.ml

build: setup.data
	$(SETUP) -build $(BUILDFLAGS)

doc: setup.data build
	$(SETUP) -doc $(DOCFLAGS)

test: setup.data build
	$(SETUP) -test $(TESTFLAGS)

all:
	$(SETUP) -all $(ALLFLAGS)

install: setup.data
	$(SETUP) -install $(INSTALLFLAGS)

uninstall: setup.data
	$(SETUP) -uninstall $(UNINSTALLFLAGS)

reinstall: setup.data
	$(SETUP) -reinstall $(REINSTALLFLAGS)

clean:
	$(SETUP) -clean $(CLEANFLAGS)

distclean:
	$(SETUP) -distclean $(DISTCLEANFLAGS)

setup.data:
	$(SETUP) -configure $(CONFIGUREFLAGS)

configure:
	$(SETUP) -configure $(CONFIGUREFLAGS)

.PHONY: build doc test all install uninstall reinstall clean distclean configure

# OASIS_STOP

# Uncomment to test the deploy process.
# DEPLOY_ARGS=--dry_run --verbose --ignore_changes

# Use 'make deploy FORGE_USER=you' to change this value.
FORGE_USER=gildor-admin

# Contact sylvain@le-gall.net to install admin-gallu-deploy and
# admin-gallu-oasis-increment or to do the release.
deploy:
	OASIS_VERSION=$$(oasis query version | sed -e 's/\.//g'); \
	../admin-gallu/src/admin-gallu-deploy \
		--vcs_tag release$$OASIS_VERSION \
		--forge_upload --forge_group cryptokit --forge_user $(FORGE_USER) \
		$(DEPLOY_ARGS)
	../admin-gallu/src/admin-gallu-oasis-increment \
		--setup_run --use_vcs \
		$(DEPLOY_ARGS)
