# make package               .deb nach dist/ bauen (Version: VERSION)
# make package VERSION=1.2.0
# make test                  Unit-Tests
#
# Gebaut wird mit nfpm; ist es nicht installiert, läuft es per Docker.
VERSION ?= 1.0.0
export VERSION

DIST := dist
NFPM_IMAGE := goreleaser/nfpm:v2.48.0
NFPM := $(shell command -v nfpm 2>/dev/null)
ifeq ($(NFPM),)
NFPM := docker run --rm -e VERSION -v "$(CURDIR)":/src -w /src $(NFPM_IMAGE)
endif

.PHONY: package test clean

package: test
	mkdir -p $(DIST)
	$(NFPM) package --config packaging/nfpm.yaml --packager deb --target $(DIST)/

test:
	python3 -m unittest discover -s tests -t .

clean:
	rm -rf $(DIST)
