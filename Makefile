# make package               build the .deb into dist/ (version: VERSION)
# make package VERSION=1.2.0
# make test                  unit tests
#
# Built with nfpm; if it is not installed, it runs via Docker.
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
