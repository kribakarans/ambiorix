include ../makefile.inc
PACKAGE_VERSION?=$(shell git describe --tags | cut -dv -f2 | sed -E 's/(.*)-([0-9]+)-(.*)/\1.dev\2/')

all: header build footer

clean:
	@echo "Clean $(COMPONENT)"
	python3 setup.py clean
	rm -rf dist
	rm -rf build
	rm -rf python_amx.egg-info

build: clean
	sed "s/version='99.99.99'/version='$(PACKAGE_VERSION)'/g" setup.py > versioned_setup.py
	python3 versioned_setup.py build
	python3 versioned_setup.py bdist_wheel
	rm versioned_setup.py

header:
	@echo "==================================================="
	@echo "^^ Project: $(COMPONENT)"
	@echo "^^ Build started, please wait..."
	@echo "==================================================="

footer: build
	@echo "==================================================="
	@echo "^^ Project: $(COMPONENT)"
	@echo "^^ Build finished"
	@echo "==================================================="

.PHONY: all install release clean build header footer
