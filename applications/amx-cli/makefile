include makefile.inc

NOW = $(shell date +"%Y-%m-%d(%H:%M:%S %z)")

# Extra destination directories
PKGDIR = ./output/$(MACHINE)/pkg/

define create_changelog
	@$(ECHO) "Update changelog"
	mv CHANGELOG.md CHANGELOG.md.bak
	head -n 9 CHANGELOG.md.bak > CHANGELOG.md
	$(ECHO) "" >> CHANGELOG.md
	$(ECHO) "## Release $(VERSION) - $(NOW)" >> CHANGELOG.md
	$(ECHO) "" >> CHANGELOG.md
	$(GIT) log --pretty=format:"- %s" $$($(GIT) describe --tags | grep -v "merge" | cut -d'-' -f1)..HEAD  >> CHANGELOG.md
	$(ECHO) "" >> CHANGELOG.md
	tail -n +10 CHANGELOG.md.bak >> CHANGELOG.md
	rm CHANGELOG.md.bak
endef

# targets
all:
	$(MAKE) -C src all

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean

install: all
	$(INSTALL) -D -p -m 0755 src/$(COMPONENT) $(DEST)$(BINDIR)/$(COMPONENT)
	$(INSTALL) -D -p -m 0644 config/amx-cli.conf $(DEST)/etc/amx/cli/amx-cli.conf
	$(INSTALL) -D -p -m 0644 config/amx-cli.init $(DEST)/etc/amx/cli/amx-cli.init

package: all
	$(INSTALL) -D -p -m 0755 src/$(COMPONENT) $(PKGDIR)$(BINDIR)/$(COMPONENT)
	$(INSTALL) -D -p -m 0644 config/amx-cli.conf $(PKGDIR)/etc/amx/cli/amx-cli.conf
	$(INSTALL) -D -p -m 0644 config/amx-cli.init $(PKGDIR)/etc/amx/cli/amx-cli.init
	cd $(PKGDIR) && $(TAR) -czvf ../$(COMPONENT)-$(VERSION).tar.gz .
	cp $(PKGDIR)../$(COMPONENT)-$(VERSION).tar.gz .
	make -C packages

changelog:
	$(call create_changelog)

test:
	$(MAKE) -C test run
	$(MAKE) -C test coverage

.PHONY: all clean changelog install package test