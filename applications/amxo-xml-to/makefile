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
	$(INSTALL) -d -m 0755 $(DEST)//etc/amx/xsl
	$(INSTALL) -D -p -m 0644 config/xsl/*.xsl $(DEST)/etc/amx/xsl/
	$(INSTALL) -d -m 0755 $(DEST)//etc/amx/html
	$(INSTALL) -D -p -m 0644 config/html/* $(DEST)/etc/amx/html/
	$(INSTALL) -D -p -m 0644 config/default.conf $(DEST)/etc/amx/xml/default.conf

package: all
	$(INSTALL) -D -p -m 0755 src/$(COMPONENT) $(PKGDIR)$(BINDIR)/$(COMPONENT)
	$(INSTALL) -d -m 0755 $(PKGDIR)//etc/amx/xsl
	$(INSTALL) -D -p -m 0644 config/xsl/*.xsl $(PKGDIR)/etc/amx/xsl/
	$(INSTALL) -d -m 0755 $(PKGDIR)//etc/amx/html
	$(INSTALL) -D -p -m 0644 config/html/* $(PKGDIR)/etc/amx/html/
	$(INSTALL) -D -p -m 0644 config/default.conf $(PKGDIR)/etc/amx/xml/default.conf
	cd $(PKGDIR) && $(TAR) -czvf ../$(COMPONENT)-$(VERSION).tar.gz .
	cp $(PKGDIR)../$(COMPONENT)-$(VERSION).tar.gz .
	make -C packages

changelog:
	$(call create_changelog)

test:
	$(MAKE) -C test run
	$(MAKE) -C test coverage

.PHONY: all clean changelog install package test