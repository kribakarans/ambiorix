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
	$(INSTALL) -D -p -m 0644 odl/la_threshold_defaults.odl $(DEST)/etc/amx/la_threshold/la_threshold_defaults.odl
	$(INSTALL) -D -p -m 0644 odl/la_threshold_definition.odl $(DEST)/etc/amx/la_threshold/la_threshold_definition.odl
	$(INSTALL) -D -p -m 0644 odl/la_threshold.odl $(DEST)/etc/amx/la_threshold/la_threshold.odl
	$(INSTALL) -D -p -m 0755 odl/la_threshold.odl $(DEST)$(BINDIR)/la_threshold.odl
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/object/la_threshold.so $(DEST)/usr/lib/amx/la_threshold/la_threshold.so
	$(INSTALL) -d -m 0755 $(DEST)$(BINDIR)
	ln -sfr $(DEST)$(BINDIR)/amxrt $(DEST)$(BINDIR)/la_threshold

package: all
	$(INSTALL) -D -p -m 0644 odl/la_threshold_defaults.odl $(PKGDIR)/etc/amx/la_threshold/la_threshold_defaults.odl
	$(INSTALL) -D -p -m 0644 odl/la_threshold_definition.odl $(PKGDIR)/etc/amx/la_threshold/la_threshold_definition.odl
	$(INSTALL) -D -p -m 0644 odl/la_threshold.odl $(PKGDIR)/etc/amx/la_threshold/la_threshold.odl
	$(INSTALL) -D -p -m 0755 odl/la_threshold.odl $(PKGDIR)$(BINDIR)/la_threshold.odl
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/object/la_threshold.so $(PKGDIR)/usr/lib/amx/la_threshold/la_threshold.so
	$(INSTALL) -d -m 0755 $(PKGDIR)$(BINDIR)
	cd $(PKGDIR) && $(TAR) -czvf ../$(COMPONENT)-$(VERSION).tar.gz .
	cp $(PKGDIR)../$(COMPONENT)-$(VERSION).tar.gz .
	make -C packages

changelog:
	$(call create_changelog)

doc:
	$(eval ODLFILES += odl/la_threshold_defaults.odl)
	$(eval ODLFILES += odl/la_threshold_definition.odl)
	$(eval ODLFILES += odl/la_threshold.odl)
	$(eval ODLFILES += odl/la_threshold.odl)

	mkdir -p output/xml
	mkdir -p output/html
	amxo-cg -Gxml,output/xml/$(COMPONENT).xml $(or $(ODLFILES), "")
	amxo-xml-to -x html -o output-dir=output/html -o title="$(COMPONENT)" -o version=$(VERSION) -o sub-title="Datamodel reference" output/xml/*.xml

test:
	$(MAKE) -C test run
	$(MAKE) -C test coverage

.PHONY: all clean changelog install package doc test