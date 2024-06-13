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
	$(INSTALL) -D -p -m 0644 odl/greeter_defaults.odl $(DEST)/etc/amx/greeter/greeter_defaults.odl
	$(INSTALL) -D -p -m 0644 odl/greeter_definition.odl $(DEST)/etc/amx/greeter/greeter_definition.odl
	$(INSTALL) -D -p -m 0644 odl/greeter_extra.odl $(DEST)/etc/amx/greeter/greeter_extra.odl
	$(INSTALL) -D -p -m 0644 odl/greeter.odl $(DEST)/etc/amx/greeter/greeter.odl
	$(INSTALL) -D -p -m 0755 src/$(COMPONENT) $(DEST)$(BINDIR)/greeter

package: all
	$(INSTALL) -D -p -m 0644 odl/greeter_defaults.odl $(PKGDIR)/etc/amx/greeter/greeter_defaults.odl
	$(INSTALL) -D -p -m 0644 odl/greeter_definition.odl $(PKGDIR)/etc/amx/greeter/greeter_definition.odl
	$(INSTALL) -D -p -m 0644 odl/greeter_extra.odl $(PKGDIR)/etc/amx/greeter/greeter_extra.odl
	$(INSTALL) -D -p -m 0644 odl/greeter.odl $(PKGDIR)/etc/amx/greeter/greeter.odl
	$(INSTALL) -D -p -m 0755 src/$(COMPONENT) $(PKGDIR)$(BINDIR)/greeter
	cd $(PKGDIR) && $(TAR) -czvf ../$(COMPONENT)-$(VERSION).tar.gz .
	cp $(PKGDIR)../$(COMPONENT)-$(VERSION).tar.gz .
	make -C packages

changelog:
	$(call create_changelog)

doc:
	$(eval ODLFILES += odl/greeter_defaults.odl)
	$(eval ODLFILES += odl/greeter_definition.odl)
	$(eval ODLFILES += odl/greeter_extra.odl)
	$(eval ODLFILES += odl/greeter.odl)

	mkdir -p output/xml
	mkdir -p output/html
	mkdir -p output/confluence
	amxo-cg -Gxml,output/xml/$(COMPONENT).xml $(or $(ODLFILES), "")
	amxo-xml-to -x html -o output-dir=output/html -o title="$(COMPONENT)" -o version=$(VERSION) -o sub-title="Datamodel reference" output/xml/*.xml
	amxo-xml-to -x confluence -o output-dir=output/confluence -o title="$(COMPONENT)" -o version=$(VERSION) -o sub-title="Datamodel reference" output/xml/*.xml

test:
	$(MAKE) -C test run
	$(MAKE) -C test coverage

.PHONY: all clean changelog install package doc test