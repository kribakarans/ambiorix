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
	$(MAKE) -C mod_session_dummy/src all
	$(MAKE) -C mod_session_httpaccess/src all

clean:
	$(MAKE) -C src clean
	$(MAKE) -C test clean

install: all
	$(INSTALL) -D -p -m 0644 odl/amx-fcgi.odl $(DEST)/etc/amx/amx-fcgi/amx-fcgi.odl
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/object/amx-fcgi.so $(DEST)/usr/lib/amx/amx-fcgi/amx-fcgi.so
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/mod-session-dummy.so $(DEST)/usr/lib/amx/amx-fcgi/modules/mod-session-dummy.so
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/mod-session-httpaccess.so $(DEST)/usr/lib/amx/amx-fcgi/modules/mod-session-httpaccess.so
	$(INSTALL) -d -m 0755 $(DEST)$(BINDIR)
	ln -sfr $(DEST)$(BINDIR)/amxrt $(DEST)$(BINDIR)/amx-fcgi
	$(INSTALL) -D -p -m 0755 scripts/$(COMPONENT).sh $(DEST)$(INITDIR)/$(COMPONENT)

package: all
	$(INSTALL) -D -p -m 0644 odl/amx-fcgi.odl $(PKGDIR)/etc/amx/amx-fcgi/amx-fcgi.odl
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/object/amx-fcgi.so $(PKGDIR)/usr/lib/amx/amx-fcgi/amx-fcgi.so
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/mod-session-dummy.so $(PKGDIR)/usr/lib/amx/amx-fcgi/modules/mod-session-dummy.so
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/mod-session-httpaccess.so $(PKGDIR)/usr/lib/amx/amx-fcgi/modules/mod-session-httpaccess.so
	$(INSTALL) -d -m 0755 $(PKGDIR)$(BINDIR)
	rm -f $(PKGDIR)$(BINDIR)/amx-fcgi
	ln -sfr $(PKGDIR)$(BINDIR)/amxrt $(PKGDIR)$(BINDIR)/amx-fcgi
	$(INSTALL) -D -p -m 0755 scripts/$(COMPONENT).sh $(PKGDIR)$(INITDIR)/$(COMPONENT)
	cd $(PKGDIR) && $(TAR) -czvf ../$(COMPONENT)-$(VERSION).tar.gz .
	cp $(PKGDIR)../$(COMPONENT)-$(VERSION).tar.gz .
	make -C packages

changelog:
	$(call create_changelog)

doc:
	$(eval ODLFILES += odl/amx-fcgi.odl)

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