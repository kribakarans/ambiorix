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

install: all
	$(INSTALL) -D -p -m 0644 odl/ssh_server.odl $(DEST)/etc/amx/ssh_server/ssh_server.odl
	$(INSTALL) -D -p -m 0644 odl/ssh_server_definition.odl $(DEST)/etc/amx/ssh_server/ssh_server_definition.odl
	$(INSTALL) -D -p -m 0644 odl/ssh_server_storage-odl.odl $(DEST)/etc/amx/ssh_server/ssh_server_storage-odl.odl
	$(INSTALL) -D -p -m 0644 odl/ssh_server_storage-uci.odl $(DEST)/etc/amx/ssh_server/ssh_server_storage-uci.odl
	$(INSTALL) -D -p -m 0644 odl/ssh_server_defaults.odl $(DEST)/etc/amx/ssh_server/defaults/odl/00_defaults.odl
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/object/amx-ssh-server.so $(DEST)/usr/lib/amx/ssh_server/amx-ssh-server.so
	$(INSTALL) -d -m 0755 $(DEST)$(BINDIR)
	ln -sfr $(DEST)$(BINDIR)/amxrt $(DEST)$(BINDIR)/ssh_server

package: all
	$(INSTALL) -D -p -m 0644 odl/ssh_server.odl $(PKGDIR)/etc/amx/ssh_server/ssh_server.odl
	$(INSTALL) -D -p -m 0644 odl/ssh_server_definition.odl $(PKGDIR)/etc/amx/ssh_server/ssh_server_definition.odl
	$(INSTALL) -D -p -m 0644 odl/ssh_server_storage-odl.odl $(PKGDIR)/etc/amx/ssh_server/ssh_server_storage-odl.odl
	$(INSTALL) -D -p -m 0644 odl/ssh_server_storage-uci.odl $(PKGDIR)/etc/amx/ssh_server/ssh_server_storage-uci.odl
	$(INSTALL) -D -p -m 0644 odl/ssh_server_defaults.odl $(PKGDIR)/etc/amx/ssh_server/defaults/odl/00_defaults.odl
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/object/amx-ssh-server.so $(PKGDIR)/usr/lib/amx/ssh_server/amx-ssh-server.so
	$(INSTALL) -d -m 0755 $(PKGDIR)$(BINDIR)
	cd $(PKGDIR) && $(TAR) -czvf ../$(COMPONENT)-$(VERSION).tar.gz .
	cp $(PKGDIR)../$(COMPONENT)-$(VERSION).tar.gz .
	make -C packages

changelog:
	$(call create_changelog)

doc:
	$(eval ODLFILES += odl/ssh_server.odl)
	$(eval ODLFILES += odl/ssh_server_definition.odl)
	$(eval ODLFILES += odl/ssh_server_storage-odl.odl)
	$(eval ODLFILES += odl/ssh_server_storage-uci.odl)
	$(eval ODLFILES += odl/ssh_server_defaults.odl)

	mkdir -p output/xml
	mkdir -p output/html
	amxo-cg -Gxml,output/xml/$(COMPONENT).xml $(or $(ODLFILES), "")
	amxo-xml-to -x html -o output-dir=output/html -o title="$(COMPONENT)" -o version=$(VERSION) -o sub-title="Datamodel reference" output/xml/*.xml

test:
	$(MAKE) -C test run
	$(MAKE) -C test coverage

.PHONY: all clean changelog install package doc test