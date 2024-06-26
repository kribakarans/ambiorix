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
	$(INSTALL) -d -m 0755 $(DEST)//etc/amx/cpu_info
	$(foreach odl,$(wildcard odl/*.odl), $(INSTALL) -D -p -m 0644 $(odl) $(DEST)/etc/amx/cpu_info/;)
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/object/cpu_info.so $(DEST)/usr/lib/amx/cpu_info/cpu_info.so
	$(INSTALL) -d -m 0755 $(DEST)$(BINDIR)
	ln -sfr $(DEST)$(BINDIR)/amxrt $(DEST)$(BINDIR)/cpu_info

package: all
	$(INSTALL) -d -m 0755 $(PKGDIR)//etc/amx/cpu_info
	$(INSTALL) -D -p -m 0644 odl/*.odl $(PKGDIR)/etc/amx/cpu_info/
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/object/cpu_info.so $(PKGDIR)/usr/lib/amx/cpu_info/cpu_info.so
	$(INSTALL) -d -m 0755 $(PKGDIR)$(BINDIR)
	ln -sfr $(PKGDIR)$(BINDIR)/amxrt $(PKGDIR)$(BINDIR)/cpu_info
	cd $(PKGDIR) && $(TAR) -czvf ../$(COMPONENT)-$(VERSION).tar.gz .
	cp $(PKGDIR)../$(COMPONENT)-$(VERSION).tar.gz .
	make -C packages

changelog:
	$(call create_changelog)

doc:
	# expand/substitute source wildcard instead of using destination directory: the destination directory can contain files from another artifact not intended for pcb_docgen use
	$(eval ODLFILES += $(wildcard odl/*.odl))

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