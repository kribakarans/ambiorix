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
	$(INSTALL) -d -m 0755 $(DEST)/$(INCLUDEDIR)/amxb_be_dummy
	$(INSTALL) -D -p -m 0644 include/amxb_be_dummy/*.h $(DEST)$(INCLUDEDIR)/amxb_be_dummy/
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/$(COMPONENT).so $(DEST)/usr/bin/mods/amxb/$(COMPONENT).so
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/$(COMPONENT).so $(DEST)$(LIBDIR)/libamxb_dummy.so.$(VERSION)
	ln -sfr $(DEST)$(LIBDIR)/libamxb_dummy.so.$(VERSION) $(DEST)$(LIBDIR)/libamxb_dummy.so.$(VMAJOR)
	ln -sfr $(DEST)$(LIBDIR)/libamxb_dummy.so.$(VERSION) $(DEST)$(LIBDIR)/libamxb_dummy.so

package: all
	$(INSTALL) -d -m 0755 $(PKGDIR)/$(INCLUDEDIR)/amxb_be_dummy
	$(INSTALL) -D -p -m 0644 include/amxb_be_dummy/*.h $(PKGDIR)$(INCLUDEDIR)/amxb_be_dummy/
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/$(COMPONENT).so $(PKGDIR)/usr/bin/mods/amxb/$(COMPONENT).so
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/$(COMPONENT).so $(PKGDIR)$(LIBDIR)/libamxb_dummy.so.$(VERSION)
	cd $(PKGDIR) && $(TAR) -czvf ../$(COMPONENT)-$(VERSION).tar.gz .
	cp $(PKGDIR)../$(COMPONENT)-$(VERSION).tar.gz .
	make -C packages

changelog:
	$(call create_changelog)

test:
	$(MAKE) -C test run
	$(MAKE) -C test coverage

.PHONY: all clean changelog install package test