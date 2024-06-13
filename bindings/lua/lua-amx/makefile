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
ifeq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/$(COMPONENT).so $(DEST)/usr/local/lib/lua/$(CONFIG_SAH_LUA_AMX_LUA_VERSION)/lamx.so
endif
ifneq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/$(COMPONENT).so $(DEST)/usr/local/lib/lua/$(LUA_DEFAULT_VERSION)/lamx.so
endif
ifeq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 scripts/lamx_wait_for.lua $(DEST)/usr/local/lib/lua/$(CONFIG_SAH_LUA_AMX_LUA_VERSION)/lamx_wait_for.lua
endif
ifneq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 scripts/lamx_wait_for.lua $(DEST)/usr/local/lib/lua/$(LUA_DEFAULT_VERSION)/lamx_wait_for.lua
endif
ifeq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 scripts/lamxb.lua $(DEST)/usr/local/lib/lua/$(CONFIG_SAH_LUA_AMX_LUA_VERSION)/lamxb.lua
endif
ifneq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 scripts/lamxb.lua $(DEST)/usr/local/lib/lua/$(LUA_DEFAULT_VERSION)/lamxb.lua
endif
ifeq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -d -m 0755 $(DEST)/usr/lib/lua
	ln -sfr $(DEST)/usr/local/lib/lua/$(CONFIG_SAH_LUA_AMX_LUA_VERSION)/lamx.so $(DEST)/usr/lib/lua/lamx.so
endif
ifneq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -d -m 0755 $(DEST)/usr/lib/lua
	ln -sfr $(DEST)/usr/local/lib/lua/$(LUA_DEFAULT_VERSION)/lamx.so $(DEST)/usr/lib/lua/lamx.so
endif
ifeq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -d -m 0755 $(DEST)/usr/lib/lua
	ln -sfr $(DEST)/usr/local/lib/lua/$(CONFIG_SAH_LUA_AMX_LUA_VERSION)/lamx_wait_for.lua $(DEST)/usr/lib/lua/lamx_wait_for.lua
endif
ifneq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -d -m 0755 $(DEST)/usr/lib/lua
	ln -sfr $(DEST)/usr/local/lib/lua/$(LUA_DEFAULT_VERSION)/lamx_wait_for.lua $(DEST)/usr/lib/lua/lamx_wait_for.lua
endif
	$(INSTALL) -D -p -m 0755 scripts/amx_monitor_dm.lua $(DEST)/usr/bin/amx_monitor_dm
	$(INSTALL) -D -p -m 0755 scripts/amx_wait_for.lua $(DEST)/usr/bin/amx_wait_for

package: all
ifeq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/$(COMPONENT).so $(PKGDIR)/usr/local/lib/lua/$(CONFIG_SAH_LUA_AMX_LUA_VERSION)/lamx.so
endif
ifneq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/$(COMPONENT).so $(PKGDIR)/usr/local/lib/lua/$(LUA_DEFAULT_VERSION)/lamx.so
endif
ifeq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 scripts/lamx_wait_for.lua $(PKGDIR)/usr/local/lib/lua/$(CONFIG_SAH_LUA_AMX_LUA_VERSION)/lamx_wait_for.lua
endif
ifneq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 scripts/lamx_wait_for.lua $(PKGDIR)/usr/local/lib/lua/$(LUA_DEFAULT_VERSION)/lamx_wait_for.lua
endif
ifeq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 scripts/lamxb.lua $(PKGDIR)/usr/local/lib/lua/$(CONFIG_SAH_LUA_AMX_LUA_VERSION)/lamxb.lua
endif
ifneq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -D -p -m 0644 scripts/lamxb.lua $(PKGDIR)/usr/local/lib/lua/$(LUA_DEFAULT_VERSION)/lamxb.lua
endif
ifeq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -d -m 0755 $(PKGDIR)/usr/lib/lua
	rm -f $(PKGDIR)/usr/lib/lua/lamx.so
	ln -sfr $(PKGDIR)/usr/local/lib/lua/$(CONFIG_SAH_LUA_AMX_LUA_VERSION)/lamx.so $(PKGDIR)/usr/lib/lua/lamx.so
endif
ifneq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -d -m 0755 $(PKGDIR)/usr/lib/lua
	rm -f $(PKGDIR)/usr/lib/lua/lamx.so
	ln -sfr $(PKGDIR)/usr/local/lib/lua/$(LUA_DEFAULT_VERSION)/lamx.so $(PKGDIR)/usr/lib/lua/lamx.so
endif
ifeq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -d -m 0755 $(PKGDIR)/usr/lib/lua
	rm -f $(PKGDIR)/usr/lib/lua/lamx_wait_for.lua
	ln -sfr $(PKGDIR)/usr/local/lib/lua/$(CONFIG_SAH_LUA_AMX_LUA_VERSION)/lamx_wait_for.lua $(PKGDIR)/usr/lib/lua/lamx_wait_for.lua
endif
ifneq ($(CONFIG_SAH_LUA_AMX_LUA_VERSION_OVERRIDE),y)
	$(INSTALL) -d -m 0755 $(PKGDIR)/usr/lib/lua
	rm -f $(PKGDIR)/usr/lib/lua/lamx_wait_for.lua
	ln -sfr $(PKGDIR)/usr/local/lib/lua/$(LUA_DEFAULT_VERSION)/lamx_wait_for.lua $(PKGDIR)/usr/lib/lua/lamx_wait_for.lua
endif
	$(INSTALL) -D -p -m 0755 scripts/amx_monitor_dm.lua $(PKGDIR)/usr/bin/amx_monitor_dm
	$(INSTALL) -D -p -m 0755 scripts/amx_wait_for.lua $(PKGDIR)/usr/bin/amx_wait_for
	cd $(PKGDIR) && $(TAR) -czvf ../$(COMPONENT)-$(VERSION).tar.gz .
	cp $(PKGDIR)../$(COMPONENT)-$(VERSION).tar.gz .
	make -C packages

changelog:
	$(call create_changelog)

doc:
	$(MAKE) -C doc doc


test:
	$(MAKE) -C test run
	$(MAKE) -C test coverage

.PHONY: all clean changelog install package doc test