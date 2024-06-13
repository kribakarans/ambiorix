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
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/$(COMPONENT).so $(DEST)/usr/lib/amx/amx-cli/$(COMPONENT).so
	$(INSTALL) -D -p -m 0644 config/ba-cli.init $(DEST)/etc/amx/cli/ba-cli.init
	$(INSTALL) -D -p -m 0644 config/ba-cli.conf $(DEST)/etc/amx/cli/ba-cli.conf
	$(INSTALL) -d -m 0755 $(DEST)$(BINDIR)
	ln -sfr $(DEST)$(BINDIR)/amx-cli $(DEST)$(BINDIR)/ba-cli
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_UBUS_CLI),y)
	$(INSTALL) -D -p -m 0644 config/ubus-cli.init $(DEST)/etc/amx/cli/ubus-cli.init
endif
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_UBUS_CLI),y)
	$(INSTALL) -D -p -m 0644 config/ubus-cli.conf $(DEST)/etc/amx/cli/ubus-cli.conf
endif
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_UBUS_CLI),y)
	$(INSTALL) -d -m 0755 $(DEST)$(BINDIR)
	ln -sfr $(DEST)$(BINDIR)/amx-cli $(DEST)$(BINDIR)/ubus-cli
endif
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_PCB_CLI),y)
	$(INSTALL) -D -p -m 0644 config/pcb-cli.init $(DEST)/etc/amx/cli/pcb-cli.init
endif
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_PCB_CLI),y)
	$(INSTALL) -D -p -m 0644 config/pcb-cli.conf $(DEST)/etc/amx/cli/pcb-cli.conf
endif
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_PCB_CLI),y)
	$(INSTALL) -d -m 0755 $(DEST)$(BINDIR)
	ln -sfr $(DEST)$(BINDIR)/amx-cli $(DEST)$(BINDIR)/pcb-cli
endif

package: all
	$(INSTALL) -D -p -m 0644 output/$(MACHINE)/$(COMPONENT).so $(PKGDIR)/usr/lib/amx/amx-cli/$(COMPONENT).so
	$(INSTALL) -D -p -m 0644 config/ba-cli.init $(PKGDIR)/etc/amx/cli/ba-cli.init
	$(INSTALL) -D -p -m 0644 config/ba-cli.conf $(PKGDIR)/etc/amx/cli/ba-cli.conf
	$(INSTALL) -d -m 0755 $(PKGDIR)$(BINDIR)
	rm -f $(PKGDIR)$(BINDIR)/ba-cli
	ln -sfr $(PKGDIR)$(BINDIR)/amx-cli $(PKGDIR)$(BINDIR)/ba-cli
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_UBUS_CLI),y)
	$(INSTALL) -D -p -m 0644 config/ubus-cli.init $(PKGDIR)/etc/amx/cli/ubus-cli.init
endif
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_UBUS_CLI),y)
	$(INSTALL) -D -p -m 0644 config/ubus-cli.conf $(PKGDIR)/etc/amx/cli/ubus-cli.conf
endif
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_UBUS_CLI),y)
	$(INSTALL) -d -m 0755 $(PKGDIR)$(BINDIR)
	rm -f $(PKGDIR)$(BINDIR)/ubus-cli
	ln -sfr $(PKGDIR)$(BINDIR)/amx-cli $(PKGDIR)$(BINDIR)/ubus-cli
endif
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_PCB_CLI),y)
	$(INSTALL) -D -p -m 0644 config/pcb-cli.init $(PKGDIR)/etc/amx/cli/pcb-cli.init
endif
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_PCB_CLI),y)
	$(INSTALL) -D -p -m 0644 config/pcb-cli.conf $(PKGDIR)/etc/amx/cli/pcb-cli.conf
endif
ifeq ($(CONFIG_SAH_MOD_BA_CLI_INSTALL_PCB_CLI),y)
	$(INSTALL) -d -m 0755 $(PKGDIR)$(BINDIR)
	rm -f $(PKGDIR)$(BINDIR)/pcb-cli
	ln -sfr $(PKGDIR)$(BINDIR)/amx-cli $(PKGDIR)$(BINDIR)/pcb-cli
endif
	cd $(PKGDIR) && $(TAR) -czvf ../$(COMPONENT)-$(VERSION).tar.gz .
	cp $(PKGDIR)../$(COMPONENT)-$(VERSION).tar.gz .
	make -C packages

changelog:
	$(call create_changelog)

test:
	$(MAKE) -C test run
	$(MAKE) -C test coverage

.PHONY: all clean changelog install package test