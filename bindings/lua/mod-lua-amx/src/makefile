include ../makefile.inc
-include $(STAGINGDIR)/components.config

# build destination directories
OUTPUTDIR = ../output/$(MACHINE)
OBJDIR = $(OUTPUTDIR)/object

# TARGETS
TARGET_SO = $(OBJDIR)/$(COMPONENT).so

# directories
# source directories
SRCDIR = .
INCDIR_PRIV = ../include_priv
INCDIRS = $(INCDIR_PRIV) $(if $(STAGINGDIR), $(STAGINGDIR)/include) $(if $(STAGINGDIR), $(STAGINGDIR)/usr/include)
STAGING_LIBDIR = $(if $(STAGINGDIR), -L$(STAGINGDIR)/lib) $(if $(STAGINGDIR), -L$(STAGINGDIR)/usr/lib)

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))

# compilation and linking flags
CFLAGS += -Werror -Wall -Wextra \
          -Wformat=2 -Wshadow \
          -Wwrite-strings -Wredundant-decls \
		  -Wmissing-declarations -Wno-attributes \
		  -Wno-format-nonliteral \
		  -fPIC -g3 $(addprefix -I ,$(INCDIRS))

ifdef CONFIG_SAH_LUA_AMX_LUA_VERSION
	CFLAGS += -DLUA_VERSION_$(subst .,_,$(CONFIG_SAH_LUA_AMX_LUA_VERSION))
else
	CFLAGS += -DLUA_VERSION_$(subst .,_,$(LUA_DEFAULT_VERSION))
endif

ifeq ($(CC_NAME),g++)
    CFLAGS += -std=c++2a
else
	CFLAGS += -Wstrict-prototypes -Wold-style-definition -Wnested-externs -std=c11
endif

LDFLAGS += -shared -fPIC $(STAGING_LIBDIR) \
           -lamxc -lamxp -lamxd -lamxo

ifdef CONFIG_SAH_LUA_AMX_LUA_VERSION
ifeq ("$(wildcard $(STAGINGDIR)/usr/include/liblua.so.$(CONFIG_SAH_LUA_AMX_LUA_VERSION))","")
	LDFLAGS += -llua
else
	LDFLAGS += -llua$(CONFIG_SAH_LUA_AMX_LUA_VERSION)
endif
else
ifeq ("$(wildcard $(STAGINGDIR)/usr/include/liblua.so.$(LUA_DEFAULT_VERSION))","")
	LDFLAGS += -llua
else
	LDFLAGS += -llua$(LUA_DEFAULT_VERSION)
endif
endif

# targets
all: $(TARGET_SO)

$(TARGET_SO): $(OBJECTS)
	$(CC) -Wl,-soname,$(COMPONENT).so -o $@ $(OBJECTS) $(LDFLAGS)

-include $(OBJECTS:.o=.d)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/:
	$(MKDIR) -p $@

clean:
	rm -rf ../output/ ../$(COMPONENT)-*.* ../$(COMPONENT)_*.*

.PHONY: all clean
