include ../makefile.inc

# TARGETS
TARGET = $(COMPONENT)-$(VERSION)

# directories
# source directories
SRCDIR = .
INCDIR_PRIV = ../include_priv
INCDIRS = $(INCDIR_PRIV) $(if $(STAGINGDIR), $(STAGINGDIR)/include) $(if $(STAGINGDIR), $(STAGINGDIR)/usr/include)
STAGING_LIBDIR = $(if $(STAGINGDIR), -L$(STAGINGDIR)/lib) $(if $(STAGINGDIR), -L$(STAGINGDIR)/usr/lib)

# build destination directories
OBJDIR = ../output/$(MACHINE)

# files
SOURCES_CG = $(wildcard $(SRCDIR)/*.c)
SOURCES_XML = $(wildcard $(SRCDIR)/xml/*.c)
SOURCES_DMM = $(wildcard $(SRCDIR)/dmm/*.c)

SOURCES = $(SOURCES_CG) $(SOURCES_XML) $(SOURCES_DMM)

OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))
		
# compilation and linking flags
CFLAGS += -Werror -Wall -Wextra \
          -Wformat=2 -Wshadow \
          -Wwrite-strings -Wredundant-decls \
		  -Wno-format-nonliteral  -Wno-format-nonliteral \
		  -Wno-error=deprecated-declarations \
          -g3 -Wmissing-declarations $(addprefix -I ,$(INCDIRS)) \
		  -pthread \
		  $(shell pkg-config --cflags libxml-2.0)

ifeq ($(CC_NAME),g++)
    CFLAGS += -std=c++2a
else
	CFLAGS += -Wstrict-prototypes -Wold-style-definition -Wnested-externs -std=gnu11 
endif

LDFLAGS += $(shell pkg-config --libs libxml-2.0) $(STAGING_LIBDIR) -lyajl -lamxc -lamxj -lamxp -lamxd -lamxo

# targets
all: ../include_priv/version.h $(COMPONENT)

$(COMPONENT):  ../include_priv/version.h $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

-include $(OBJECTS:.o=.d)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/%.o: $(SRCDIR)/xml/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/%.o: $(SRCDIR)/dmm/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)


../include_priv/version.h : ../include_priv/version.h.m4
	@echo "Current version = $(VMAJOR).$(VMINOR).$(VBUILD)"
	m4 -DMAJOR=$(VMAJOR) -DMINOR=$(VMINOR) -DBUILD=$(VBUILD) $(<) > $(@)

$(OBJDIR)/:
	$(MKDIR) -p $@

clean:
	rm -rf ../output/ $(COMPONENT) include_priv/version.h

.PHONY: clean all
