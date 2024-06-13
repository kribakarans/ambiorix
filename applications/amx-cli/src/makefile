include ../makefile.inc

# TARGETS
TARGET = $(TARGET_NAME)-$(VERSION)

# directories
# source directories
SRCDIR = .
INCDIR_PRIV = ../include_priv
INCDIRS = $(INCDIR_PRIV) $(if $(STAGINGDIR), $(STAGINGDIR)/include) $(if $(STAGINGDIR), $(STAGINGDIR)/usr/include)
LDFLAGS_EXTRA = -L$(STAGINGDIR)/lib -L$(STAGINGDIR)/usr/lib
STAGING_LIBDIR = $(if $(STAGINGDIR), $(LDFLAGS_EXTRA))

# build destination directories
OBJDIR = ../output/$(MACHINE)

# files
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))
		
# compilation and linking flags
CFLAGS += -Werror -Wall -Wextra \
          -Wformat=2 -Wno-unused-parameter -Wshadow \
          -Wwrite-strings -Wredundant-decls \
          -Wno-format-nonliteral \
          -g3 -Wmissing-declarations $(addprefix -I ,$(INCDIRS)) \
          -pthread

ifeq ($(CC_NAME),g++)
    CFLAGS += -std=c++2a
else
	CFLAGS += -Wstrict-prototypes -Wold-style-definition -Wnested-externs -std=c11
endif

LDFLAGS += $(STAGING_LIBDIR) -pthread \
  		   $(shell pkg-config --libs libevent) \
           -lyajl -lamxc -lamxj -lamxp -lamxt -lamxm -lm

# targets
all: ../include_priv/version.h $(COMPONENT)

$(COMPONENT): ../include_priv/version.h $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

-include $(OBJECTS:.o=.d)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

../include_priv/version.h: ../include_priv/version.h.m4
	@echo "Current version = $(VMAJOR).$(VMINOR).$(VBUILD)"
	m4 -DMAJOR=$(VMAJOR) -DMINOR=$(VMINOR) -DBUILD=$(VBUILD) $(<) > $(@)

$(OBJDIR)/:
	$(MKDIR) -p $@

clean:
	rm -rf ../output/ ../$(COMPONENT)-*.* ../$(COMPONENT)_*.* ../include_priv/version.h

.PHONY: all clean
