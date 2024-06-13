 include ../../makefile.inc

# build destination directories
OUTPUTDIR = ../../output/$(MACHINE)
OBJDIR = $(OUTPUTDIR)/object

# TARGETS
TARGET_SO = $(OUTPUTDIR)/mod-session-httpaccess.so

# directories
# source directories
SRCDIR = .
INCDIR_PRIV = ../include_priv
INCDIRS = $(INCDIR_PRIV)  $(if $(STAGINGDIR), $(STAGINGDIR)/include) $(if $(STAGINGDIR), $(STAGINGDIR)/usr/include)
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

ifeq ($(CC_NAME),g++)
    CFLAGS += -std=c++2a
else
	CFLAGS += -Wstrict-prototypes -Wold-style-definition -Wnested-externs -std=gnu11
endif

LDFLAGS += -shared -fPIC \
           -lamxc -lamxp -lamxm -lamxb -lamxa

# targets
all: $(TARGET_SO)

$(TARGET_SO): $(OBJECTS)
	$(CC) -Wl,-soname,mod-session-httpaccess -o $@ $(OBJECTS) $(LDFLAGS)

-include $(OBJECTS:.o=.d)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/:
	$(MKDIR) -p $@

.PHONY: all
