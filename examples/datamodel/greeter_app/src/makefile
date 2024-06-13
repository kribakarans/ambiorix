include ../makefile.inc

# TARGETS
TARGET = $(COMPONENT)-$(VERSION)

# Function to check directory existence
define dir_exists
$(if $(wildcard $(1)), $(1))
endef

# Directories
SRCDIR = .
INCDIR_PRIV = ../include_priv
STAGING_INCDIR = $(call dir_exists, $(STAGINGDIR)/usr/include) \
                 $(call dir_exists, $(STAGINGDIR)/include)
STAGING_LIBDIR = $(call dir_exists, $(STAGINGDIR)/lib) \
                 $(call dir_exists, $(STAGINGDIR)/usr/lib)
OBJDIR = ../output/$(MACHINE)

# Files
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))

# Compilation and linking flags
CFLAGS += -Werror -Wall -Wextra \
          -Wformat=2 -Wshadow -Wwrite-strings -Wredundant-decls \
          -Wmissing-include-dirs -Wno-unused-parameter -Wno-format-nonliteral \
          -g3 -Wmissing-declarations -pthread \
          $(addprefix -I,$(INCDIR_PRIV) $(STAGING_INCDIR))

ifeq ($(CC_NAME),g++)
    CFLAGS += -std=c++2a
else
    CFLAGS += -Wstrict-prototypes -Wold-style-definition -Wnested-externs -std=c11
endif

LDFLAGS += $(addprefix -L,$(STAGING_LIBDIR)) -levent_core -luriparser -lamxc -lamxp -lamxb -lamxd -lamxo -lamxj -lamxrt

# Targets
all: $(COMPONENT)

$(COMPONENT): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)/.dirstamp
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $<

$(OBJDIR)/.dirstamp:
	@mkdir -p $(OBJDIR)
	@touch $@

clean:
	rm -rf $(OBJDIR) $(COMPONENT)
	$(MAKE) -C ../test clean
	find .. -name "run_test" -delete

.PHONY: all clean

# Include dependency files
-include $(OBJECTS:.o=.d)