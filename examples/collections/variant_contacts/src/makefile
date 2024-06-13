include ../makefile.inc

# TARGETS
TARGET = $(COMPONENT)-$(VERSION)

# directories
# source directories
SRCDIR = .
INCDIR_PRIV = ../include_priv
INCDIRS = $(INCDIR_PRIV)

# build destination directories
OBJDIR = ../output/$(MACHINE)

# files
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))
		
# compilation and linking flags
CFLAGS += -Werror -Wall -Wextra \
          -Wformat=2 -Wno-unused-parameter -Wshadow \
          -Wwrite-strings -Wredundant-decls -Wmissing-include-dirs \
          -Wno-format-nonliteral \
          -g3 -Wmissing-declarations $(addprefix -I ,$(INCDIRS)) \
          -pthread

ifeq ($(CC_NAME),g++)
    CFLAGS += -std=c++2a
else
	CFLAGS += -Wstrict-prototypes -Wold-style-definition -Wnested-externs -std=c11
endif

LDFLAGS += -lamxc

# targets
all: $(COMPONENT)

$(COMPONENT): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

-include $(OBJECTS:.o=.d)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/:
	$(MKDIR) -p $@

clean:
	rm -rf ../output/ $(COMPONENT)
	make -C ../test clean

.PHONY: all clean
