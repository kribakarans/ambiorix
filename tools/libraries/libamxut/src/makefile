include ../makefile.inc

# build destination directories
OBJDIR = ../output/$(MACHINE)

# TARGETS
TARGET_SO = $(OBJDIR)/$(COMPONENT).so.$(VERSION)
TARGET_A = $(OBJDIR)/$(COMPONENT).a

# directories
# source directories
SRCDIR = .
INCDIR_PUB = ../include
INCDIR_PRIV = ../include_priv
INCDIRS = $(INCDIR_PUB) $(INCDIR_PRIV) $(if $(STAGINGDIR), $(STAGINGDIR)/include)
STAGING_LIBDIR = $(if $(STAGINGDIR), -L$(STAGINGDIR)/lib)

# files
HEADERS = $(wildcard $(INCDIR_PUB)/amxut/*.h)
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))
OBJECTS += $(addprefix $(OBJDIR)/,$(notdir $(VARIANTS:.c=.o)))

# compilation and linking flags
# -Werror=pedantic is removed because of the use of dlsym
# when added the following error occurs:
# error: ISO C forbids conversion of object pointer to function pointer type [-Werror=pedantic]
CFLAGS += -Werror -Wall -Wextra \
          -Wformat=2 -Wshadow \
          -Wwrite-strings -Wredundant-decls \
          -Wmissing-declarations \
          -Wno-format-nonliteral \
          -fPIC -g3 $(addprefix -I ,$(INCDIRS))

ifeq ($(CC_NAME),g++)
	CFLAGS += -std=c++2a
else
	CFLAGS += -Wstrict-prototypes -Wold-style-definition -Wnested-externs -std=c11
endif

LDFLAGS += $(STAGING_LIBDIR) -shared -fPIC \
           -lamxc -lamxp -lamxd -lamxo -lamxb -lsahtrace -lamxj -ldl

# targets
all: $(TARGET_SO) $(TARGET_A)

$(TARGET_SO): $(OBJECTS)
	$(CC) -Wl,-soname,$(COMPONENT).so.$(VMAJOR) -o $(@) $(OBJECTS) $(LDFLAGS)

$(TARGET_A): $(OBJECTS)
	$(AR) rcs $(@) $(OBJECTS)

-include $(OBJECTS:.o=.d)

$(OBJDIR)/%.o: $(SRCDIR)/variants/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/:
	$(MKDIR) -p $@

clean:
	rm -rf ../output/ ../$(COMPONENT)-*.* ../$(COMPONENT)_*.*

.PHONY: all clean
