-include $(STAGINGDIR)/components.config
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
INCDIRS = $(INCDIR_PUB) $(INCDIR_PRIV) $(if $(STAGINGDIR), $(STAGINGDIR)/include) $(if $(STAGINGDIR), $(STAGINGDIR)/usr/include)
STAGING_LIBDIR = $(if $(STAGINGDIR), -L$(STAGINGDIR)/lib) $(if $(STAGINGDIR), -L$(STAGINGDIR)/usr/lib)

# files
HEADERS = $(wildcard $(INCDIR_PUB)/amxrt/*.h)
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))
OBJECTS += $(addprefix $(OBJDIR)/,$(notdir $(VARIANTS:.c=.o)))
		
# compilation and linking flags
CFLAGS += -Wall -Wextra \
          -Wformat=2 -Wshadow \
		  -Wno-format-nonliteral \
          -Wwrite-strings -Wredundant-decls \
		  -Wpedantic -Wmissing-declarations \
          -fPIC -g3 $(addprefix -I ,$(INCDIRS))

ifdef CONFIG_SAH_AMXRT_RWDATAPATH
    CFLAGS += -DRWDATAPATH=\"$(CONFIG_SAH_AMXRT_RWDATAPATH)\"
else
    CFLAGS += -DRWDATAPATH=\"/etc/config\"
endif

ifeq ($(CC_NAME),g++)
    CFLAGS += -std=c++2a
else
	CFLAGS += -Wstrict-prototypes \
	          -Wold-style-definition \
			  -Wnested-externs \
    		  -Wdeclaration-after-statement \
			  -std=c11
endif

LDFLAGS += $(STAGING_LIBDIR) -shared -fPIC \
   		   $(shell pkg-config --libs libevent) \
           -lamxc -lamxp -lamxd -lamxo -lamxb -lamxj -lcap-ng

# targets
all: $(TARGET_SO) $(TARGET_A)

$(TARGET_SO): $(OBJECTS)
	$(CC) -Wl,-soname,$(COMPONENT).so.$(VMAJOR) -o $@ $(OBJECTS) $(LDFLAGS)

$(TARGET_A): $(OBJECTS)
	$(AR) rcs $(@) $(OBJECTS)

-include $(OBJECTS:.o=.d)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/:
	$(MKDIR) -p $@

clean:
	rm -rf ../output/ ../$(COMPONENT)-*.* ../$(COMPONENT)_*.*
	find . -name "run_test" -delete


.PHONY: all clean
