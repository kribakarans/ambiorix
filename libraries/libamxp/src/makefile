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
HEADERS = $(wildcard $(INCDIR_PUB)/amxp/*.h)
SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))
OBJECTS += $(OBJDIR)/lex.amxp_expr.o \
           $(OBJDIR)/amxp_expr.tab.o \

FLEX_BISON = $(OBJDIR)/lex.amxp_expr.c \
             $(OBJDIR)/amxp_expr.tab.c

# compilation and linking flags
CFLAGS += -Werror -Wall -Wextra \
          -Wformat=2 -Wno-unused-parameter -Wshadow \
          -Wwrite-strings  -Wredundant-decls \
		  -Wpedantic -Wno-format-nonliteral \
          -fPIC -g3 -Wmissing-declarations  \
		  $(addprefix -I ,$(INCDIRS)) -I$(OBJDIR) \
		  -pthread

ifeq ($(CC_NAME),g++)
    CFLAGS += -std=c++2a
else
	CFLAGS += -Wstrict-prototypes \
	          -Wold-style-definition \
			  -Wnested-externs \
     		  -Wdeclaration-after-statement \
			  -std=c11
endif

LDFLAGS += $(STAGING_LIBDIR) -pthread -shared -fPIC -Wl,--version-script=libamxp.version -lamxc -lpthread

# targets
all: $(TARGET_SO) $(TARGET_A)

$(TARGET_SO): $(FLEX_BISON) $(OBJECTS)
	$(CC) -Wl,-soname,$(COMPONENT).so.$(VMAJOR) -o $@ $(OBJECTS) $(LDFLAGS)

$(TARGET_A): $(FLEX_BISON) $(OBJECTS)
	$(AR) rcs $(@) $(OBJECTS)

-include $(OBJECTS:.o=.d)

$(OBJDIR)/amxp_expr.tab.c: $(SRCDIR)/amxp_expression.y | $(OBJDIR)/
	bison -d --verbose -o $@ $<

$(OBJDIR)/amxp_expr.tab.h: $(OBJDIR)/amxp_expr.tab.c

$(OBJDIR)/lex.amxp_expr.c: $(SRCDIR)/amxp_expression.l $(OBJDIR)/amxp_expr.tab.h | $(OBJDIR)/
	flex --header-file=$(OBJDIR)/amxp_expr_flex.h -o $@ $<

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(OBJDIR)/amxp_expr.tab.h | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/:
	$(MKDIR) -p $@

clean:
	rm -rf ../output/ ../$(COMPONENT)-*.* ../$(COMPONENT)_*.*

.PHONY: all clean
