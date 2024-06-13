include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) \
          $(OBJDIR)/../amxp_expr.tab.o \
		  $(OBJDIR)/../lex.amxp_expr.o

WRAP_FUNC=-Wl,--wrap=
MOCK_WRAP = kill \
            fopen \
            getline \
            amxc_var_init

LDFLAGS += -g $(addprefix $(WRAP_FUNC),$(MOCK_WRAP))
		   
include ../test_targets.mk
