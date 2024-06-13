include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) \
          $(OBJDIR)/../amxp_expr.tab.o \
		  $(OBJDIR)/../lex.amxp_expr.o

LDFLAGS += -g -Wl,--wrap=signalfd

include ../test_targets.mk
