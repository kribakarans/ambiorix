include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c) $(wildcard $(MOCK_SRCDIR)/*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))

LDFLAGS += -lamxo

include ../test_targets.mk
