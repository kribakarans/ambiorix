include ../test_defines.mk

TARGET = run_test
COMMON_TEST_SRCDIR = $(realpath ../threshold_event_common)
SOURCES += $(wildcard ./*.c) $(wildcard $(COMMON_TEST_SRCDIR)/*.c) 
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) 

include ../test_targets.mk
