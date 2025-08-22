include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) 

LDFLAGS += -g \
		   -Wl,--wrap=event_base_new \
		   -Wl,--wrap=event_base_dispatch \
		   -Wl,--wrap=event_new \
		   -Wl,--wrap=event_add

include ../test_targets.mk
