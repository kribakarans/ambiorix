include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))

LDFLAGS += -g -Wl,--wrap=dlopen -Wl,--wrap=dlclose -Wl,--wrap=dlsym 

include ../test_targets.mk
