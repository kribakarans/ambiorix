include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) 

LDFLAGS += -g \
           -Wl,--wrap=amxrt_connect \

include ../test_targets.mk
