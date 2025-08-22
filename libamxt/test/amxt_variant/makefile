include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))

LDFLAGS += -g -Wl,--wrap=isatty \
			  -Wl,--wrap=ttyname_r \
			  -Wl,--wrap=open 

include ../test_targets.mk
