include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))

LDFLAGS += -g -Wl,--wrap=read \
              -Wl,--wrap=write \
			  -Wl,--wrap=isatty \
			  -Wl,--wrap=ttyname_r \
			  -Wl,--wrap=open 

include ../test_targets.mk
