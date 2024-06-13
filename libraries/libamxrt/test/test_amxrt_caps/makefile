include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) 

LDFLAGS += -g \
		   -Wl,--wrap=capng_get_caps_process \
		   -Wl,--wrap=capng_clear \
		   -Wl,--wrap=capng_update \
		   -Wl,--wrap=capng_apply \
		   -Wl,--wrap=capng_change_id \
		   -Wl,--wrap=getpwnam \
		   -Wl,--wrap=getgrnam

include ../test_targets.mk
