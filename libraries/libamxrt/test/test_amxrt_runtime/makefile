include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) 

LDFLAGS += -g \
           -Wl,--wrap=amxb_be_load_multiple \
		   -Wl,--wrap=amxb_connect \
		   -Wl,--wrap=amxb_listen \
		   -Wl,--wrap=amxb_get_fd \
		   -Wl,--wrap=amxb_free \
		   -Wl,--wrap=amxb_register \
		   -Wl,--wrap=amxb_read \
		   -Wl,--wrap=amxb_wait_for_object \
		   -Wl,--wrap=setpriority \
		   -Wl,--wrap=daemon

include ../test_targets.mk
