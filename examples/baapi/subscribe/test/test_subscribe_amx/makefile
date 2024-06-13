include ../test_defines.mk

TARGET = run_test
COMMON_TEST_SRCDIR = $(realpath ../common_test_funcs)
SOURCES += $(wildcard ./*.c) $(wildcard $(COMMON_TEST_SRCDIR)/*.c) 
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) 

LDFLAGS += -g \
           -Wl,--wrap=amxrt_connect \
		   -Wl,--wrap=amxb_wait_for_object \
		   -Wl,--wrap=amxb_subscribe \
		   -Wl,--wrap=amxb_be_who_has
		   
include ../test_targets.mk
