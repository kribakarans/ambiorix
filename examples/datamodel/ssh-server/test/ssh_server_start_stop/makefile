include ../test_defines.mk

TARGET = run_test
SOURCES += $(wildcard ./*.c)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) 

WRAP_FUNC=-Wl,--wrap=
MOCK_WRAP = amxp_proc_ctrl_new \
            amxp_proc_ctrl_start \
            amxp_proc_ctrl_stop \
            amxp_proc_ctrl_delete 

LDFLAGS += -g $(addprefix $(WRAP_FUNC),$(MOCK_WRAP))

include ../test_targets.mk
