include ../test_defines.mk

MOCK_SRC_DIR = ../mocks
MOCK_SOURCES = $(wildcard $(MOCK_SRC_DIR)/*.c)

TARGET = run_test
SOURCES += $(wildcard ./*.c) $(MOCK_SOURCES)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) 

WRAP_FUNC=-Wl,--wrap=
MOCK_WRAP = stat \
            amxp_dir_scan

LDFLAGS += -g $(addprefix $(WRAP_FUNC),$(MOCK_WRAP))

include ../test_targets.mk
