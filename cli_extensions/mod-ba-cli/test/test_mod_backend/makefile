MOCK_WRAP = read \
			write \
			amxt_tty_open \
			amxt_tty_close

WRAP_FUNC=-Wl,--wrap=

include ../test_defines.mk

MOCK_SRC_DIR = ../mocks
MOCK_SOURCES = $(wildcard $(MOCK_SRC_DIR)/*.c)

TARGET = run_test
SOURCES += $(wildcard ./*.c) $(MOCK_SOURCES)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o))) 

include ../test_targets.mk
