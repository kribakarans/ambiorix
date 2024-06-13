include ../test_defines.mk

MOCK_SRC_DIR = ../mocks
MOCK_SOURCES = $(wildcard $(MOCK_SRC_DIR)/*.c)

TARGET = run_test
SOURCES += $(wildcard ./*.c) $(MOCK_SOURCES)
OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SOURCES:.c=.o)))

LDFLAGS_TMP := $(LDFLAGS)

LDFLAGS = $(subst amx_fcgi_is_request_authorized,,$(LDFLAGS_TMP))

include ../test_targets.mk
