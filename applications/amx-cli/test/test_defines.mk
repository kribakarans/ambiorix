MACHINE = $(shell $(CC) -dumpmachine)

SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../include)

HEADERS = $(wildcard $(INCDIR)/$(TARGET)/*.h)
SOURCES = $(wildcard $(SRCDIR)/amx_cli_*.c)

CFLAGS += -Werror -Wall -Wextra -Wno-attributes\
          --std=gnu99 -g3 -Wmissing-declarations \
		  $(addprefix -I ,$(INCDIR)) -I$(OBJDIR)/.. -I../mocks \
		  -fkeep-inline-functions -fkeep-static-functions -Wno-format-nonliteral \
		  $(shell pkg-config --cflags cmocka) -I/usr/local/include/mosquitto_poc/ -pthread

LDFLAGS += -fkeep-inline-functions -fkeep-static-functions -g \
		   $(shell pkg-config --libs cmocka) \
		   $(shell pkg-config --libs libevent) \
		   -lamxc -lamxj -lamxt -lamxm -lamxp

LDFLAGS += -g $(addprefix $(WRAP_FUNC),$(MOCK_WRAP))

