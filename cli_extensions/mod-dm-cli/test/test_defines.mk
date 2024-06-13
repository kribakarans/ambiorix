MACHINE = $(shell $(CC) -dumpmachine)

SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include_priv)

HEADERS = $(wildcard $(INCDIR)/$(TARGET)/*.h)
SOURCES = $(wildcard $(SRCDIR)/mod_*.c)

CFLAGS += -Werror -Wall -Wextra -Wno-attributes\
          --std=gnu99 -g3 -Wmissing-declarations \
		  $(addprefix -I ,$(INCDIR)) -I$(OBJDIR)/.. -I../mocks \
		  -fkeep-inline-functions -fkeep-static-functions -Wno-format-nonliteral

LDFLAGS += -fkeep-inline-functions -fkeep-static-functions -g \
		   $(shell pkg-config --libs cmocka) -lamxc -lamxt -lamxm -lamxp -lamxd -lamxb -lamxo

LDFLAGS += -g $(addprefix $(WRAP_FUNC),$(MOCK_WRAP))

