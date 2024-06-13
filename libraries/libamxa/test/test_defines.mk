MACHINE = $(shell $(CC) -dumpmachine)

SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../test_amxa_common ../mocks)

HEADERS = $(wildcard $(INCDIR)/$(TARGET)/*.h)
SOURCES = $(wildcard $(SRCDIR)/*.c)

CFLAGS += -Werror -Wall -Wextra -Wno-attributes\
          --std=gnu99 -g3 -Wmissing-declarations \
		  $(addprefix -I ,$(INCDIR)) -I$(OBJDIR)/.. \
		  -fkeep-inline-functions -fkeep-static-functions -Wno-format-nonliteral \
		  $(shell pkg-config --cflags cmocka)

LDFLAGS += -fkeep-inline-functions -fkeep-static-functions \
		   $(shell pkg-config --libs cmocka) -lamxc -lamxj -lyajl -lamxp -lamxd -lamxb -lamxo
