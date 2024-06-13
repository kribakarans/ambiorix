MACHINE = $(shell $(CC) -dumpmachine)

SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../include)

HEADERS = $(wildcard $(INCDIR)/amxp/*.h)
SOURCES = $(wildcard $(SRCDIR)/amxp_*.c) \
		  $(wildcard $(SRCDIR)/variant_*.c)

CFLAGS += -Werror -Wall -Wextra \
          --std=gnu99 -g3 -Wmissing-declarations -Wno-format-nonliteral \
		  $(addprefix -I ,$(INCDIR))  -I$(OBJDIR)/.. \
		  -fkeep-inline-functions -fkeep-static-functions \
		  $(shell pkg-config --cflags cmocka) -pthread
LDFLAGS += -fkeep-inline-functions -fkeep-static-functions \
		   $(shell pkg-config --libs cmocka) -lamxc -lpthread