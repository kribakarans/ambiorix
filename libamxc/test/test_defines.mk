MACHINE = $(shell $(CC) -dumpmachine)

SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../include)

HEADERS = $(wildcard $(INCDIR)/amxc/*.h)
SOURCES = $(wildcard $(SRCDIR)/amxc_*.c) \
		  $(wildcard $(SRCDIR)/variants/*.c) \
		  $(wildcard ../common/*.c) \

CFLAGS += -Werror -Wall -Wextra \
          --std=gnu99 -g3 -Wmissing-declarations -Wno-implicit-fallthrough \
		  -Wno-format-nonliteral \
		  $(addprefix -I ,$(INCDIR)) \
		  -fkeep-inline-functions -fkeep-static-functions \
		  $(shell pkg-config --cflags cmocka)
LDFLAGS += -fkeep-inline-functions -fkeep-static-functions \
		   $(shell pkg-config --libs cmocka)
