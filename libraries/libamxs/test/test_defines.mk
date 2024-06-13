MACHINE = $(shell $(CC) -dumpmachine)

MOCK_SRCDIR = $(realpath ../mock)
SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../include ../mock)

HEADERS = $(wildcard $(INCDIR)/amxs/*.h)
SOURCES = $(wildcard $(SRCDIR)/amxs_*.c)\
		  $(wildcard $(MOCK_SRCDIR)/*.c)

CFLAGS += -Werror -Wall -Wextra -Wno-attributes \
          --std=gnu99 -g3 -Wmissing-declarations \
		  $(addprefix -I ,$(INCDIR)) \
		  -fprofile-arcs -ftest-coverage \
		  -fkeep-inline-functions -fkeep-static-functions \
		   -Wno-format-nonliteral \
		  $(shell pkg-config --cflags cmocka)
LDFLAGS += -fprofile-arcs -ftest-coverage \
           -fkeep-inline-functions -fkeep-static-functions \
		   $(shell pkg-config --libs cmocka) -lamxc -lamxp -lamxb -lamxd -lamxo
