MACHINE = $(shell $(CC) -dumpmachine)

SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../include)

HEADERS = $(wildcard $(INCDIR)/*.h)
SOURCES = $(SRCDIR)/config.c $(SRCDIR)/parse_args.c $(wildcard $(SRCDIR)/to_*.c) $(SRCDIR)/utils.c


CFLAGS += -DUNIT_TEST -Werror -Wall -Wextra -Wno-attributes\
          --std=gnu99 -g3 -Wmissing-declarations \
		  $(addprefix -I ,$(INCDIR)) -I$(OBJDIR)/.. \
		  -fkeep-inline-functions -fkeep-static-functions \
		  -Wno-format-nonliteral \
		  $(shell pkg-config --cflags libxslt libexslt) \
		  $(shell pkg-config --cflags cmocka) -pthread

LDFLAGS += -fkeep-inline-functions -fkeep-static-functions \
		   $(shell pkg-config --libs cmocka) -lamxc -lamxj \
		   $(shell pkg-config --libs libxslt libexslt)