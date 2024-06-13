MACHINE = $(shell $(CC) -dumpmachine)

MOCK_SRCDIR = $(realpath ../mock)
SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../include ../mock)

HEADERS = $(wildcard $(INCDIR)/amxb/*.h)
SOURCES = $(wildcard $(SRCDIR)/*.c)

CFLAGS += -Werror -Wall -Wextra \
          --std=gnu99 -g3 -Wmissing-declarations \
		  $(addprefix -I ,$(INCDIR)) \
		  -fprofile-arcs -ftest-coverage \
		  -fkeep-inline-functions -fkeep-static-functions \
		  -Wno-format-nonliteral \
		  $(shell pkg-config --cflags cmocka) \
		  -fPIC
LDFLAGS += -fprofile-arcs -ftest-coverage \
           -fkeep-inline-functions -fkeep-static-functions \
		   $(shell pkg-config --libs cmocka) -lamxc -lamxp -lamxd -lamxo -luriparser -ldl
