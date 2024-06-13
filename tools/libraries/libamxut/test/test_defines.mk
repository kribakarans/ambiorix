MACHINE = $(shell $(CC) -dumpmachine)

SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../include)

HEADERS = $(wildcard $(INCDIR)/amxut/*.h)
SOURCES = $(wildcard $(SRCDIR)/amxut_*.c) \
		  $(wildcard ../common/*.c) \

CFLAGS += -Werror -Wall -Wextra \
          --std=gnu99 -g3 -Wmissing-declarations -Wno-implicit-fallthrough \
		  -Wno-format-nonliteral \
		  $(addprefix -I ,$(INCDIR)) \
		  -fprofile-arcs -ftest-coverage \
		  -fkeep-inline-functions -fkeep-static-functions \
		  $(shell pkg-config --cflags cmocka)
LDFLAGS += -fprofile-arcs -ftest-coverage \
           -fkeep-inline-functions -fkeep-static-functions \
		   $(shell pkg-config --libs cmocka) \
		   -lamxc -lamxp -lamxb -lamxd -lamxo -lsahtrace -lamxj -ldl
