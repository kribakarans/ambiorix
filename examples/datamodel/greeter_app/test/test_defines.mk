MACHINE = $(shell $(CC) -dumpmachine)

SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../include)

HEADERS = $(wildcard $(INCDIR)/*.h)
SOURCES = $(wildcard $(SRCDIR)/dm_greeter_*.c) $(wildcard $(SRCDIR)/greeter_*.c)

CFLAGS += -Werror -Wall -Wextra -Wno-attributes\
          --std=gnu99 -g3 -Wmissing-declarations \
		  $(addprefix -I ,$(INCDIR)) -I$(OBJDIR)/.. \
		  -fkeep-inline-functions -fkeep-static-functions \
		   -Wno-format-nonliteral \
		  $(shell pkg-config --cflags cmocka) -pthread
LDFLAGS += -fkeep-inline-functions -fkeep-static-functions \
		   $(shell pkg-config --libs cmocka) -lamxc -lamxp -lamxd -lamxrt \
		   -lamxo -lamxb -ldl -lpthread $(shell pkg-config --libs libevent)

