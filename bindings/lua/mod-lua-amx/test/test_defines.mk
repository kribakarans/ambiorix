MACHINE = $(shell $(CC) -dumpmachine)

SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../include)

HEADERS = $(wildcard $(INCDIR)/*.h)
SOURCES = $(wildcard $(SRCDIR)/mod_lua_*.c) 

MOCK_WRAP = 
WRAP_FUNC=-Wl,--wrap=

LUA_VERSION = 5.3

CFLAGS += -Werror -Wall -Wextra -Wno-attributes\
          --std=gnu99 -g3 -Wmissing-declarations \
		  $(addprefix -I ,$(INCDIR)) -I$(OBJDIR)/.. -I../mocks \
		  -fkeep-inline-functions -fkeep-static-functions -Wno-format-nonliteral

LDFLAGS += -fkeep-inline-functions -fkeep-static-functions -g \
		   $(shell pkg-config --libs cmocka) -lamxc -lamxp -lamxd -lamxo -lamxb -llua$(LUA_VERSION) \
 		   $(shell pkg-config --libs libevent)

LDFLAGS += -g $(addprefix $(WRAP_FUNC),$(MOCK_WRAP))

ifeq ($(LUA_VERSION),5.1)
    CFLAGS += -DLUA_VERSION_5_1
endif
ifeq ($(LUA_VERSION),5.3)
    CFLAGS += -DLUA_VERSION_5_3
endif
