MACHINE = $(shell $(CC) -dumpmachine)

SRCDIR = $(realpath ../../src)
OBJDIR = $(realpath ../../output/$(MACHINE)/coverage)
INCDIR = $(realpath ../../include ../../include_priv ../include)

HEADERS = $(wildcard $(INCDIR)/*.h)
SOURCES = $(wildcard $(SRCDIR)/amx_*.c) 

MOCK_WRAP = FCGX_Init \
            FCGX_Free \
			FCGX_ClearError \
			FCGX_PutS \
			FCGX_FPrintF \
			FCGX_FFlush \
			FCGX_GetError \
			FCGX_Finish_r \
			FCGX_InitRequest \
			FCGX_Accept_r \
			FCGX_GetParam \
			FCGX_GetStr \
			FCGX_OpenSocket \
			FCGX_PutChar \
			fread \
			malloc \
			OS_LibShutdown  \
			amx_fcgi_is_request_authorized

WRAP_FUNC=-Wl,--wrap=

CFLAGS += -Werror -Wall -Wextra -Wno-attributes\
          --std=gnu99 -g3 -Wmissing-declarations \
		  $(addprefix -I ,$(INCDIR)) -I$(OBJDIR)/.. -I../mocks \
		  -fkeep-inline-functions -fkeep-static-functions -Wno-format-nonliteral

LDFLAGS += -fkeep-inline-functions -fkeep-static-functions -g \
		   $(shell pkg-config --libs cmocka) -lamxc -lamxj -lamxp -lamxm -lamxd -lamxo -lamxb -lamxa

LDFLAGS += -g $(addprefix $(WRAP_FUNC),$(MOCK_WRAP))
