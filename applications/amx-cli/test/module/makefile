COMPONENT = mod-test-cli

# TARGETS
TARGET_SO = $(COMPONENT).so

# directories
# source directories
SRCDIR = .

SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)

# compilation and linking flags
CFLAGS += -Werror -Wall -Wextra \
          -Wformat=2 -Wshadow \
          -Wwrite-strings -Wredundant-decls \
          -Wpedantic -Wmissing-declarations -Wno-attributes \
          -Wno-format-nonliteral \
          -fPIC -g3

ifeq ($(CC_NAME),g++)
    CFLAGS += -std=c++2a
else
	CFLAGS += -Wstrict-prototypes -Wold-style-definition -Wnested-externs -std=c11
endif

LDFLAGS += -shared -fPIC \
           -lamxc -lamxt -lamxm -lamxp

# targets
all: $(TARGET_SO)

$(TARGET_SO): $(OBJECTS)
	$(CC) -Wl,-soname,$(COMPONENT).so -o $@ $(OBJECTS) $(LDFLAGS)

-include $(OBJECTS:.o=.d)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

clean:
	rm -rf ./$(COMPONENT).so *.d *.o 

.PHONY: all clean
