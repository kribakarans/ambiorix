TARGET = oci_reader

SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)

# compilation and linking flags
CFLAGS += -Werror -Wall -Wextra \
          -Wformat=2 -Wshadow \
          -Wwrite-strings -Wstrict-prototypes -Wold-style-definition \
          -Wredundant-decls -Wnested-externs -Wmissing-include-dirs \
		  -Wpedantic -Wmissing-declarations \
          --std=c18 -g3
LDFLAGS += -lamxc -lamxj

# targets
all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

-include $(OBJECTS:.o=.d)

%.o: %.c 
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

clean:
	rm -f $(OBJECTS) $(TARGET)
	rm -f *.d

.PHONY: clean
