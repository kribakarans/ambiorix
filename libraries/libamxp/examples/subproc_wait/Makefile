TARGET = subproc_wait

SOURCES = $(wildcard *.c)
OBJECTS = $(SOURCES:.c=.o)

CFLAGS += -Werror -Wall -Wextra -g
LDFLAGS += -levent -lamxp -lamxc

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
