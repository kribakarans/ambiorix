COMPONENT = greeter

OBJECTS = $(COMPONENT).o


CFLAGS += -fPIC -g  -I$(STAGINGDIR)/include   -Wall -Werror -Wextra -std=gnu99 \
          $(shell pkg-config --cflags sahtrace pcb mtk )
LDFLAGS += $(shell pkg-config --libs sahtrace pcb mtk )

ifeq ($(COVERAGE),y)
CFLAGS +=-fprofile-arcs -ftest-coverage
LDFLAGS += -fprofile-arcs -ftest-coverage
endif

all:  $(COMPONENT).so

%.o: %.c
	$(CC) $(CFLAGS)  -o $@ -c $<
	$(CC) $(CFLAGS)  -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $<  >/dev/null

$(COMPONENT).so:  $(OBJECTS)
	$(CC) -shared -o $(@) $(OBJECTS) $(LDFLAGS) 

clean:
	rm -rf  $(COMPONENT).so $(OBJECTS:.o=.d)  $(OBJECTS)

.PHONY: clean