
# compilation and linking flags
CFLAGS += -Werror -Wall -Wextra \
          -Wformat=2 -Wshadow \
          -Wwrite-strings -Wredundant-decls -Wmissing-include-dirs \
		  -Wpedantic -Wmissing-declarations -Wno-attributes \
		  -Wno-format-nonliteral \
		  -fPIC -g3 $(addprefix -I ,$(INCDIRS))

ifeq ($(CC_NAME),g++)
    CFLAGS += -std=c++2a
else
	CFLAGS += -Wstrict-prototypes -Wold-style-definition -Wnested-externs -std=c11
endif

LDFLAGS += -shared -fPIC \
           -lamxc -lamxp -lamxd -lamxo

export INSTALL ?= install
export COMPONENT ?= conversion

##
# Add your object files here
#
OBJECTS = conversion.o 
#
# Main target
#
all: conversion.so

#
# Link binary.
#
conversion.so: $(OBJECTS)
	$(CC) -shared -o $(@) $(OBJECTS) $(LDFLAGS) 

#
# Compile object files and generate the dependencies for them
#
%.o: %.c
	$(CC) $(CFLAGS) -c -o $(@) $(<)
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<) >/dev/null

#
# Remove generated files
#
clean:
	rm -f $(COMPONENT).so *.o *.d *.a

#
# Include generated dependencies
#
-include $(OBJECTS:.o=.d)

#
# All these targets must be run regardless of the presence of a file
# named after them.
#
.PHONY: all clean
