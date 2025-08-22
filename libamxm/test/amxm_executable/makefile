include ../test_defines.mk

TARGET = run_test
TARGET_MODULE = run_mod.so
SOURCES += $(wildcard ./*.c) 
EXE_OBJECTS = $(OBJDIR)/test_executable.o \
              $(OBJDIR)/amxm.o \
			  $(OBJDIR)/amxm_so.o \
			  $(OBJDIR)/amxm_module.o \
			  $(OBJDIR)/test_main.o

MOD_OBJECTS = $(OBJDIR)/test_module.o $(OBJDIR)/amxm.o $(OBJDIR)/amxm_so.o

LOCAL_CFLAGS += -I../../include -I../../../libamxc/include
LOCAL_LDFLAGS += -L../../ -L../../../libamxc/

# uncomment if you dont want to install
#CFLAGS += $(LOCAL_CFLAGS)
#LDFLAGS += $(LOCAL_LDFLAGS)

include ../test_targets.mk
