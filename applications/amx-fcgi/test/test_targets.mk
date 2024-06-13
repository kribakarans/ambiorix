SESSION_HTTPACCESS_SRC = $(wildcard $(realpath ../../mod_session_httpaccess/src)/*.c)
SESSION_DUMMY_SRC = $(wildcard $(realpath ../../mod_session_dummy/src)/*.c)

SESSION_HTTPACCESS = $(OBJDIR)/mod-session-httpaccess.so
SESSION_DUMMY = $(OBJDIR)/mod-session-dummy.so

SESSION_HTTPACCESS_OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SESSION_HTTPACCESS_SRC:.c=.o))) 
SESSION_DUMMY_OBJECTS = $(addprefix $(OBJDIR)/,$(notdir $(SESSION_DUMMY_SRC:.c=.o))) 

all: $(SESSION_HTTPACCESS) $(SESSION_DUMMY) $(TARGET)

run: $(SESSION_HTTPACCESS) $(SESSION_DUMMY) $(TARGET)
	set -o pipefail; valgrind --leak-check=full --exit-on-first-error=yes --error-exitcode=1 ./$(TARGET) 2>&1 | tee -a $(OBJDIR)/unit_test_results.txt;

$(SESSION_HTTPACCESS) : $(SESSION_HTTPACCESS_OBJECTS)
	$(CC) -Wl,-soname,mod-session-httpaccess -o $@ $(SESSION_HTTPACCESS_OBJECTS) -shared -fPIC -lamxc -lamxp -lamxm -lamxb -lamxa -fprofile-arcs -ftest-coverage

$(SESSION_DUMMY) : $(SESSION_DUMMY_OBJECTS)
	$(CC) -Wl,-soname,mod-session-dummy -o $@ $(SESSION_DUMMY_OBJECTS) -shared -fPIC -lamxc -lamxp -lamxm -lamxb -lamxa -fprofile-arcs -ftest-coverage

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS) -fprofile-arcs -ftest-coverage

-include $(OBJECTS:.o=.d)

$(SESSION_HTTPACCESS_OBJECTS) : $(SESSION_HTTPACCESS_SRC)
	$(CC) -Werror -Wall -Wextra -fPIC -g3 $(addprefix -I ,$(INCDIRS)) -fprofile-arcs -ftest-coverage -c -o $@ $<

$(SESSION_DUMMY_OBJECTS) : $(SESSION_DUMMY_SRC)
	$(CC) -Werror -Wall -Wextra -fPIC -g3 $(addprefix -I ,$(INCDIRS)) -fprofile-arcs -ftest-coverage -c -o $@ $<

$(OBJDIR)/%.o: ./%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -fprofile-arcs -ftest-coverage -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)
	
$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -fprofile-arcs -ftest-coverage -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/%.o: $(MOCK_SRC_DIR)/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -fprofile-arcs -ftest-coverage -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/%.o:

$(OBJDIR)/:
	mkdir -p $@

clean:
	rm -rf $(TARGET) $(OBJDIR) 

.PHONY: clean $(OBJDIR)/
