all: $(TARGET)

run: $(TARGET) $(TARGET_MODULE)
	set -o pipefail; valgrind --leak-check=full --exit-on-first-error=yes --error-exitcode=1 ./$< 2>&1 | tee -a $(OBJDIR)/unit_test_results.txt;

$(TARGET): $(EXE_OBJECTS)
	$(CC) -o $@ $(EXE_OBJECTS) $(LDFLAGS)

$(TARGET_MODULE): $(MOD_OBJECTS)
	$(CC) -shared $(MOD_OBJECTS) -Wl,-soname,$(@) -o $@ $(LDFLAGS)

-include $(OBJECTS:.o=.d)

$(OBJDIR)/%.o: ./%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)/
	$(CC) $(CFLAGS) -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/:
	mkdir -p $@

clean:
	! rm -f $(TARGET) $(TARGET_MODULE) vgcore.* $(OBJDIR)

.PHONY: clean $(OBJDIR)/
