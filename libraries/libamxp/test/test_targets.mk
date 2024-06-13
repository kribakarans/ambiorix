all: $(TARGET)

run: $(TARGET)
	set -o pipefail;  valgrind --leak-check=full --error-exitcode=1 --exit-on-first-error=yes --child-silent-after-fork=yes --trace-children=no ./$< 2>&1 | tee -a $(OBJDIR)/unit_test_results.txt;

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS) -fprofile-arcs -ftest-coverage

-include $(OBJECTS:.o=.d)

$(OBJDIR)/../lex.amxp_expr.o $(OBJDIR)/../lex.amxp_expr.c: $(OBJDIR)/../amxp_expr.tab.h ../../src/amxp_expression.l | $(OBJDIR)/
	flex --header-file=$(OBJDIR)/../amxp_expr_flex.h -o $(OBJDIR)/../lex.amxp_expr.c ../../src/amxp_expression.l
	$(CC) $(CFLAGS) -c -o $(OBJDIR)/../lex.amxp_expr.o $(OBJDIR)/../lex.amxp_expr.c

$(OBJDIR)/../amxp_expr.tab.o $(OBJDIR)/../amxp_expr.tab.c $(OBJDIR)/../amxp_expr.tab.h: ../../src/amxp_expression.y | $(OBJDIR)/
	bison -d --verbose -o $(OBJDIR)/../amxp_expr.tab.c ../../src/amxp_expression.y
	$(CC) $(CFLAGS) -c -o $(OBJDIR)/../amxp_expr.tab.o $(OBJDIR)/../amxp_expr.tab.c

$(OBJDIR)/%.o: ./%.c $(OBJDIR)/../amxp_expr.tab.h | $(OBJDIR)/
	$(CC) $(CFLAGS) -fprofile-arcs -ftest-coverage -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)
	
$(OBJDIR)/%.o: $(SRCDIR)/%.c $(OBJDIR)/../amxp_expr.tab.h | $(OBJDIR)/
	$(CC) $(CFLAGS) -fprofile-arcs -ftest-coverage -c -o $@ $<
	@$(CC) $(CFLAGS) -MM -MP -MT '$(@) $(@:.o=.d)' -MF $(@:.o=.d) $(<)

$(OBJDIR)/:
	mkdir -p $@

clean:
	rm -rf $(TARGET) $(OBJDIR) 

.PHONY: clean $(OBJDIR)/
