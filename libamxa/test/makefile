PKG_CONFIG_LIBDIR := /usr/lib/pkgconfig:/lib/pkgconfig:/usr/lib/x86_64-linux-gnu/pkgconfig:$(PKG_CONFIG_LIBDIR)
MACHINE = $(shell $(CC) -dumpmachine)
SUBDIRS := test_amxa_merge test_amxa_resolve test_amxa_validate test_amxa_get \
           test_amxa_add test_amxa_del test_amxa_set test_amxa_operate test_amxa_subscription \
		   test_amxa_device test_amxa_issue_18 test_amxa_get_supported \
		   test_amxa_set_multiple test_amxa_get_inst
OBJDIR = ../output/$(MACHINE)/coverage
COVERREPORT = report

run: $(OBJDIR)/
	echo run test
	@for dir in $(SUBDIRS); do make -C $$dir $@  || exit -1; done
	@rm -rf $(OBJDIR)/test_*

clean: 
	rm -rf $(OBJDIR)
	rm -rf $(OBJDIR)/$(COVERREPORT)
	find .. -name "run_test" -delete

coverage: $(OBJDIR)/$(COVERREPORT)/
	@cd $(OBJDIR) && \
	for i in $$(find . -type f -iname "*.o" ! -iname "lex.*.o" ! -name "*.tab.o" ! -iname "dummy_backend.o"); do \
		gcov -c -b -f --long-file-names --preserve-paths $$i > /dev/null; \
    done
	@cd $(OBJDIR) && for i in $$(find . -name "*.h.gcov"); do rm $$i > /dev/null; done
	cd $(OBJDIR) && gcovr -k -p -r ../../.. -s -g --html --html-details -o ./$(COVERREPORT)/index.html
	cd $(OBJDIR) && gcovr -k -p -r ../../.. -s -g | tee ./$(COVERREPORT)/gcovr_summary.txt

$(OBJDIR)/:
	mkdir -p $@

$(OBJDIR)/$(COVERREPORT)/:
	mkdir -p $@

.PHONY: run clean coverage

