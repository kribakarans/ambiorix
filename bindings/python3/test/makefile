include ../makefile.inc

MACHINE = $(shell $(CC) -dumpmachine)
OBJDIR = ../output/$(MACHINE)/coverage
OUTPUTDIR = ../output
COVERREPORT = report
PACKAGE_VERSION?=$(shell git describe --tags | cut -dv -f2 | sed -E 's/(.*)-([0-9]+)-(.*)/\1.dev\2/')

run: $(OBJDIR)/
	$(MAKE) -C model
	sudo python3 -m pip uninstall python-amx -y
	@cd ../src && make clean
	@cd ../src && sed "s/version='99.99.99'/version='$(PACKAGE_VERSION)'/g" test_setup.py > versioned_test_setup.py
	@cd ../src && python3 versioned_test_setup.py build
	@cd ../src && python3 versioned_test_setup.py bdist_wheel
	@cd ../src && rm versioned_test_setup.py
	sudo python3 -m pip install --upgrade ../src/dist/*.whl
	python3 -m pytest -v -s --capture=no

clean:
	$(MAKE) -C model clean
	rm -rf $(OUTPUTDIR)
	rm -rf __pycache__
	rm -f ../src/*.o
	rm -f ../src/*.gcno
	rm -f ../src/*.gcda
	rm -f ../src/*.gcov

coverage: $(OBJDIR)/$(COVERREPORT)/ $(OUTPUTDIR)/result/pamx/
	cp ../src/build/temp.*/* ../src
	@cd ../src && for i in $$(find . -name "*.o"); do gcov -c -b -f --long-file-names --preserve-paths $$i > /dev/null; done
	@cd ../src && for i in $$(find . -name "*.h.gcov"); do rm $$i > /dev/null; done
	cd ../src && gcovr -k -p -r . -s -g --html --html-details -o $(OBJDIR)/$(COVERREPORT)/index.html
	cd ../src && gcovr -k -p -r . -s -g | tee $(OBJDIR)/$(COVERREPORT)/gcovr_summary.txt

	cp $(OBJDIR)/$(COVERREPORT)/* $(OUTPUTDIR)/result/pamx/

$(OBJDIR)/:
	mkdir -p $@

$(OBJDIR)/$(COVERREPORT)/:
	mkdir -p $@

$(OUTPUTDIR)/result/pamx/:
	mkdir -p $@

.PHONY: run clean coverage

