include ../makefile.inc

doc:
	mkdir -p ../output/xml/
	mkdir -p ./html/
	amxo-cg -Gxml,../output/xml ../odl/greeter.odl
	amxo-xml-to -x html -o output-dir=./html/ -o title="Example Data Model" -o version=$(VERSION) -o sub-titel="Greeter" ../output/xml/*.xml

clean:
	rm -rf ./html/

.PHONY: doc clean
