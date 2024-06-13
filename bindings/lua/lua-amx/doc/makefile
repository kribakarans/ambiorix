include ../makefile.inc

doc: config.ld
	mkdir -p ../output/staging/doc
	mkdir -p ../output/html
	sudo luarocks install ldoc
	ldoc -B -c $< -d ../output/staging/doc ../src/
	ldoc -B -c $< -d ../output/html ../src/

.PHONY: doc
