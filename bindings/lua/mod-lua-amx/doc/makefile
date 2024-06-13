include ../makefile.inc

doc: config.ld
	mkdir -p ../output/staging/doc
	sudo luarocks install ldoc
	ldoc -B -c $< -d ../output/staging/doc ../src/

.PHONY: doc
