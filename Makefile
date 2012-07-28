.PHONY: all clean distclean setup build doc install test-build test 
all: build

NAME=dns

-include Makefile.config

clean: setup.data
	./setup.bin -clean $(OFLAGS)

distclean: setup.data
	./setup.bin -distclean $(OFLAGS)
	$(RM) setup.bin

setup: setup.data

build: setup.data $(wildcard lib/*.ml)
	./setup.bin -build -j $(J) $(OFLAGS)

doc: setup.data setup.bin
	./setup.bin -doc -j $(J) $(OFLAGS)

install: 
	ocamlfind remove $(NAME) $(OFLAGS)
	./setup.bin -install

##

setup.ml: _oasis
	oasis setup

setup.bin: setup.ml
	ocamlopt.opt -o $@ $< || ocamlopt -o $@ $< || ocamlc -o $@ $<
	$(RM) setup.cmx setup.cmi setup.o setup.cmo

setup.data: setup.bin
	./setup.bin -configure --enable-tests
