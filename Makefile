.PHONY: all clean distclean setup build doc install test-build test 
all: build

NAME=dns
J=4

export OCAMLRUNPARAM=b


clean: setup.data
	./setup.bin -clean

distclean: setup.data
	./setup.bin -distclean
	$(RM) setup.bin

setup: setup.data

build: setup.data $(wildcard lib/*.ml)
	./setup.bin -build -j $(J)

doc: setup.data setup.bin
	./setup.bin -doc -j $(J)

install: 
	ocamlfind remove $(NAME)
	./setup.bin -install

##

setup.ml: _oasis
	oasis setup

setup.bin: setup.ml
	ocamlopt.opt -o $@ $< || ocamlopt -o $@ $< || ocamlc -o $@ $<
	$(RM) setup.cmx setup.cmi setup.o setup.cmo

setup.data: setup.bin
	./setup.bin -configure --enable-tests
