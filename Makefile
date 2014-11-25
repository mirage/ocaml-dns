.PHONY: all clean distclean setup build doc install test
all: build

J ?= 2
PREFIX ?= /usr/local
NAME=dns

LWT ?= $(shell if ocamlfind query lwt.unix >/dev/null 2>&1; then echo --enable-lwt; fi)
MIRAGE ?= $(shell if ocamlfind query mirage-types >/dev/null 2>&1; then echo --enable-mirage; fi)
ASYNC ?= $(shell if ocamlfind query async >/dev/null 2>&1; then echo --enable-async; fi)
TESTS ?= --enable-tests

-include Makefile.config

setup.data: setup.bin
	./setup.bin -configure $(LWT) $(ASYNC) $(MIRAGE) $(TESTS) $(NETTESTS) --prefix $(PREFIX)

distclean: setup.data setup.bin
	./setup.bin -distclean $(OFLAGS)
	$(RM) setup.bin

setup: setup.data

build: setup.data  setup.bin
	./setup.bin -build -j $(J) $(OFLAGS)

clean:
	ocamlbuild -clean
	rm -f setup.data setup.bin

doc: setup.data setup.bin
	./setup.bin -doc -j $(J) $(OFLAGS)

install: 
	ocamlfind remove $(NAME) $(OFLAGS)
	./setup.bin -install

setup.bin: setup.ml
	ocamlopt.opt -o $@ $< || ocamlopt -o $@ $< || ocamlc -o $@ $<
	$(RM) setup.cmx setup.cmi setup.o setup.cmo

test: build
	./setup.bin -test

