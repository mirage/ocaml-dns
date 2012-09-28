.PHONY: all clean distclean setup build doc install test
all: build

J ?= 2
PREFIX ?= /usr/local
NAME=dns
NAME=cohttp

LWT ?= $(shell if ocamlfind query lwt.ssl >/dev/null 2>&1; then echo --enable-lwt; fi)
ASYNC ?= $(shell if ocamlfind query async_core >/dev/null 2>&1; then echo --enable-async; fi)
MIRAGE ?= $(shell if ocamlfind query mirage-net >/dev/null 2>&1; then echo --enable-mirage; fi)
ifneq ($(MIRAGE_OS),xen)
TESTS ?= --enable-tests
endif

-include Makefile.config

configure: setup.data setup.bin
	./setup.bin -configure $(LWT) $(ASYNC) $(MIRAGE) $(TESTS) $(NETTESTS) --prefix $(PREFIX)

distclean: setup.data setup.bin
	./setup.bin -distclean $(OFLAGS)
	$(RM) setup.bin

setup: setup.data

build: setup.data  setup.bin
	./setup.bin -build -j $(J) $(OFLAGS)

clean:
	ocamlbuild -clean

doc: setup.data setup.bin
	./setup.bin -doc -j $(J) $(OFLAGS)

install: 
	ocamlfind remove $(NAME) $(OFLAGS)
	./setup.bin -install

setup.bin: setup.ml
	ocamlopt.opt -o $@ $< || ocamlopt -o $@ $< || ocamlc -o $@ $<
	$(RM) setup.cmx setup.cmi setup.o setup.cmo

setup.data: setup.bin
	./setup.bin -configure --enable-tests
