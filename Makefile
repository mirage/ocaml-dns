.PHONY: build clean test doc

build:
	dune build

test:
	dune runtest

doc:
	dune build @doc

clean:
	dune clean
