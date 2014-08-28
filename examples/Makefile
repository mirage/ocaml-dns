all: forward

forward: forward.ml
	ocamlfind ocamlopt forward.ml -package lwt,dns.lwt -linkpkg -g -o forward

clean:
	rm -f forward forward.cmi forward.cmx forward.o
