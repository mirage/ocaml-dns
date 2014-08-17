client_test: client_test.ml
	ocamlfind ocamlopt -package dns.lwt -package lwt -g -linkpkg \
		client_test.ml -o client_test

clean:
	rm -f client_test
	rm -f *.cmi *.cmx *.o

.PHONY: clean
