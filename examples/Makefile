all: forward server

forward: forward.ml
	ocamlfind ocamlopt forward.ml -package lwt,dns.lwt -linkpkg -g -o forward

server: server.ml
	ocamlfind ocamlopt server.ml -package lwt,dns.lwt -linkpkg -g -o server

clean:
	rm -f forward forward.cmi forward.cmx forward.o
	rm -f server  server.cmi  server.cmx  server.o
