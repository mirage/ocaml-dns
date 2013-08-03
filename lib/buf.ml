module B = Bigarray
module B1 = B.Array1

type t = (char, B.int8_unsigned_elt, B.c_layout) B1.t

let create = B1.create B.char B.c_layout
let length = B1.dim
let of_cstruct c = Cstruct.(B1.sub c.buffer c.off c.len)
let shift b k = B1.sub b k (length b - k)
let sub = B1.sub
