(*
 * Copyright (c) 2005-2006 Tim Deegan <tjd@phlegethon.org>
 * Copyright (c) 2017 Hannes Mehnert <hannes@mehnert.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *)

val parse : string -> (Dns.Name_rr_map.t, [> `Msg of string ]) result
(** [parse data] attempts to parse the [data], given in [zone file format].
    It either returns the content as a map, or an error. *)

val decode_keys : 'a Domain_name.t -> string -> Dns.Dnskey.t Domain_name.Map.t
(** [decode_keys zone data] decodes DNSKEY in [data], and ensure that all are
    within [zone]. Errors are logged via the logs library. *)

val decode_zones : (string * string) list -> Domain_name.Set.t * Dns_trie.t
(** [decode_zones (name, data)] parses the zones [data] with the names
    [name], and constructs a trie that has been checked for consistency.
    The set of zones are returned, together with the constructed trie.
    Errors and inconsistencies are logged via the logs library, and the
    respective zone data is ignored. *)

val decode_zones_keys : (string * string) list ->
  Domain_name.Set.t * Dns_trie.t * ([`raw] Domain_name.t * Dns.Dnskey.t) list
(** [decode_zones_keys (name, data)] is [decode_zones], but also if a [name]
    ends with "_keys", the Dnskey records are decoded (using [decode_keys] and
    are added to the last part of the return value. *)
