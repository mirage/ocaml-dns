module Transport = Happy_eyeballs_miou_unix

include Dns_client.Make (Transport)
