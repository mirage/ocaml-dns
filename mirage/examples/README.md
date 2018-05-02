# Unikernel examples

## Installation

You first need to have µDNS installed (`opam pin add udns https://github.com/roburio/udns`).

In either of the directories, run `mirage configure` (see `mirage help
configure` for options), followed by `make depend` and `make` (read more
information [Hello MirageOS world](https://mirage.io/wiki/hello-world)).

Depending on the target, the name and type of the resulting binary varies. In
the default target, `unix`, its name is `./main.native`, and which requires
superuser privileges to listen on port 53 (e.g. `doas ./main.native -l
\*:debug`).

## Primary authoritative nameservers

The [`primary`](primary/) subdirectory contains an example unikernel with the
hardcoded zone (in its [unikernel.ml](primary/unikernel.ml)) named `mirage`,
listening on `10.0.42.2/24`, and some example resource records.  It also
configures several TSIG keys, one for the seconday, another for update,
transfer, and key-management.

The [`primary-with-zone`](primary-with-zone/) contains no hardcoded
configuration, but serves [`data/zone`](primary-with-zone/data/zone) instead.

## Secondary authoritative nameserver

The [`secondary`](secondary/) subdirectory contains an example unikernel which
listens on `10.0.42.4/24` by default and accepts TSIG keys as command line
arguments (`--keys`, can be provided multiple times).

An example setup how they play together could be:
```
# ./ukvm-bin --net=tap0 -- primary/primary.ukvm -l \*:debug
# ./ukvm-bin --net=tap1 -- secondary/secondary.ukvm -l \*:debug --keys 10.0.42.2.10.0.42.4._transfer.mirage:SHA256:E0A7MFr4kfcGIRngRVBcBdFPg43XIb2qbGswcn66q4Q=
```

## Caching resolvers

The [`resolver`](resolver/) subdirectory contains a recursive resolver listening
on `10.0.42.5/24`.  A single key-management key is included,
`foo._key-management:SHA256:/NzgCgIc4yKa7nZvWmODrHMbU+xpMeGiDLkZJGD/Evo=`.

The [`stub`](stub/) subdirectory contains a stub resolver, which forwards all
requests to `141.1.1.1`.
