Who needs a stunnel if you have a tls tunnel?

## Installation

You first need [OCaml](http://ocaml.org) (at least 4.2.0) and
[opam](http://opam.ocaml.org) (1.2.*) from your distribution.

Then, run `opam pin add tlstunnel
https://github.com/hannesm/tlstunnel`, which will install `tlstunnel`
for you.

## Execution

A sample command line is:

`tlstunnel 127.0.0.1:8080 4433 server.pem server.key`

which listens on TCP port `4433` with the given certificate chain
(`server.pem`) and private key (`server.key`), and forwards
connections to `127.0.0.1` on port `8080`.

An optional argument is `-l FILE` to log into a file instead of to
stdout.  Try `--help` for help.
