FROM ocaml/opam:alpine
RUN opam pin add -n tlstunnel https://github.com/hannesm/tlstunnel && \
    opam depext -u tlstunnel && \
    opam install -j 2 -y tlstunnel
