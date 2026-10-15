# §18.10 item 6: build the spike on linux/amd64 from a pinned toolchain image.
# Paths are remapped by build.sh, so the hash should match other hosts on the same rustc.
FROM --platform=linux/amd64 rust:1.95.0-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS build
RUN rustup target add wasm32v1-none
WORKDIR /work
COPY verifier/Cargo.toml verifier/Cargo.lock /work/verifier/
COPY verifier/src /work/verifier/src
COPY build.sh /work/build.sh
RUN cd /work/verifier && cargo fetch --locked
RUN /work/build.sh base && /work/build.sh probe

FROM scratch
COPY --from=build /work/out/ /
