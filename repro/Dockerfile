# The reference build of collatio.wasm (genesis.md §18.6): linux/amd64, toolchain from
# rust-toolchain.toml, dependencies from Cargo.lock, no post-processing.
FROM --platform=linux/amd64 rust:1.95.0-slim-bookworm@sha256:d7482085ff5b415f84dba5647ae71606650bdef00db7aeb69f4b3d170c3e4082 AS build
WORKDIR /work
COPY rust-toolchain.toml Cargo.toml Cargo.lock build.sh /work/
COPY crates /work/crates
RUN rustup show active-toolchain && cargo fetch --locked --target wasm32v1-none
RUN /work/build.sh

FROM scratch
COPY --from=build /work/out/collatio.wasm /collatio.wasm
