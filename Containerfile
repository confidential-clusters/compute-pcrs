FROM docker.io/library/rust:1.89-trixie AS builder
WORKDIR /usr/src/compute-pcrs
COPY . .
RUN cargo build
FROM docker.io/library/debian:trixie
COPY --from=builder /usr/src/compute-pcrs/target/debug/compute-pcrs /usr/local/bin
