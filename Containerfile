FROM ghcr.io/confidential-clusters/compute-pcrs/buildroot:latest AS builder
WORKDIR /usr/src/compute-pcrs
COPY . .
RUN cargo build
FROM quay.io/fedora/fedora:latest
COPY --from=builder /usr/src/compute-pcrs/target/debug/compute-pcrs /usr/local/bin
