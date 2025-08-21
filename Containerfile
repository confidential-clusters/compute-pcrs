FROM docker.io/library/rust:1.89-trixie AS builder
WORKDIR /usr/src/compute-pcrs
COPY . .
RUN git clone --depth 1 https://github.com/confidential-clusters/reference-values && cargo build --release
FROM docker.io/library/debian:trixie
COPY --from=builder /usr/src/compute-pcrs/target/release/compute-pcrs /usr/local/bin
COPY --from=builder /usr/src/compute-pcrs/reference-values reference-values
