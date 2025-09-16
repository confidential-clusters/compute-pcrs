# SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
# SPDX-FileCopyrightText: Beñat Gartzia Arruabarrena <bgartzia@redhat.com>
#
# SPDX-License-Identifier: CC0-1.0

FROM ghcr.io/confidential-clusters/buildroot:latest AS builder
WORKDIR /usr/src/compute-pcrs
COPY . .
RUN cargo build
FROM quay.io/fedora/fedora:latest
COPY --from=builder /usr/src/compute-pcrs/target/debug/compute-pcrs /usr/local/bin
