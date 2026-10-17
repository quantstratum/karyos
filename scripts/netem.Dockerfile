# SPDX-License-Identifier: Apache-2.0
#
# The Linux test image with `tc` (iproute2) for scripts/netem-test.sh: the
# network fault tests shape the container's loopback with netem. Built on
# demand from the same Rust image as scripts/linux-test.sh.
ARG BASE=rust:1.99
FROM ${BASE}
RUN apt-get update \
    && apt-get install -y --no-install-recommends iproute2 \
    && rm -rf /var/lib/apt/lists/*
