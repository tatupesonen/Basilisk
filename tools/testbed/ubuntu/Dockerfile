# A newer distribution for the crates that compile C (tools/testbed/ubuntu.sh):
# Ubuntu 26.04, GCC 15 (C23 by default), what CI's ubuntu-latest runs. The
# Rust toolchain is the one named in rust-toolchain.toml (RUST_CHANNEL),
# installed read-only for any user; CARGO_HOME is a mounted cache at run time.
FROM ubuntu:26.04
ARG RUST_CHANNEL
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git gcc g++ libc6-dev make patch \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | CARGO_HOME=/usr/local/cargo sh -s -- -y --no-modify-path --profile minimal \
          --default-toolchain "$RUST_CHANNEL" -c clippy -c rustfmt \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git \
    && chmod -R a+rX /usr/local/rustup /usr/local/cargo
