# Linux AArch64 tests on the x86-64 build host (tools/testbed/arm64.sh):
# cross-compiled for aarch64-unknown-linux-gnu with Debian's cross GCC, the
# test binaries run under qemu-user. The Rust toolchain is the one named in
# rust-toolchain.toml (RUST_CHANNEL), installed read-only for any user.
FROM debian:trixie
ARG RUST_CHANNEL
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git gcc g++ libc6-dev make \
      gcc-aarch64-linux-gnu g++-aarch64-linux-gnu libc6-dev-arm64-cross \
      qemu-user \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | CARGO_HOME=/usr/local/cargo sh -s -- -y --no-modify-path --profile minimal \
          --default-toolchain "$RUST_CHANNEL" -c clippy -c rustfmt -t aarch64-unknown-linux-gnu \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git \
    && chmod -R a+rX /usr/local/rustup /usr/local/cargo
