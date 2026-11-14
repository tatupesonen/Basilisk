# Windows tests under Wine (tools/testbed/wine.sh): MinGW-w64 for
# x86_64-pc-windows-gnu, clang-cl/lld with cargo-xwin for
# x86_64-pc-windows-msvc, Wine to run the test binaries. Debian 13, the
# build host's own distribution. The Rust toolchain is the one named in
# rust-toolchain.toml (passed as RUST_CHANNEL), installed read-only for any
# user; CARGO_HOME is a mounted cache at run time.
FROM debian:trixie
ARG RUST_CHANNEL
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git gcc libc6-dev \
      gcc-mingw-w64-x86-64 g++-mingw-w64-x86-64 \
      clang lld llvm \
      wine wine64 \
    && rm -rf /var/lib/apt/lists/*
ENV RUSTUP_HOME=/usr/local/rustup PATH=/usr/local/cargo/bin:$PATH
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
      | CARGO_HOME=/usr/local/cargo sh -s -- -y --no-modify-path --profile minimal \
          --default-toolchain "$RUST_CHANNEL" -c clippy -c rustfmt \
          -t x86_64-pc-windows-gnu -t x86_64-pc-windows-msvc \
    && CARGO_HOME=/usr/local/cargo cargo install --locked cargo-xwin --version 0.23.1 \
    && rm -rf /usr/local/cargo/registry /usr/local/cargo/git \
    && chmod -R a+rX /usr/local/rustup /usr/local/cargo
