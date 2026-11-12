# NovaDB build/test environment. Source is NOT baked in: the container clones the repo at run time.
FROM rust:1-bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
      git ca-certificates clang lld pkg-config libssl-dev linux-perf default-mysql-client \
    && rm -rf /var/lib/apt/lists/*
RUN rustup component add clippy rustfmt llvm-tools-preview \
 && rustup toolchain install nightly --profile minimal \
 && curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash \
 && cargo binstall -y --locked cargo-audit cargo-deny cargo-nextest cargo-fuzz cargo-llvm-cov
RUN useradd -m -u 10001 builder
USER builder
WORKDIR /home/builder
COPY --chown=builder:builder run-tests.sh /usr/local/bin/novadb-test
ENTRYPOINT ["/usr/local/bin/novadb-test"]
