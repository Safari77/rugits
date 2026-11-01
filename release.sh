#!/bin/sh

cargo fmt --check && \
    cargo clippy --all-targets && \
    cargo deny check && \
    cargo build --release && \
    cargo +nightly udeps --all-targets && \
    cargo test --release && \
    ./target/release/rugits --help && \
    cargo release patch --no-publish --execute

