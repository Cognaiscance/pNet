FROM rust:1-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY apps ./apps
RUN cargo build --release -p pnet_test_probe

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /build/target/release/pnet_test_probe /usr/local/bin/pnet_test_probe
CMD ["pnet_test_probe"]
