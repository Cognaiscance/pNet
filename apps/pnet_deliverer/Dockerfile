FROM rust:1-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY apps ./apps
RUN cargo build --release -p pnet_deliverer

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /build/target/release/pnet_deliverer /usr/local/bin/pnet_deliverer
CMD ["pnet_deliverer"]
