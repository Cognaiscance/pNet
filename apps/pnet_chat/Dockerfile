FROM rust:1-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY apps ./apps
RUN cargo build --release -p pnet_chat

FROM debian:bookworm-slim
WORKDIR /app
COPY --from=builder /build/target/release/pnet_chat /usr/local/bin/pnet_chat
CMD ["pnet_chat"]
