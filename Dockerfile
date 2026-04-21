FROM rust:1-slim AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
COPY apps ./apps
RUN cargo build --release -p pnet

FROM debian:bookworm-slim
EXPOSE 7777/udp
EXPOSE 8777/tcp
COPY --from=builder /build/target/release/pnet /usr/local/bin/pnet
CMD ["pnet"]
