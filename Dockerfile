FROM rust:1-alpine3.22 AS builder

WORKDIR /app

COPY Cargo.toml ./
COPY Cargo.lock ./
COPY bindings ./bindings
COPY crates ./crates

RUN cargo build --locked --release --package tokn-gateway-cli --bin tokn-gateway

FROM alpine:3.22

RUN apk add --no-cache ca-certificates

COPY --from=builder /app/target/release/tokn-gateway /usr/local/bin/tokn-gateway

EXPOSE 4141

ENTRYPOINT ["/usr/local/bin/tokn-gateway"]
CMD ["serve", "--host", "0.0.0.0", "--allow-remote"]
