FROM rust:1.85-bookworm AS builder
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --uid 10001 --home /var/lib/llmap --shell /usr/sbin/nologin llmap \
    && install -d -o llmap -g llmap /var/lib/llmap /etc/llmap
COPY --from=builder /source/target/release/llmap /usr/local/bin/llmap
USER 10001:10001
WORKDIR /var/lib/llmap
EXPOSE 8080 8081
ENTRYPOINT ["/usr/local/bin/llmap"]
CMD ["serve", "--config", "/etc/llmap/llmap.toml"]
