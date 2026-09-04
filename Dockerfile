FROM rust:1.98-bookworm AS builder
ARG VCS_REF=unknown
WORKDIR /source
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN LLMAP_BUILD_SHA="$VCS_REF" cargo build --release --locked

FROM debian:bookworm-slim
ARG VCS_REF=unknown
ARG VERSION=development
LABEL org.opencontainers.image.source="https://github.com/TriformAI/llm-multiaccount-proxy" \
      org.opencontainers.image.revision="$VCS_REF" \
      org.opencontainers.image.version="$VERSION" \
      org.opencontainers.image.licenses="Apache-2.0"
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
