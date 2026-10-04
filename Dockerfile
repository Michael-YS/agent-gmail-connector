# syntax=docker/dockerfile:1.7

FROM rust:1.97-alpine@sha256:3c38f3f82c2f3d73da3b38e18d279393a04cb43ddded0e35088a8c3324d40900 AS builder
RUN apk add --no-cache build-base cmake perl
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && printf 'fn main() {}\n' > src/main.rs
RUN cargo build --release --locked
COPY . .
RUN touch src/main.rs && cargo build --release --locked

FROM alpine:3.24@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6 AS runtime-base
ENV RUST_BACKTRACE=1
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates wget \
    && addgroup --system --gid 10001 agentmail \
    && adduser --system --uid 10001 --ingroup agentmail --home /nonexistent --shell /sbin/nologin --no-create-home agentmail \
    && mkdir -p /var/lib/agentmail /var/backups/agentmail \
    && chown agentmail:agentmail /var/lib/agentmail /var/backups/agentmail
FROM runtime-base AS runtime
COPY --from=builder /src/target/release/agentmail /usr/local/bin/agentmail
RUN chown root:root /usr/local/bin/agentmail && chmod 0555 /usr/local/bin/agentmail
USER 10001:10001
WORKDIR /var/lib/agentmail
EXPOSE 18080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1:18080/health/live"]
ENTRYPOINT ["/usr/local/bin/agentmail"]
