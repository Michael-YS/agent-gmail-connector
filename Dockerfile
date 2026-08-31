# syntax=docker/dockerfile:1.7

FROM --platform=$BUILDPLATFORM rust:1.97-bookworm AS builder
WORKDIR /src
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && printf 'fn main() {}\n' > src/main.rs
RUN cargo build --release --locked
COPY . .
RUN touch src/main.rs && cargo build --release --locked

FROM --platform=linux/amd64 debian:bookworm-slim AS runtime
ENV RUST_BACKTRACE=1
RUN apt-get update \
    && apt-get install --no-install-recommends --yes ca-certificates wget \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 agentmail \
    && useradd --system --uid 10001 --gid agentmail --home-dir /nonexistent --shell /usr/sbin/nologin agentmail \
    && mkdir -p /var/lib/agentmail /var/backups/agentmail \
    && chown agentmail:agentmail /var/lib/agentmail /var/backups/agentmail
COPY --from=builder /src/target/release/agentmail /usr/local/bin/agentmail
RUN chown root:root /usr/local/bin/agentmail && chmod 0555 /usr/local/bin/agentmail
USER 10001:10001
WORKDIR /var/lib/agentmail
EXPOSE 18080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD ["wget", "--quiet", "--tries=1", "--spider", "http://127.0.0.1:18080/health/live"]
ENTRYPOINT ["/usr/local/bin/agentmail"]