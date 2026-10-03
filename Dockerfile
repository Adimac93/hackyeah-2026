# syntax=docker/dockerfile:1
# cargo-chef caches the dependency build, so an edit to our own source does not
# rebuild the whole tree.

FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /app

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release -p gateway

FROM debian:bookworm-slim AS runtime
# rustls verifies upstream TLS against the system roots
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 gateway
WORKDIR /app
COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway

# The control catalog is not optional: the gateway refuses to start without a
# policy, because a control layer that runs with no controls is worse than one
# that does not run at all. POLICY_PATH overrides the location.
COPY policy/ /app/policy/

USER gateway
# Cloud Run and friends inject PORT; this is only the documented default.
EXPOSE 8080
CMD ["gateway"]
