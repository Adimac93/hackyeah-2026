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
# --locked: build the dependency versions in Cargo.lock, not whatever
# resolves today. A deploy that differs from what was tested is not a deploy.
RUN cargo build --release --locked -p gateway

# The runtime glibc must be at least the builder's. cargo-chef:latest-rust-1
# tracks the official rust image, which is on Debian trixie (glibc 2.38); a
# bookworm runtime (2.36) fails at the dynamic linker with
#   version `GLIBC_2.38' not found (required by gateway)
# which Cloud Run reports only as "container failed to listen on PORT".
# Keep these two Debian releases in lockstep.
FROM debian:trixie-slim AS runtime
# rustls verifies upstream TLS against the system roots
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 gateway
WORKDIR /app
COPY --from=builder /app/target/release/gateway /usr/local/bin/gateway

# No policy files at runtime: the catalog lives in the database, and the
# built-in sample that seeds an empty one is compiled into the binary.

USER gateway
# Cloud Run and friends inject PORT; this is only the documented default.
EXPOSE 8080
CMD ["gateway"]
