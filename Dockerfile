# syntax=docker/dockerfile:1
# cargo-chef caches the dependency build, so an edit to our own source does not
# rebuild the whole tree. That cache only survives between Cloud Build runs
# because cloudbuild.yaml exports every stage to the registry (buildx
# --cache-to mode=max). A plain `docker build --cache-from` keeps only the final
# stage, so dependencies were recompiled on every push.

# Pinned, not latest-rust-1: a moving base tag changes digest whenever either
# cargo-chef or Rust releases, and that invalidates every cached layer below.
FROM lukemathwalker/cargo-chef:0.1.78-rust-1.99.0-trixie AS chef
WORKDIR /app
# rust-toolchain.toml is deliberately not copied: it asks for `stable`, which
# rustup does not recognise as the image's preinstalled toolchain, so it
# downloaded a second toolchain in every stage of every build.

# Copy only what the Rust build reads. With `COPY . .` a change under web/ or
# docs/ re-ran the gateway build.
FROM chef AS planner
COPY Cargo.toml Cargo.lock ./
COPY gateway gateway
COPY mcp-demo mcp-demo
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --locked -p gateway --recipe-path recipe.json
COPY Cargo.toml Cargo.lock ./
COPY gateway gateway
COPY mcp-demo mcp-demo
# the built-in sample catalog is include_str!'d into the binary
COPY policy policy
# --locked: build the dependency versions in Cargo.lock, not whatever
# resolves today. A deploy that differs from what was tested is not a deploy.
RUN cargo build --release --locked -p gateway --bin gateway

# The runtime glibc must be at least the builder's. The builder above is on
# Debian trixie (glibc 2.38); a bookworm runtime (2.36) fails at the dynamic
# linker with
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
