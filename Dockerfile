FROM rust:1.90-bookworm@sha256:3914072ca0c3b8aad871db9169a651ccfce30cf58303e5d6f2db16d1d8a7e58f AS builder

WORKDIR /usr/src/hooray
COPY . .
RUN cargo build --locked --release --bin hooray

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime

ARG VERSION
ARG VCS_REF

LABEL org.opencontainers.image.source="https://github.com/openhoo/hooray" \
      org.opencontainers.image.description="Hooray software supply-chain scanner" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.version="${VERSION}"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libgcc-s1 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 1000 gitlab \
    && useradd --uid 1000 --gid gitlab --create-home --shell /usr/sbin/nologin gitlab

COPY --from=builder /usr/src/hooray/target/release/hooray /usr/local/bin/hooray

USER 1000:1000
ENTRYPOINT ["hooray"]
