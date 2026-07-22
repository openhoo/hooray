FROM rust:1.90-bookworm AS builder

WORKDIR /usr/src/hooray
COPY . .
RUN cargo build --locked --release --bin hooray

FROM debian:bookworm-slim AS runtime

ARG VERSION
ARG VCS_REF

LABEL org.opencontainers.image.source="https://github.com/openhoo/hooray" \
      org.opencontainers.image.description="Hooray software supply-chain scanner" \
      org.opencontainers.image.licenses="MIT" \
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
