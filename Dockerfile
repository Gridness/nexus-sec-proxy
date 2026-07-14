# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.95
ARG DEBIAN_VERSION=bookworm
ARG TRIVY_VERSION=0.71.0
ARG HELM_VERSION=3.18.4

FROM --platform=$BUILDPLATFORM rust:${RUST_VERSION}-${DEBIAN_VERSION} AS builder

WORKDIR /workspace

ENV CARGO_TERM_COLOR=never

COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/cache/Cargo.toml crates/cache/Cargo.toml
COPY crates/config/Cargo.toml crates/config/Cargo.toml
COPY crates/proxy/Cargo.toml crates/proxy/Cargo.toml
COPY crates/security/Cargo.toml crates/security/Cargo.toml
COPY crates/yandex-messenger/Cargo.toml crates/yandex-messenger/Cargo.toml

RUN set -eux; \
	mkdir -p crates/cache/src crates/config/src crates/proxy/src crates/security/src crates/security/examples crates/yandex-messenger/src; \
	printf 'pub fn placeholder() {}\n' > crates/cache/src/lib.rs; \
	printf 'pub fn placeholder() {}\n' > crates/config/src/lib.rs; \
	printf 'fn main() {}\n' > crates/proxy/src/main.rs; \
	printf 'pub fn placeholder() {}\n' > crates/security/src/lib.rs; \
	printf 'fn main() {}\n' > crates/security/examples/policy_schema.rs; \
	printf 'pub fn placeholder() {}\n' > crates/yandex-messenger/src/lib.rs

RUN --mount=type=cache,target=/usr/local/cargo/registry \
	--mount=type=cache,target=/usr/local/cargo/git \
	cargo fetch --locked

COPY crates ./crates

RUN --mount=type=cache,target=/usr/local/cargo/registry \
	--mount=type=cache,target=/usr/local/cargo/git \
	cargo build --release --locked -p nexus-sec-proxy && \
	install -D -m 0755 target/release/nexus-sec-proxy /out/nexus-sec-proxy

FROM --platform=$BUILDPLATFORM debian:${DEBIAN_VERSION}-slim AS scanners

ARG TARGETARCH
ARG TRIVY_VERSION
ARG HELM_VERSION

RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends ca-certificates curl gzip tar; \
	rm -rf /var/lib/apt/lists/*

RUN set -eux; \
	case "${TARGETARCH}" in \
		amd64) trivy_arch="64bit"; helm_arch="amd64" ;; \
		arm64) trivy_arch="ARM64"; helm_arch="arm64" ;; \
		*) echo "unsupported TARGETARCH=${TARGETARCH}" >&2; exit 1 ;; \
	esac; \
	trivy_archive="trivy_${TRIVY_VERSION}_Linux-${trivy_arch}.tar.gz"; \
	trivy_base_url="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"; \
	curl -fsSLo "/tmp/${trivy_archive}" "${trivy_base_url}/${trivy_archive}"; \
	curl -fsSLo /tmp/trivy_checksums.txt "${trivy_base_url}/trivy_${TRIVY_VERSION}_checksums.txt"; \
	(cd /tmp && grep " ${trivy_archive}$" trivy_checksums.txt | sha256sum -c -); \
	tar -xzf "/tmp/${trivy_archive}" -C /tmp trivy; \
	install -D -m 0755 /tmp/trivy /out/trivy; \
	/out/trivy --version; \
	helm_archive="helm-v${HELM_VERSION}-linux-${helm_arch}.tar.gz"; \
	helm_base_url="https://get.helm.sh"; \
	curl -fsSLo "/tmp/${helm_archive}" "${helm_base_url}/${helm_archive}"; \
	curl -fsSLo /tmp/helm_checksums.txt "${helm_base_url}/helm-v${HELM_VERSION}-checksums.txt"; \
	(cd /tmp && grep " ${helm_archive}$" helm_checksums.txt | sha256sum -c -); \
	tar -xzf "/tmp/${helm_archive}" -C /tmp linux-${helm_arch}/helm; \
	install -D -m 0755 /tmp/linux-${helm_arch}/helm /out/helm; \
	/out/helm version --short

FROM busybox:1.36.1-musl AS healthcheck

FROM debian:${DEBIAN_VERSION}-slim AS runtime-layout

RUN set -eux; \
	mkdir -p \
		/layout/etc/nexus-sec-proxy \
		/layout/home/nonroot \
		/layout/var/cache/trivy \
		/layout/var/lib/nexus-sec-proxy/trust-reports \
		/layout/var/tmp/nexus-sec-proxy; \
	chown -R 65532:65532 /layout/etc/nexus-sec-proxy /layout/home/nonroot /layout/var

FROM gcr.io/distroless/cc-debian12:nonroot AS runtime

ARG BUILD_DATE=unknown
ARG VCS_REF=unknown
ARG VERSION=0.1.0

LABEL org.opencontainers.image.title="nexus-sec-proxy" \
	org.opencontainers.image.description="Front-of-Nexus security proxy for package vulnerability policy enforcement" \
	org.opencontainers.image.version="${VERSION}" \
	org.opencontainers.image.revision="${VCS_REF}" \
	org.opencontainers.image.created="${BUILD_DATE}" \
	org.opencontainers.image.source="https://github.com/local/nexus-sec-proxy"

ENV HOME=/home/nonroot \
	RUST_LOG=nexus_sec_proxy=info \
	NEXUS_SEC_PROXY_BIND_ADDR=0.0.0.0:3000 \
	NEXUS_SEC_PROXY_LOG_JSON=false \
	NEXUS_SEC_PROXY_TRUST_REPORT_DIR=/var/lib/nexus-sec-proxy/trust-reports \
	NEXUS_SEC_PROXY_ARTIFACT_TMP_DIR=/var/tmp/nexus-sec-proxy \
	TRIVY_CACHE_DIR=/var/cache/trivy

COPY --from=runtime-layout --chown=65532:65532 /layout/etc /etc
COPY --from=runtime-layout --chown=65532:65532 /layout/home /home
COPY --from=runtime-layout --chown=65532:65532 /layout/var /var
COPY --from=builder /out/nexus-sec-proxy /usr/local/bin/nexus-sec-proxy
COPY --from=scanners /out/trivy /usr/local/bin/trivy
COPY --from=scanners /out/helm /usr/local/bin/helm
COPY --from=healthcheck /bin/busybox /busybox

USER nonroot:nonroot
EXPOSE 3000
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
	CMD ["/busybox", "wget", "-q", "-O", "-", "http://127.0.0.1:3000/healthz"]

ENTRYPOINT ["/usr/local/bin/nexus-sec-proxy"]

FROM debian:${DEBIAN_VERSION}-slim AS scanner-db-updater

RUN set -eux; \
	apt-get update; \
	apt-get install -y --no-install-recommends ca-certificates; \
	rm -rf /var/lib/apt/lists/*; \
	mkdir -p /home/nonroot /var/cache/trivy; \
	chown -R 65532:65532 /home/nonroot /var/cache/trivy

ENV HOME=/home/nonroot \
	TRIVY_CACHE_DIR=/var/cache/trivy \
	NEXUS_SEC_PROXY_SCANNER_DB_UPDATE_INTERVAL_SECS=21600 \
	NEXUS_SEC_PROXY_SCANNER_DB_RETRY_INTERVAL_SECS=300

COPY --from=scanners /out/trivy /usr/local/bin/trivy
COPY --from=scanners /out/helm /usr/local/bin/helm
COPY scripts/scanner-db-updater.sh /usr/local/bin/scanner-db-updater

RUN chmod 0755 /usr/local/bin/scanner-db-updater

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/scanner-db-updater"]
CMD ["loop"]
