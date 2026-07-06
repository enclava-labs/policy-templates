# syntax=docker/dockerfile:1.7

FROM debian:bookworm-slim AS kata-tools
ARG KATA_TOOLS_VERSION=3.28.0
ARG KATA_TOOLS_SHA256=825dbf929dc5fe3f77d1a473511fd8950f08b5f81b33803c79085dbc233ab94b
ADD --checksum=sha256:${KATA_TOOLS_SHA256} \
    https://github.com/kata-containers/kata-containers/releases/download/${KATA_TOOLS_VERSION}/kata-tools-static-${KATA_TOOLS_VERSION}-amd64.tar.zst \
    /tmp/kata-tools.tar.zst
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends zstd ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    mkdir -p /kata-tools; \
    tar --zstd -xf /tmp/kata-tools.tar.zst -C /kata-tools \
      ./opt/kata/bin/genpolicy \
      ./opt/kata/share/defaults/kata-containers/rules.rego \
      ./opt/kata/share/defaults/kata-containers/genpolicy-settings.json \
      ./opt/kata/share/defaults/kata-containers/genpolicy-settings.d

FROM rust:1-bookworm AS builder
ARG BUILD_PROFILE=debug
WORKDIR /workspace

COPY signing-service/Cargo.toml signing-service/Cargo.lock ./signing-service/
COPY signing-service/src ./signing-service/src
WORKDIR /workspace/signing-service
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    cargo fetch --locked

WORKDIR /workspace
COPY signing-service ./signing-service
COPY templates ./templates
WORKDIR /workspace/signing-service
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/usr/local/cargo/git \
    --mount=type=cache,target=/workspace/signing-service/target \
    if [ "${BUILD_PROFILE}" = "release" ]; then \
      cargo build --release --locked && \
      cp target/release/enclava-policy-signing-service /usr/local/bin/enclava-policy-signing-service && \
      cp target/release/policy-artifact /usr/local/bin/enclava-policy-artifact; \
    elif [ "${BUILD_PROFILE}" = "debug" ]; then \
      cargo build --locked && \
      cp target/debug/enclava-policy-signing-service /usr/local/bin/enclava-policy-signing-service && \
      cp target/debug/policy-artifact /usr/local/bin/enclava-policy-artifact; \
    else \
      echo "unsupported BUILD_PROFILE=${BUILD_PROFILE}; expected debug or release" >&2; \
      exit 1; \
    fi

FROM debian:bookworm-slim AS runtime

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*; \
    groupadd --system --gid 65532 signing-service; \
    useradd --system --uid 65532 --gid 65532 --home-dir /nonexistent --shell /usr/sbin/nologin signing-service; \
    mkdir -p /data; \
    chown 65532:65532 /data

COPY --from=builder /usr/local/bin/enclava-policy-signing-service /usr/local/bin/enclava-policy-signing-service
COPY --from=builder /usr/local/bin/enclava-policy-artifact /usr/local/bin/enclava-policy-artifact
COPY --from=kata-tools /kata-tools/opt/kata/bin/genpolicy /usr/local/bin/genpolicy
COPY --from=kata-tools /kata-tools/opt/kata/share/defaults/kata-containers/rules.rego /etc/genpolicy/rules.rego
COPY --from=kata-tools /kata-tools/opt/kata/share/defaults/kata-containers/genpolicy-settings.json /etc/genpolicy/genpolicy-settings.json
COPY --from=kata-tools /kata-tools/opt/kata/share/defaults/kata-containers/genpolicy-settings.d /etc/genpolicy/genpolicy-settings.d

USER 65532:65532
ENV BIND_ADDR=0.0.0.0:8080 \
    OWNER_DB_PATH=/data/owner-state.sqlite3 \
    ENABLE_PLATFORM_POLICY_SIGNING=false \
    GENPOLICY_BIN=/usr/local/bin/genpolicy \
    GENPOLICY_RULES_PATH=/etc/genpolicy/rules.rego \
    GENPOLICY_SETTINGS_DIR=/etc/genpolicy
EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/enclava-policy-signing-service"]
