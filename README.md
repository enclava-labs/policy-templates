# Enclava Policy Templates

This repository owns CAP's authoritative Trustee policy templates and the
off-cluster signing-service implementation described by
`cap/SECURITY_MITIGATION_PLAN.md` rev14.

CAP API must not compose policy text. The signing service is a deterministic
policy generator and owner-key registry. Production policy artifacts are signed
by the customer/deployer key outside the platform service, then CAP verifies and
transports the signed envelope to Trustee.

## v1 Decisions

- Key custody: GitHub Actions OIDC + cosign keyless for container provenance;
  customer/deployer keys sign policy artifacts. The HTTP service runs without a
  platform policy-signing key in production.
- Policy template id: `trustee-resource-policy-v1`.
- Canonical encoding: CE-v1 raw TLV bytes for Ed25519 signing inputs.
- Template source of truth: `templates/trustee-resource-policy-v1.rego`.
- Owner state: signing service SQLite DB, not CAP DB.
- Signed request blobs: base64-encoded JSON envelopes for
  `DeploymentDescriptorEnvelope` and `OrgKeyringEnvelope`.

## Layout

- `templates/` - reviewed Rego templates.
- `fixtures/` - CE-v1 sign/verify reference vectors.
- `signing-service/` - Rust HTTP service.
- `docs/` - bootstrap, rotation, and release-runbook notes.

## Signing Service Runtime

Required production env:

- `SIGNING_SERVICE_BEARER_TOKEN` or `SIGNING_SERVICE_BEARER_TOKENS` - bearer
  token(s) accepted by `/agent-policy`.
- `ENABLE_PLATFORM_POLICY_SIGNING=false` - production mode. Legacy `/sign`,
  `/bootstrap-org`, and `/rotate-owner` routes are not registered, and
  customers submit their own signed policy artifact.
- `TRUSTEE_KBS_URL` and `TRUSTEE_KBS_CA_CERT_PEM` - HTTPS Trustee KBS URL and
  CA certificate used when generating the pod manifest that genpolicy evaluates.

Optional local/dev env:

- `BIND_ADDR` - defaults to `0.0.0.0:8080`.
- `SIGNING_SERVICE_ALLOW_UNAUTHENTICATED=1` - local-only escape hatch when
  running the service without bearer auth.
- `ENABLE_PLATFORM_POLICY_SIGNING=1` plus
  `SIGNING_SERVICE_ENABLE_LEGACY_OWNER_API=1`, `OWNER_DB_PATH`,
  `ALLOW_RAW_POLICY_SIGNING_KEY_B64=1`, `POLICY_SIGNING_KEY_B64`, and
  `POLICY_SIGNING_KEY_ID` - compatibility-only platform signing mode. Do not
  use this in production.
- `ALLOW_EPHEMERAL_SIGNING_KEY=1` - test-only escape hatch when no signing key
  is configured.
- `GENPOLICY_BIN`, `GENPOLICY_VERSION_PIN`, `GENPOLICY_SETTINGS_DIR` - see
  `docs/genpolicy-adapter.md`. The service refuses to start if
  `GENPOLICY_VERSION_PIN` is missing, `unconfigured`, or `unpinned`.

## Signing Service Image

Build the image from the repository root so the crate can embed the reviewed
Rego template at compile time:

```bash
docker build -f signing-service/Dockerfile -t enclava-policy-signing-service:local .
```

The image runs as non-root UID/GID `65532`, listens on `BIND_ADDR`, and stores
the owner SQLite database at `OWNER_DB_PATH`. The default image env sets:

- `BIND_ADDR=0.0.0.0:8080`
- `OWNER_DB_PATH=/data/owner-state.sqlite3`
- `GENPOLICY_BIN=/usr/local/bin/genpolicy`
- `GENPOLICY_RULES_PATH=/etc/genpolicy/rules.rego`
- `GENPOLICY_SETTINGS_DIR=/etc/genpolicy`

Production deployments must mount durable storage at `/data` and provide
`SIGNING_SERVICE_BEARER_TOKEN`, `OWNER_DB_PATH`, and a pinned
`GENPOLICY_VERSION_PIN`. The image bakes Kata `genpolicy` from the
pinned `kata-tools-static` release plus `rules.rego` and the default settings
under `/etc/genpolicy`; override `GENPOLICY_BIN`, `GENPOLICY_RULES_PATH`, or
`GENPOLICY_SETTINGS_DIR` only when shipping a new platform release. Do not set
`SIGNING_SERVICE_ALLOW_UNAUTHENTICATED`, `ENABLE_PLATFORM_POLICY_SIGNING`,
`ALLOW_RAW_POLICY_SIGNING_KEY_B64`, or `ALLOW_EPHEMERAL_SIGNING_KEY` outside
local tests.

cap-test01 currently records the live Kata runtime source as
`kata-containers/genpolicy@3.28.0+660e3bb6535b141c84430acb25b159857278d596`.
The Dockerfile verifies the matching
`kata-tools-static-3.28.0-amd64.tar.zst` digest
`825dbf929dc5fe3f77d1a473511fd8950f08b5f81b33803c79085dbc233ab94b` and copies
`genpolicy` from that archive.

Minimal Kubernetes scaffolding lives in
`signing-service/deploy/kubernetes.yaml`. Before applying it, replace the image
placeholder with an immutable digest, source the bearer token from the platform
secret manager, set the genpolicy version pin, and wire any genpolicy binary or
settings mounts required by the release.

Legacy `POST /sign`, `POST /bootstrap-org`, and `POST /rotate-owner` are not
registered in production. If explicitly enabled for a transitional environment,
`POST /sign` no longer accepts caller-provided policy slots. It decodes the
descriptor and keyring blobs, verifies:

1. org keyring owner signature against the bootstrapped owner pubkey in the
   signing-service DB,
2. descriptor signer membership in the verified keyring,
3. descriptor Ed25519 signature over D11 CE-v1 bytes,
4. Kata `genpolicy` can render an agent policy from the verified descriptor,
5. template id/hash and rendered KBS policy hash.

Only then does it return `SignedPolicyArtifact`.
The v1 envelope field names match CAP, Trustee, and `enclava-init`:
`{ metadata, rego_text, rego_sha256, agent_policy_text, agent_policy_sha256,
signature, verify_pubkey_b64 }`, with `signature` encoded as lowercase hex.
Verifiers recompute Rego and agent-policy hashes from the text fields and use
`verify_pubkey_b64` only as a diagnostic key hint.

For customer/CI-signed artifacts, use the standalone generator instead of the
HTTP signing-service authorization key:

```bash
export ENCLAVA_POLICY_ARTIFACT_SIGNING_SEED_HEX=<deployment-key-seed-hex>
docker run --rm \
  -e ENCLAVA_POLICY_ARTIFACT_SIGNING_SEED_HEX \
  -v "$PWD:/work" -w /work \
  ghcr.io/enclava-labs/policy-signing-service:<version> \
  /usr/local/bin/enclava-policy-artifact \
  --request sign-request.json \
  --owner-pubkey-hex <trusted-org-owner-pubkey-hex> \
  --key-id github-actions:<repo>:<workflow> \
  --out signed-policy-artifact.json
```

For local development against the source tree:

```bash
cd signing-service
cargo run --locked --bin policy-artifact -- \
  --request sign-request.json \
  --owner-pubkey-hex <trusted-org-owner-pubkey-hex> \
  --key-id github-actions:<repo>:<workflow> \
  --out signed-policy-artifact.json
```

The command verifies the owner-signed keyring, verifies the deployment
descriptor signature, runs the pinned `genpolicy` adapter, renders the Trustee
policy template, and signs the resulting artifact with the same deployment key
named by `metadata.descriptor_signing_pubkey`. CAP can then verify and transport
that artifact without calling `POST /sign`. Prefer the environment variable for
the signing seed in CI so the seed is not exposed through shell history or the
process list.

## Release Requirements

Every platform release must publish:

- `policy_template_id`
- `policy_template_sha256`
- `policy_template_text`
- customer/org owner trust anchors used by Trustee
- genpolicy version pin
- signing-service image digest/provenance

## Local Verification

```bash
cd signing-service
cargo fmt --check
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Container build verification:

```bash
docker build -f signing-service/Dockerfile -t enclava-policy-signing-service:local .
```
