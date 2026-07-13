# Owner Bootstrap and Rotation

This is the receipt-mode owner authority flow. Production signing-service
deployments register the bearer-protected `/bootstrap-org`, `/rotate-owner`,
and `/sign` routes when `ENABLE_PLATFORM_POLICY_SIGNING=1`. The owner database
is an independent trust store and must not be reconstructed from CAP state.

## Bootstrap

1. CLI creates the org owner Ed25519 keypair.
2. CLI posts the owner pubkey directly to `POST /bootstrap-org` on the
   signing service URL from `platform-release.json`.
3. Signing service stores `(org_id, owner_pubkey, version, bootstrapped_at)` in
   its own SQLite database at `OWNER_DB_PATH`. CAP API state is not a trust
   anchor for owner keys.

Request:

```json
{
  "org_id": "11111111-1111-1111-1111-111111111111",
  "owner_pubkey_b64": "<base64 32-byte Ed25519 public key>"
}
```

`owner_pubkey_hex` is accepted as an alternative for CLI/debug tooling. The
endpoint is idempotent for the same key and rejects a different key for an
already bootstrapped org.

## Rotation

Owner rotation is not an API-admin operation. `POST /rotate-owner` accepts a
current-owner-signed recovery directive before replacing the active owner key.
The D11 signing input is:

```text
("purpose","enclava-recovery-v1")
("org_id", uuid_16B)
("revoked_pubkey", current_owner_pubkey_32B)
("replacement_pubkey", replacement_owner_pubkey_32B)
("signed_at", rfc3339_utf8)
("reason", reason_utf8)
```

Request:

```json
{
  "org_id": "11111111-1111-1111-1111-111111111111",
  "replacement_owner_pubkey_b64": "<base64 32-byte Ed25519 public key>",
  "signed_at": "2026-04-01T12:00:00Z",
  "reason": "routine owner rotation",
  "signing_pubkey_b64": "<base64 current owner public key>",
  "signature_b64": "<base64 Ed25519 signature over CE-v1 directive bytes>"
}
```

Threshold-of-owners and recovery-contact rotation are still external workflow
work. The service-side primitive is durable and signature-checked, but v1 local
tests cover a single current-owner signature only.

## Backup And Restore

Back up `OWNER_DB_PATH` with a SQLite-consistent snapshot that includes the WAL
state. Retain backups beyond the longest CAP rollback window. A restore drill
must verify the latest owner version, the append-only owner event history, and
exact signing-result replay before the service is returned to traffic. CAP and
the signing service are restored independently; if their latest owner
fingerprints disagree, signing remains fail-closed until an audited recovery
decision is made.

## M5 Mode

M5-strict requires emergency email reset to be disabled at org creation.
If email reset is enabled, the org is M5-with-recovery-reset and the CLI must
display that mode during unlock.
