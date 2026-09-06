# Napkin Runbook

## Curation Rules
- Re-prioritize on every read.
- Keep recurring, high-value notes only.
- Max 10 items per category.
- Each item includes date + "Do instead".

## Security Invariants (Highest Priority)
1. **[2026-07-13] Authorizations must derive from independently verified customer authority**
   Do instead: resolve the durable org owner, verify the owner-signed keyring and descriptor signer membership, and sign only canonical descriptor-derived receipt fields.
2. **[2026-07-13] Receipt issuer IDs are part of the trust contract**
   Do instead: publish a stable explicit key ID with each authorization and coordinate the same current-and-retiring issuer map across KBS, CAP, and `enclava-init`.
3. **[2026-07-13] Static policy artifacts are immutable release inputs**
   Do instead: sign an explicit monotonic epoch offline, record the exact wrapper SHA-256 and issuer ID in platform-release v2, and never log signing seeds.
