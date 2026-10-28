# Genpolicy Adapter

The signing service runs the pinned Kata `genpolicy` binary. CI verifies the
publisher archive checksum and exercises policy generation with its matching
rules and settings.

The adapter is intentionally explicit:

- `GENPOLICY_BIN` selects the binary path, default `genpolicy`.
- `GENPOLICY_VERSION_PIN` records the platform release pin, default
  `unconfigured-local`; service startup rejects this default and any value
  containing `unpinned`.
- `GENPOLICY_RULES_PATH` selects the Kata rules file, default `rules.rego`.
- `GENPOLICY_SETTINGS_DIR` optionally adds `-j <dir>`.
- Invocation shape is
  `genpolicy -y pod.yaml -p <rules.rego> -r [-j <settings-dir>]`.

The generated `pod.yaml` is derived only from the verified signed
`DeploymentDescriptor`: app name, namespace, service account, runtime class,
image digest, command, args, env, ports, mounts, capabilities, resources, and
security context.

The `/sign` endpoint runs this adapter after descriptor/keyring verification
and before signing the KBS policy artifact. A failed `genpolicy` invocation
rejects the signing request.

The platform genpolicy pin is
`kata-containers/genpolicy@4.3.1+03cf2ec06a5d302f23af811744f6bcea49988bfb`,
which must match the Kata shim version running on the SNP workers. Changing
the generator also changes signed workload policy hashes.
The Dockerfile verifies and extracts `genpolicy` from
`kata-tools-static-4.3.1-amd64.tar.zst` with digest
`511262aadef2a8596355733e448b65f7c871f4c6118b44ef7eb18afc19a5c0dd`, along
with the matching `rules.rego` and settings files.

genpolicy 4.3.1 hard-fails generation under `guest_pull` when a container's
expected user/groups are not fully declared in the Kubernetes manifest; the
rendered pod therefore declares `supplementalGroups: [0, 6]`, and images
whose user database grants extra groups (e.g. alpine `wheel`) are rejected
with an actionable error instead of producing an unreproducible policy.

Source contract checked while implementing: Kata documents `genpolicy -y
test.yaml` and optional settings via `-j` for settings directories:
https://github.com/kata-containers/kata-containers/blob/main/src/tools/genpolicy/README.md
