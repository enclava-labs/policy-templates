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
`kata-containers/genpolicy@3.28.0+660e3bb6535b141c84430acb25b159857278d596`,
which must match the Kata shim version running on the SNP workers. Changing
the generator also changes signed workload policy hashes.
The Dockerfile verifies and extracts `genpolicy` from
`kata-tools-static-3.28.0-amd64.tar.zst` with digest
`825dbf929dc5fe3f77d1a473511fd8950f08b5f81b33803c79085dbc233ab94b`, along
with the matching `rules.rego` and settings files.

Source contract checked while implementing: Kata documents `genpolicy -y
test.yaml` and optional settings via `-j` for settings directories:
https://github.com/kata-containers/kata-containers/blob/main/src/tools/genpolicy/README.md
