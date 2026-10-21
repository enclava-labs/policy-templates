# Genpolicy Adapter

The signing service now has a command adapter for Kata `genpolicy`, but local CI
does not execute upstream `genpolicy` because the binary and platform settings
are not present in this repo.

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

Unit coverage asserts the exact argv and manifest fields. The `/sign` endpoint
runs this adapter after descriptor/keyring verification and before signing the
KBS policy artifact. A failed `genpolicy` invocation rejects the signing
request.

The platform genpolicy pin is
`kata-containers/genpolicy@3.32.0+337b6002681479fb6a605ca8a7a1138e81b6098c`,
which must match the Kata shim version running on the SNP workers; confirm
the live worker Kata version before rollout.
The Dockerfile verifies and extracts `genpolicy` from
`kata-tools-static-3.32.0-amd64.tar.zst` with digest
`f11a49d7a15f81a7ec3289293fa44ebe9c29610b6578535b35f1d604f22d6015`, along
with the matching `rules.rego` and settings files.

Source contract checked while implementing: Kata documents `genpolicy -y
test.yaml` and optional settings via `-j` for settings directories:
https://github.com/kata-containers/kata-containers/blob/main/src/tools/genpolicy/README.md
