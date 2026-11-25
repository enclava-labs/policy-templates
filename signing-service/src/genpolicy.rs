use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Output,
};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::descriptor::{
    validate_unique_resource_names, Capabilities, DeploymentDescriptor, EnvVar,
    LogEncryptionConfig, OciRuntimeSpec, Resources,
};

const KATA_RUNTIME_HANDLER_ANNOTATION: &str = "io.containerd.cri.runtime-handler";
const KATA_KERNEL_PARAMS_ANNOTATION: &str = "io.katacontainers.config.hypervisor.kernel_params";
const KATA_HYPERVISOR_CC_INIT_DATA_ANNOTATION: &str =
    "io.katacontainers.config.hypervisor.cc_init_data";
const KATA_RUNTIME_CC_INIT_DATA_ANNOTATION: &str = "io.katacontainers.config.runtime.cc_init_data";
const DEFAULT_KBS_URL: &str = "http://kbs-service.trustee-operator-system.svc.cluster.local:8080";
// Pinned public image used wherever tests need a registry-resolvable ref
// (content-addressed: stable forever, anonymous pulls fine).
const SIZE_CLASS_IMAGE_REPO: &str = "index.docker.io/library/debian";
const SIZE_CLASS_IMAGE_DIGEST: &str =
    "sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3";
const DEFAULT_ATTESTATION_PROXY_IMAGE_REPO: &str = "ghcr.io/enclava-labs/attestation-proxy";
const CADDY_INGRESS_IMAGE_REPO: &str = "ghcr.io/enclava-labs/caddy-ingress";

// genpolicy resolves every manifest image over the registry, so test builds swap the
// platform sidecar repos for the pinned public stand-in at the use site: the
// size-class test stays hermetic (no coupling to platform-package availability,
// visibility, or registry rate limits in CI). The production literals above stay
// the single source and are pinned by a dedicated test.
fn sidecar_image_repo(repo: &str) -> &str {
    if cfg!(test) {
        SIZE_CLASS_IMAGE_REPO
    } else {
        repo
    }
}
const ENCLAVA_WAIT_EXEC_PATH: &str = "/enclava-tools/enclava-wait-exec";
const ENCLAVA_LOG_SPOOL_DIR: &str = "/run/enclava-logs";
const ENCLAVA_LOG_RELAY_PORT: u16 = 8082;
const ENCLAVA_TOOLS_INIT_COMMAND: &str = "cp /usr/local/bin/enclava-wait-exec /work/enclava-wait-exec && chmod 0555 /work/enclava-wait-exec && install -d -m 02770 -o 0 -g 10001 /run/enclava/containers && install -d -m 02770 -o 0 -g 10001 /run/enclava-logs && printf 'not-ready\\n' > /run/enclava/init-ready && chmod 0644 /run/enclava/init-ready";
const ENCLAVA_TOOLS_INIT_COMMAND_NO_LOGS: &str = "cp /usr/local/bin/enclava-wait-exec /work/enclava-wait-exec && chmod 0555 /work/enclava-wait-exec && install -d -m 02770 -o 0 -g 10001 /run/enclava/containers && printf 'not-ready\\n' > /run/enclava/init-ready && chmod 0644 /run/enclava/init-ready";
const ENCLAVA_INIT_WAIT_FOR_CONTAINERS: &str = "web,tenant-ingress,attestation-proxy";
const CADDY_ACME_TLS_PORT: u16 = 10443;
const CADDY_INTERNAL_TLS_PORT: u16 = 10443;
const CADDY_INTERNAL_RUNTIME_PATH: &str = "/run/enclava/caddy-runtime";
const CADDY_DNS01_BROKER_TLS_HANDOFF_SCRIPT: &str = concat!(
    "trap 'exit 0' TERM INT\n",
    "i=0\n",
    "while [ \"$i\" -lt 300 ]; do\n",
    "  if [ -r '/run/enclava/caddy-runtime/certificates/tls.crt' ] && [ -r '/run/enclava/caddy-runtime/certificates/tls.key' ]; then break; fi\n",
    "  if [ \"$i\" = 0 ] || [ $((i % 10)) -eq 0 ]; then echo 'tenant-ingress waiting for TLS certificate handoff' >&2; fi\n",
    "  i=$((i + 1))\n",
    "  sleep 1\n",
    "done\n",
    "if [ ! -r '/run/enclava/caddy-runtime/certificates/tls.crt' ] || [ ! -r '/run/enclava/caddy-runtime/certificates/tls.key' ]; then echo 'tenant-ingress TLS certificate handoff missing or unreadable' >&2; exit 1; fi\n",
    "certstamp() { cksum '/run/enclava/caddy-runtime/certificates/tls.crt' 2>/dev/null || wc -c '/run/enclava/caddy-runtime/certificates/tls.crt' 2>/dev/null || echo none; }\n",
    "# The generated Caddyfile has `admin off`, so there is no reload API:\n",
    "# renewed certificates are picked up by restarting caddy when the\n",
    "# tls.crt checksum changes (checked once a minute, atomic handoff\n",
    "# writes keep the watched file complete).\n",
    "while true; do\n",
    "  rc=0\n",
    "  if /usr/bin/caddy validate --config /etc/caddy/Caddyfile; then\n",
    "    stamp=$(certstamp)\n",
    "    /usr/bin/caddy run --config /etc/caddy/Caddyfile &\n",
    "    caddy_pid=$!\n",
    "    ticks=0\n",
    "    while kill -0 \"$caddy_pid\" 2>/dev/null; do\n",
    "      ticks=$((ticks + 1))\n",
    "      if [ $((ticks % 60)) -eq 0 ] && [ \"$(certstamp)\" != \"$stamp\" ]; then\n",
    "        echo 'tenant-ingress TLS certificate changed; restarting caddy' >&2\n",
    "        kill \"$caddy_pid\" 2>/dev/null || true\n",
    "        n=0\n",
    "        while kill -0 \"$caddy_pid\" 2>/dev/null && [ \"$n\" -lt 30 ]; do n=$((n + 1)); sleep 1; done\n",
    "        kill -9 \"$caddy_pid\" 2>/dev/null || true\n",
    "        break\n",
    "      fi\n",
    "      sleep 1\n",
    "    done\n",
    "    wait \"$caddy_pid\" || rc=$?\n",
    "  else\n",
    "    rc=$?\n",
    "  fi\n",
    "  echo \"tenant-ingress caddy exited rc=$rc; restarting in 5s\" >&2\n",
    "  sleep 5\n",
    "done"
);
const CAP_CONFIG_READY_MARKER: &str = "/state/.enclava/luks-ready";
const CAP_CONFIG_FILE_GID: &str = "10001";
const PLATFORM_MANAGED_SSH_RELAY_CAPS: &[&str] =
    &["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"];
const ROOTFUL_SUDO_CAPS: &[&str] = &[
    "CHOWN",
    "DAC_OVERRIDE",
    "FOWNER",
    "SETGID",
    "SETUID",
    "AUDIT_WRITE",
];

fn log_spool_path(log_encryption: &LogEncryptionConfig) -> String {
    let digest = log_encryption
        .public_key_sha256
        .strip_prefix("sha256:")
        .unwrap_or(&log_encryption.public_key_sha256)
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                c
            } else {
                '-'
            }
        })
        .collect::<String>();
    format!("{ENCLAVA_LOG_SPOOL_DIR}/web-{digest}.jsonl")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaddyTlsMode {
    Acme,
    Dns01Broker,
    Internal,
}

impl std::str::FromStr for CaddyTlsMode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "" | "acme" => Ok(Self::Acme),
            "dns01-broker" | "dns-01-broker" | "broker" => Ok(Self::Dns01Broker),
            "internal" => Ok(Self::Internal),
            other => Err(format!(
                "invalid tenant Caddy TLS mode {other:?}; expected acme, dns01-broker, or internal"
            )),
        }
    }
}

fn tenant_caddy_tls_mode() -> Result<CaddyTlsMode> {
    std::env::var("TENANT_CADDY_TLS_MODE")
        .unwrap_or_default()
        .parse::<CaddyTlsMode>()
        .map_err(anyhow::Error::msg)
        .context("TENANT_CADDY_TLS_MODE")
}

fn trustee_kbs_url() -> String {
    std::env::var("TRUSTEE_KBS_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_KBS_URL.to_string())
}

fn attestation_proxy_image_repo() -> String {
    std::env::var("ATTESTATION_PROXY_IMAGE_REPO")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| DEFAULT_ATTESTATION_PROXY_IMAGE_REPO.to_string())
}

fn trustee_kbs_resource_url() -> String {
    format!(
        "{}/kbs/v0/resource",
        trustee_kbs_url().trim_end_matches('/')
    )
}

fn trustee_kbs_ca_cert_pem() -> Option<String> {
    std::env::var("TRUSTEE_KBS_CA_CERT_PEM")
        .ok()
        .map(|value| value.replace("\\n", "\n").trim().to_string())
        .filter(|value| !value.is_empty())
}

fn amd_kds_base_url() -> Option<String> {
    std::env::var("AMD_KDS_BASE_URL")
        .ok()
        .map(|value| value.trim().trim_end_matches('/').to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
pub struct GenpolicyConfig {
    pub binary: PathBuf,
    pub version_pin: String,
    pub rules_path: PathBuf,
    pub settings_dir: Option<PathBuf>,
    /// Maximum CONCURRENT genpolicy steps this process runs. The old
    /// blocking call implicitly capped concurrency at the worker-thread
    /// count; the async runner needs an explicit cap so concurrent /sign
    /// requests cannot each start a generator under the same container
    /// limits (500m CPU / 512Mi, deploy/kubernetes.yaml). Default 2.
    pub max_concurrent: usize,
    /// Hard TOTAL budget for one genpolicy step (both attempts together).
    /// 90 s sits under cap's 120 s signing client timeout
    /// (PLATFORM_SIGNING_SERVICE_TIMEOUT_SECONDS) with room for the rest of
    /// /sign (descriptor verification, key operations) and for the
    /// attributable timeout error to reach the caller. Injected so tests
    /// can shrink it.
    pub total_budget: std::time::Duration,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenpolicyInvocation {
    pub binary: PathBuf,
    pub args: Vec<String>,
    pub manifest_yaml: String,
    pub version_pin: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedAgentPolicy {
    pub policy_text: String,
    pub invocation: GenpolicyInvocation,
}

impl GenpolicyConfig {
    pub fn from_env() -> Self {
        let binary = std::env::var("GENPOLICY_BIN").unwrap_or_else(|_| "genpolicy".to_string());
        let version_pin = std::env::var("GENPOLICY_VERSION_PIN")
            .unwrap_or_else(|_| "unconfigured-local".to_string());
        let rules_path =
            std::env::var("GENPOLICY_RULES_PATH").unwrap_or_else(|_| "rules.rego".to_string());
        let settings_dir = std::env::var("GENPOLICY_SETTINGS_DIR")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .map(PathBuf::from);
        Self {
            binary: PathBuf::from(binary),
            version_pin,
            rules_path: PathBuf::from(rules_path),
            settings_dir,
            total_budget: DEFAULT_GENPOLICY_TOTAL_BUDGET,
            max_concurrent: DEFAULT_GENPOLICY_MAX_CONCURRENT,
        }
    }

    pub fn require_pinned_version(&self) -> Result<()> {
        let pin = self.version_pin.trim();
        if pin.is_empty() || pin.contains("unconfigured") || pin.contains("unpinned") {
            bail!("GENPOLICY_VERSION_PIN must be a concrete pinned genpolicy release");
        }
        Ok(())
    }

    pub fn build_invocation(
        &self,
        descriptor: &DeploymentDescriptor,
    ) -> Result<GenpolicyInvocation> {
        self.build_invocation_with_log_encryption(descriptor, None)
    }

    pub fn build_invocation_with_log_encryption(
        &self,
        descriptor: &DeploymentDescriptor,
        log_encryption: Option<&LogEncryptionConfig>,
    ) -> Result<GenpolicyInvocation> {
        let manifest_yaml = render_pod_manifest(descriptor, log_encryption)?;
        let mut args = vec![
            "-y".to_string(),
            "pod.yaml".to_string(),
            "-p".to_string(),
            self.rules_path.display().to_string(),
            "-r".to_string(),
        ];
        if let Some(settings_dir) = &self.settings_dir {
            args.push("-j".to_string());
            args.push(settings_dir.display().to_string());
        }
        Ok(GenpolicyInvocation {
            binary: self.binary.clone(),
            args,
            manifest_yaml,
            version_pin: self.version_pin.clone(),
        })
    }

    pub async fn run(&self, descriptor: &DeploymentDescriptor) -> Result<GeneratedAgentPolicy> {
        self.run_with_log_encryption(descriptor, None).await
    }

    pub async fn run_with_log_encryption(
        &self,
        descriptor: &DeploymentDescriptor,
        log_encryption: Option<&LogEncryptionConfig>,
    ) -> Result<GeneratedAgentPolicy> {
        // Explicit concurrency cap: waiting requests queue here instead of
        // each starting a generator under the same container limits
        // (Devin T5).
        static PERMITS: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
        let semaphore = PERMITS
            .get_or_init(|| tokio::sync::Semaphore::new(std::cmp::max(1, self.max_concurrent)));
        let invocation = self.build_invocation_with_log_encryption(descriptor, log_encryption)?;
        let dir = tempfile::tempdir().context("creating genpolicy work dir")?;
        let manifest_path = dir.path().join("pod.yaml");
        std::fs::write(&manifest_path, &invocation.manifest_yaml)
            .with_context(|| format!("writing {}", manifest_path.display()))?;

        let effective_settings_dir = if let Some(settings_dir) = &self.settings_dir {
            Some(prepare_cap_settings_dir(settings_dir, dir.path())?)
        } else {
            None
        };

        let mut args = vec![
            "-y".to_string(),
            manifest_path.display().to_string(),
            "-p".to_string(),
            self.rules_path.display().to_string(),
            "-r".to_string(),
        ];
        if let Some(settings_dir) = &effective_settings_dir {
            args.push("-j".to_string());
            args.push(settings_dir.display().to_string());
        }

        let output = run_genpolicy(
            &self.binary,
            &args,
            dir.path(),
            self.total_budget,
            Some(semaphore),
            &descriptor.image_ref,
        )
        .await?;
        if !output.status.success() {
            bail!(
                "genpolicy failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let policy_text =
            String::from_utf8(output.stdout).context("genpolicy output is not UTF-8")?;
        let policy_text = normalize_guest_memory_mount_propagation(&policy_text)?;
        Ok(GeneratedAgentPolicy {
            policy_text: normalize_cap_generated_policy(&policy_text),
            invocation,
        })
    }
}

fn normalize_guest_memory_mount_propagation(policy_text: &str) -> Result<String> {
    // Pinned genpolicy appends JSON policy_data and ignores mountPropagation
    // for emptyDirs. Correct the platform-owned mounts before signing;
    // leave the Rego source, destination, type and options checks unchanged.
    // The two `logs` mounts exist only when log encryption is enabled (v2
    // layout): absent is fine, present gets the matching propagation fix.
    const SEPARATOR: &str = "\npolicy_data := ";
    let (rules, json_data) = policy_text
        .rsplit_once(SEPARATOR)
        .context("genpolicy output missing final policy_data")?;
    let mut data: Value =
        serde_json::from_str(json_data).context("invalid genpolicy policy_data")?;
    let containers = data
        .get_mut("containers")
        .and_then(Value::as_array_mut)
        .context("genpolicy policy_data missing containers")?;
    for (container_name, volume, destination, propagation, required) in [
        ("web", "state-mount", "/state", "rslave", true),
        ("web", "logs", "/run/enclava-logs", "rslave", false),
        ("attestation-proxy", "state-mount", "/data", "rslave", true),
        ("attestation-proxy", "state-mount", "/state", "rslave", true),
        ("enclava-init", "state-mount", "/state", "rshared", true),
        (
            "enclava-init",
            "tls-state-mount",
            "/state/tls-state",
            "rshared",
            true,
        ),
        (
            "enclava-init",
            "logs",
            "/run/enclava-logs",
            "rshared",
            false,
        ),
    ] {
        let matching = containers
            .iter_mut()
            .filter(|container| {
                container
                    .pointer("/OCI/Annotations/io.kubernetes.cri.container-name")
                    .and_then(Value::as_str)
                    == Some(container_name)
            })
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            bail!("genpolicy platform container missing or duplicated");
        }
        let container = matching.into_iter().next().unwrap();
        let mounts = container
            .pointer_mut("/OCI/Mounts")
            .and_then(Value::as_array_mut)
            .context("genpolicy platform container missing mounts")?;
        let matching = mounts
            .iter_mut()
            .filter(|mount| mount.get("destination").and_then(Value::as_str) == Some(destination))
            .collect::<Vec<_>>();
        if matching.len() != 1 {
            if matching.is_empty() && !required {
                continue;
            }
            bail!("genpolicy platform mount missing or duplicated");
        }
        let mount = matching.into_iter().next().unwrap();
        let source = format!("^/run/kata-containers/sandbox/ephemeral/{volume}$");
        if mount.get("source").and_then(Value::as_str) != Some(source.as_str())
            || mount.get("type_").and_then(Value::as_str) != Some("bind")
            || mount.get("options") != Some(&json!(["rbind", "rprivate", "rw"]))
        {
            bail!("unexpected genpolicy platform memory mount shape");
        }
        mount["options"] = json!(["rbind", propagation, "rw"]);
    }
    Ok(format!(
        "{rules}{SEPARATOR}{}",
        serde_json::to_string_pretty(&data)?
    ))
}

/// The production genpolicy budget (see `GenpolicyConfig::total_budget`).
pub const DEFAULT_GENPOLICY_TOTAL_BUDGET: std::time::Duration = std::time::Duration::from_secs(90);

/// The production concurrency cap (see `GenpolicyConfig::max_concurrent`).
pub const DEFAULT_GENPOLICY_MAX_CONCURRENT: usize = 2;

#[cfg(unix)]
fn new_command(binary: &Path) -> tokio::process::Command {
    let mut command = tokio::process::Command::new(binary);
    // Own process group (tokio::process::Command::process_group): a
    // stalled genpolicy that spawned helpers must be killed as a GROUP on
    // expiry, not leave orphans behind.
    command.process_group(0);
    command
}

#[cfg(not(unix))]
fn new_command(binary: &Path) -> tokio::process::Command {
    tokio::process::Command::new(binary)
}

/// Kill the child's whole process group (the child plus any helpers it
/// spawned). Best effort: failures are logged, never fatal — the budget
/// error is the answer either way.
/// TERminate the child's whole process group via the OS API — no external
/// `kill` executable (the shipped image does not carry one; Devin T1) and
/// no async requirement, so it also works from a Drop guard on any
/// cancellation path. Best effort: failures are logged, never fatal.
fn term_process_group_by_pid(pid: u32) -> bool {
    #[cfg(unix)]
    {
        // Negative pid = the process group; SIGTERM matches the kill(1)
        // default. The direct child is additionally covered by kill_on_drop.
        let result = unsafe { libc::kill(-(pid as i32), libc::SIGTERM) };
        if result != 0 {
            tracing::warn!(
                pid,
                errno = std::io::Error::last_os_error().raw_os_error(),
                "process-group TERM failed; the direct child is still covered by kill_on_drop"
            );
            return false;
        }
        true
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        false
    }
}

/// Maximum child stdout/stderr bytes carried into a log tail
/// (ADDENDUM 2: a fixed small bound).
const OUTPUT_TAIL_MAX_BYTES: usize = 512;

/// Credential byte strings that must never appear in a log tail: the
/// registry auth config handed to the child (the file we wrote for the
/// anonymous attempt, or the service's own REGISTRY_AUTH_FILE for the
/// configured attempt). The pre-existing failure-body path keeps its own
/// separate contract; this redaction governs LOG LINES ONLY.
fn credential_secrets(env: Option<(&Path, &Path)>) -> Vec<Vec<u8>> {
    let mut secrets = Vec::new();
    let mut push_file = |path: &Path| {
        if let Ok(bytes) = fs::read(path) {
            if !bytes.is_empty() {
                secrets.push(bytes);
            }
        }
    };
    match env {
        Some((auth_file, _docker_dir)) => push_file(auth_file),
        None => {
            // The configured attempt inherits the service's own registry
            // credentials from the environment (ghcr auth secret mount).
            if let Ok(value) = std::env::var("REGISTRY_AUTH_FILE") {
                push_file(Path::new(&value));
            } else if let Ok(value) = std::env::var("DOCKER_CONFIG") {
                push_file(&Path::new(&value).join("config.json"));
            }
        }
    }
    secrets
}

/// Extracted credential VALUES from an auth-config document (docker
/// config shape `{"auths":{registry:{"auth":..., "identitytoken":...,
/// "username":..., "password":...}}}`): every string value, plus for each
/// `auth` token its base64-decoded `user:password` pair and the password
/// half alone — a child echoing any of these verbatim (QA F-C) must hit
/// redaction, not just a child echoing the whole file.
fn credential_values(document: &[u8]) -> Vec<Vec<u8>> {
    let mut values = Vec::new();
    let Ok(parsed) = serde_json::from_slice::<Value>(document) else {
        return values;
    };
    fn walk(node: &Value, values: &mut Vec<Vec<u8>>) {
        match node {
            Value::String(s) => {
                let bytes = s.as_bytes();
                if !bytes.is_empty() {
                    values.push(bytes.to_vec());
                }
            }
            Value::Array(items) => items.iter().for_each(|item| walk(item, values)),
            Value::Object(map) => map.values().for_each(|item| walk(item, values)),
            _ => {}
        }
    }
    walk(&parsed, &mut values);
    // Base64 `auth` tokens decode to `user:password`; redact the decoded
    // pair and the password half in addition to the token itself.
    if let Some(auths) = parsed.get("auths").and_then(Value::as_object) {
        use base64::Engine;
        for entry in auths.values() {
            for field in ["auth", "identitytoken", "registrytoken"] {
                let Some(token) = entry.get(field).and_then(Value::as_str) else {
                    continue;
                };
                if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(token) {
                    if !decoded.is_empty() {
                        values.push(decoded.clone());
                        if let Some(colon) = decoded.iter().position(|b| *b == b':') {
                            values.push(decoded[colon + 1..].to_vec());
                        }
                    }
                }
            }
        }
    }
    // No length floor here (Devin): a 3-byte password is still a
    // credential — every string value of the auth document is redacted.
    // The >=4 floor lives only in secret_variants' ENCODING expansion,
    // where it prevents redacting every 2-char hex pair in normal text.
    values
}

/// Common encodings of one secret byte string: raw, hex (lower and upper),
/// base64 (standard and URL-safe), percent-encoding, and JSON string
/// escaping. OUT OF SCOPE, deliberately: double encodings (hex-of-base64
/// and friends) — combinatorial, no demonstrated vector, and genpolicy is
/// a digest-pinned verified binary (QA's context note), so the modeled
/// threat is a buggy/quoting child using one standard encoding.
fn secret_variants(secret: &[u8]) -> Vec<Vec<u8>> {
    use base64::Engine;
    // The raw form is ALWAYS a needle, however short (Devin: short
    // credentials are still credentials); encodings are expanded only
    // for sources of >= 4 bytes so normal short words are not scrubbed
    // from tails by their 2-char hex forms.
    let mut variants = vec![secret.to_vec()];
    if secret.len() >= 4 {
        variants.push(hex::encode(secret).into_bytes());
        variants.push(hex::encode_upper(secret).into_bytes());
        variants.push(
            base64::engine::general_purpose::STANDARD
                .encode(secret)
                .into_bytes(),
        );
        variants.push(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(secret)
                .into_bytes(),
        );
        // Percent-encoding in both hex cases (RFC 3986 uppercase is
        // standard; lazy encoders emit lowercase).
        variants.push(
            secret
                .iter()
                .flat_map(|b| format!("%{b:02X}").into_bytes())
                .collect(),
        );
        variants.push(
            secret
                .iter()
                .flat_map(|b| format!("%{b:02x}").into_bytes())
                .collect(),
        );
    }
    // JSON string escaping with the standard SHORT escapes first
    // (Devin: serializers emit \t/\n/\r/\b/\f before \u00XX;
    // both forms covered) — a tab-containing password must not slip
    // between them.
    let mut json_escaped = Vec::new();
    for &b in secret {
        match b {
            b'"' => json_escaped.extend_from_slice(b"\\\""),
            b'\\' => json_escaped.extend_from_slice(b"\\\\"),
            b'\t' => json_escaped.extend_from_slice(b"\\t"),
            b'\n' => json_escaped.extend_from_slice(b"\\n"),
            b'\r' => json_escaped.extend_from_slice(b"\\r"),
            0x08 => json_escaped.extend_from_slice(b"\\b"),
            0x0C => json_escaped.extend_from_slice(b"\\f"),
            0x20..=0x7E => json_escaped.push(b),
            _ => json_escaped.extend_from_slice(format!("\\u{b:04x}").as_bytes()),
        }
    }
    variants.push(json_escaped);
    variants.sort();
    variants.dedup();
    variants.retain(|variant| variant.len() >= 4 || variant.as_slice() == secret);
    variants
}

/// Every needle the tail redaction must scrub: the credential documents
/// themselves, their extracted values, and the common encodings of each.
fn redaction_needles(secrets: &[Vec<u8>]) -> Vec<Vec<u8>> {
    let mut needles = Vec::new();
    for secret in secrets {
        needles.extend(secret_variants(secret));
        needles.extend(credential_values(secret));
    }
    for value in needles.clone() {
        needles.extend(secret_variants(&value));
    }
    // LONGEST-FIRST (Devin): applying a shorter needle inside a longer
    // one's text first (e.g. a username that prefixes its password)
    // breaks the longer match and leaves readable fragments behind.
    // Longest needles are replaced before their substrings can interfere.
    needles.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
    needles.dedup();
    needles
}

/// Byte-level `haystack[needle] -> replacement` (credential bytes need not
/// be valid UTF-8).
fn replace_bytes(mut haystack: Vec<u8>, needle: &[u8], replacement: &[u8]) -> Vec<u8> {
    if needle.is_empty() {
        return haystack;
    }
    let mut out: Vec<u8> = Vec::with_capacity(haystack.len());
    let mut i = 0;
    while i < haystack.len() {
        if haystack[i..].starts_with(needle) {
            out.extend_from_slice(replacement);
            i += needle.len();
        } else {
            out.push(haystack[i]);
            i += 1;
        }
    }
    haystack.clear();
    haystack.extend_from_slice(&out);
    haystack
}

/// Render a child stream tail for a log line: REDACT-THEN-SLICE — every
/// redaction needle (credential documents, extracted values, and their
/// common encodings) is replaced over the WHOLE captured buffer FIRST,
/// and only then are the last `OUTPUT_TAIL_MAX_BYTES` bytes taken, so a
/// secret straddling the tail boundary can never leak its trailing bytes
/// (QA F-A; the buffer is the already-captured stream, so this stays
/// bounded). Newlines are flattened so the tail stays on one log line.
fn render_output_tail(bytes: &[u8], secrets: &[Vec<u8>]) -> String {
    let needles = redaction_needles(secrets);
    let mut redacted = bytes.to_vec();
    for needle in &needles {
        redacted = replace_bytes(redacted, needle, b"[redacted]");
    }
    let start = redacted.len().saturating_sub(OUTPUT_TAIL_MAX_BYTES);
    String::from_utf8_lossy(&redacted[start..])
        .replace('\r', "\\r")
        .replace('\n', "\\n")
}

/// Drain a piped child stream in its own task so the kill path still gets
/// its bytes: EOF arrives when the TERMed process group closes the pipe,
/// and the bounded grace below keeps a stuck reader from stalling the
/// response.
async fn drain_child_pipe<R: tokio::io::AsyncRead + Unpin + Send + 'static>(
    mut pipe: R,
) -> Vec<u8> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::new();
    let _ = pipe.read_to_end(&mut buf).await;
    buf
}

/// Await an output reader with a small grace; on expiry the tail is
/// logged as empty (never block the response on a helper that somehow
/// kept the pipe open past the group TERM).
async fn collect_child_output(reader: Option<tokio::task::JoinHandle<Vec<u8>>>) -> Vec<u8> {
    match reader {
        None => Vec::new(),
        Some(handle) => match tokio::time::timeout(std::time::Duration::from_secs(2), handle).await
        {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(join_error)) => {
                tracing::warn!(%join_error, "genpolicy output reader task failed");
                Vec::new()
            }
            Err(_) => {
                tracing::warn!(
                    "genpolicy output reader did not finish within the grace window; logging an empty tail"
                );
                Vec::new()
            }
        },
    }
}

/// RAII group guard: whatever cancels the attempt future — the budget, a
/// Ctrl-C drop in the CLI, a panic — TERMinates the child's process group
/// synchronously, so helpers the child spawned cannot outlive the step
/// (Devin T2). Disarmed on successful completion.
struct ProcessGroupGuard {
    pid: Option<u32>,
}

impl ProcessGroupGuard {
    fn disarm(mut self) {
        self.pid = None;
    }
}

impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        if let Some(pid) = self.pid {
            term_process_group_by_pid(pid);
        }
    }
}

async fn kill_process_group_by_pid(pid: Option<u32>, attempt: u8) {
    let Some(pid) = pid else {
        return;
    };
    let _ = attempt;
    term_process_group_by_pid(pid);
}

/// One budgeted, non-blocking genpolicy attempt. INFO logs bracket every
/// invocation (attempt number, auth mode, exit status, duration,
/// stdout/stderr byte counts, and a small REDACTED TAIL of each stream —
/// ADDENDUM 2); on expiry the process group is killed, a WARN line names
/// the attempt, elapsed time, auth mode and image reference (ADDENDUM 1),
/// and the error names the attempt and the elapsed time. The child's
/// pipes are drained by dedicated reader tasks, so the kill path captures
/// its output too: EOF follows the group TERM.
#[allow(clippy::too_many_arguments)]
async fn attempt_genpolicy(
    binary: &Path,
    args: &[String],
    work_dir: &Path,
    env: Option<(&Path, &Path)>,
    deadline: tokio::time::Instant,
    attempt_no: u8,
    auth_mode: &'static str,
    image_ref: &str,
) -> Result<Output> {
    let started = tokio::time::Instant::now();
    tracing::info!(
        attempt = attempt_no,
        auth = auth_mode,
        binary = %binary.display(),
        "genpolicy invocation starting"
    );
    let mut command = new_command(binary);
    command
        .args(args)
        .current_dir(work_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    if let Some((auth_file, docker_dir)) = env {
        command
            .env("REGISTRY_AUTH_FILE", auth_file)
            .env("DOCKER_CONFIG", docker_dir);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("executing genpolicy binary {}", binary.display()))?;
    // Capture the pid BEFORE the wait: the group kill on expiry works from
    // the pid alone. The guard TERMs the group on ANY cancellation
    // (budget, CLI Ctrl-C drop, panic), not only the timeout path.
    let pid = child.id();
    let _guard = ProcessGroupGuard { pid };
    // Reader tasks own the pipes for BOTH paths (ADDENDUM 2): the kill
    // path would lose `wait_with_output`'s capture entirely, and EOF
    // arrives here once the TERMed group closes the pipe.
    let stdout_reader = child
        .stdout
        .take()
        .map(|pipe| tokio::spawn(drain_child_pipe(pipe)));
    let stderr_reader = child
        .stderr
        .take()
        .map(|pipe| tokio::spawn(drain_child_pipe(pipe)));
    let secrets = credential_secrets(env);
    let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
    match tokio::time::timeout(remaining, child.wait()).await {
        Ok(status) => {
            let status = status
                .with_context(|| format!("waiting for genpolicy binary {}", binary.display()))?;
            let stdout = collect_child_output(stdout_reader).await;
            let stderr = collect_child_output(stderr_reader).await;
            tracing::info!(
                attempt = attempt_no,
                auth = auth_mode,
                image_ref = image_ref,
                status = ?status,
                duration_ms = started.elapsed().as_millis() as u64,
                stdout_bytes = stdout.len(),
                stderr_bytes = stderr.len(),
                stdout_tail = %render_output_tail(&stdout, &secrets),
                stderr_tail = %render_output_tail(&stderr, &secrets),
                "genpolicy invocation finished"
            );
            _guard.disarm();
            Ok(Output {
                status,
                stdout,
                stderr,
            })
        }
        Err(_) => {
            kill_process_group_by_pid(pid, attempt_no).await;
            let elapsed = started.elapsed();
            let stdout = collect_child_output(stdout_reader).await;
            let stderr = collect_child_output(stderr_reader).await;
            // ADDENDUM 1: dev runs with RUST_LOG unset render nothing from
            // INFO lines, so the expiry/kill path must ALSO carry a WARN
            // naming the attempt, the elapsed time, the auth mode and the
            // image reference — with the same redacted tails (ADDENDUM 2).
            tracing::warn!(
                attempt = attempt_no,
                auth = auth_mode,
                image_ref = image_ref,
                elapsed_ms = elapsed.as_millis() as u64,
                elapsed = ?elapsed,
                stdout_bytes = stdout.len(),
                stderr_bytes = stderr.len(),
                stdout_tail = %render_output_tail(&stdout, &secrets),
                stderr_tail = %render_output_tail(&stderr, &secrets),
                "genpolicy budget expired; child process group terminated"
            );
            bail!(
                "genpolicy timed out: attempt {attempt_no} (auth: {auth_mode}) exceeded the total budget; elapsed {elapsed:?}"
            );
        }
    }
}

/// Run genpolicy — attempt 1 with the configured environment, attempt 2
/// with the anonymous-registry auth env on non-success — under one TOTAL
/// budget for both attempts, never blocking a runtime worker.
async fn run_genpolicy(
    binary: &Path,
    args: &[String],
    work_dir: &Path,
    total_budget: std::time::Duration,
    permits: Option<&tokio::sync::Semaphore>,
    image_ref: &str,
) -> Result<Output> {
    // The concurrency cap (if configured) is held across BOTH attempts of
    // this step: one request, one generator slot (Devin T5).
    let _permit = match permits {
        Some(semaphore) => Some(
            semaphore
                .acquire()
                .await
                .context("genpolicy concurrency permits closed")?,
        ),
        None => None,
    };
    let deadline = tokio::time::Instant::now() + total_budget;
    let output = attempt_genpolicy(
        binary,
        args,
        work_dir,
        None,
        deadline,
        1,
        "configured",
        image_ref,
    )
    .await?;
    if output.status.success() {
        return Ok(output);
    }

    let docker_dir = work_dir.join("anonymous-registry");
    fs::create_dir_all(&docker_dir).context("creating anonymous registry config directory")?;
    let auth_file = docker_dir.join("config.json");
    fs::write(&auth_file, br#"{"auths":{}}"#).context("writing anonymous registry config")?;
    attempt_genpolicy(
        binary,
        args,
        work_dir,
        Some((&auth_file, &docker_dir)),
        deadline,
        2,
        "anonymous-registry",
        image_ref,
    )
    .await
}

fn prepare_cap_settings_dir(source_dir: &Path, work_dir: &Path) -> Result<PathBuf> {
    let dest_dir = work_dir.join("genpolicy-settings");
    fs::create_dir_all(&dest_dir).context("creating CAP genpolicy settings directory")?;

    let settings_path = source_dir.join("genpolicy-settings.json");
    let raw = fs::read_to_string(&settings_path)
        .with_context(|| format!("reading {}", settings_path.display()))?;
    let mut settings: Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing {}", settings_path.display()))?;
    remove_service_account_token_mounts(&mut settings);
    let rendered =
        serde_json::to_vec_pretty(&settings).context("serializing CAP genpolicy settings")?;
    fs::write(dest_dir.join("genpolicy-settings.json"), rendered)
        .context("writing CAP genpolicy settings")?;

    let source_settings_d = source_dir.join("genpolicy-settings.d");
    if source_settings_d.is_dir() {
        copy_dir_all(&source_settings_d, &dest_dir.join("genpolicy-settings.d"))?;
    }

    Ok(dest_dir)
}

fn copy_dir_all(source: &Path, dest: &Path) -> Result<()> {
    fs::create_dir_all(dest).with_context(|| format!("creating {}", dest.display()))?;
    for entry in fs::read_dir(source).with_context(|| format!("reading {}", source.display()))? {
        let entry = entry?;
        let source_path = entry.path();
        let dest_path = dest.join(entry.file_name());
        if source_path.is_dir() {
            copy_dir_all(&source_path, &dest_path)?;
        } else {
            fs::copy(&source_path, &dest_path).with_context(|| {
                format!(
                    "copying {} to {}",
                    source_path.display(),
                    dest_path.display()
                )
            })?;
        }
    }
    Ok(())
}

fn remove_service_account_token_mounts(settings: &mut Value) {
    const TOKEN_MOUNT_DESTINATIONS: &[&str] = &[
        "/var/run/secrets/kubernetes.io/serviceaccount",
        "/var/run/secrets/azure/tokens",
    ];

    if let Some(mounts) = settings
        .pointer_mut("/other_container/Mounts")
        .and_then(Value::as_array_mut)
    {
        mounts.retain(|mount| {
            !mount
                .get("destination")
                .and_then(Value::as_str)
                .is_some_and(|destination| TOKEN_MOUNT_DESTINATIONS.contains(&destination))
        });
    }

    if let Some(destinations) = settings
        .pointer_mut("/mount_destinations")
        .and_then(Value::as_array_mut)
    {
        destinations.retain(|destination| {
            !destination
                .as_str()
                .is_some_and(|destination| TOKEN_MOUNT_DESTINATIONS.contains(&destination))
        });
    }
}

fn normalize_cap_generated_policy(policy_text: &str) -> String {
    let normalized = normalize_cap_sandbox_pidns(policy_text);
    let normalized = normalize_rootfs_propagation(&normalized);
    let normalized = normalize_cap_storage_mounts(&normalized);
    let normalized = normalize_cap_sandbox_storages(&normalized);
    let normalized = normalize_cap_extra_storages(&normalized);
    // Signed with the exact policy bytes: CAP keeps historical, unmarked and
    // v1 artifacts on their recorded volume layouts during retry and rollback.
    // v2 = bootstrap Memory volumes plus, when log encryption is enabled, a
    // Memory logs mountpoint bind-bound to the encrypted state PVC.
    format!(
        "# enclava-cap-volume-layout: guest-memory-v2\n{}",
        normalize_privileged_caps_placeholder(&normalized)
    )
}

fn normalize_cap_sandbox_pidns(policy_text: &str) -> String {
    const PIDNS_CHECK: &str = "    p_pidns == i_pidns\n";
    const PIDNS_ALLOW: &str = "    allow_cap_sandbox_pidns(p_container, p_pidns, i_pidns)\n";
    const PIDNS_HELPERS: &str = r#"
allow_cap_sandbox_pidns(_p_container, p_pidns, i_pidns) if {
    p_pidns == i_pidns
}

allow_cap_sandbox_pidns(p_container, _p_pidns, i_pidns) if {
    p_container.OCI.Annotations["io.kubernetes.cri.container-type"] == "sandbox"
    i_pidns == false
}
"#;

    if policy_text.contains("allow_cap_sandbox_pidns") || !policy_text.contains(PIDNS_CHECK) {
        return policy_text.to_string();
    }

    let normalized = policy_text.replace(PIDNS_CHECK, PIDNS_ALLOW);
    insert_policy_helper(&normalized, PIDNS_HELPERS)
}

fn normalize_rootfs_propagation(policy_text: &str) -> String {
    const ROOTFS_PRECHECK: &str = "    count(i_linux.RootfsPropagation) == 0\n";
    const ROOTFS_ALLOW: &str = "    allow_cap_rootfs_propagation(i_linux.RootfsPropagation)\n";
    const ROOTFS_HELPER: &str = r#"
allow_cap_rootfs_propagation(rootfs_propagation) if {
    count(rootfs_propagation) == 0
}

allow_cap_rootfs_propagation(rootfs_propagation) if {
    rootfs_propagation == "rshared"
}

allow_cap_rootfs_propagation(rootfs_propagation) if {
    rootfs_propagation == "rslave"
}
"#;

    if !policy_text.contains(ROOTFS_PRECHECK)
        || policy_text.contains("allow_cap_rootfs_propagation")
    {
        return policy_text.to_string();
    }

    let with_allow = policy_text.replace(ROOTFS_PRECHECK, ROOTFS_ALLOW);
    let insert_after = "default AllowRequestsFailingPolicy := false\n";
    if let Some(idx) = with_allow.find(insert_after) {
        let insert_at = idx + insert_after.len();
        let mut patched = String::with_capacity(with_allow.len() + ROOTFS_HELPER.len());
        patched.push_str(&with_allow[..insert_at]);
        patched.push_str(ROOTFS_HELPER);
        patched.push_str(&with_allow[insert_at..]);
        patched
    } else {
        format!("{ROOTFS_HELPER}\n{with_allow}")
    }
}

fn normalize_cap_storage_mounts(policy_text: &str) -> String {
    const MOUNT_OPTIONS_CHECK: &str = "    p_mount.options == i_mount.options\n";
    const MOUNT_OPTIONS_ALLOW: &str = "    allow_cap_mount_options(p_mount, i_mount)\n";
    const STORAGE_FS_GROUP_CHECK: &str = "    p_storage.fs_group       == i_storage.fs_group\n";
    const STORAGE_FS_GROUP_ALLOW: &str = "    allow_cap_storage_fs_group(p_storage, i_storage)\n";
    const STORAGE_OPTIONS_CHECK: &str = "    p_storage.options == i_storage.options\n";
    const STORAGE_OPTIONS_ALLOW: &str = "    allow_cap_storage_options(p_storage, i_storage)\n";
    const STORAGE_HELPERS: &str = r#"
allow_cap_mount_options(p_mount, i_mount) if {
    p_mount.options == i_mount.options
}

allow_cap_mount_options(p_mount, i_mount) if {
    p_mount.type_ == "bind"
    p_mount.source == ""
    p_mount.options == ["rbind", "rprivate", "rw"]
    i_mount.options == ["rbind", "rslave", "rw"]
}

allow_cap_mount_options(p_mount, i_mount) if {
    p_mount.type_ == "bind"
    p_mount.source == ""
    p_mount.options == ["rbind", "rprivate", "ro"]
    i_mount.options == ["rbind", "rslave", "ro"]
}

allow_cap_mount_options(p_mount, i_mount) if {
    p_mount.type_ == "bind"
    p_mount.source == ""
    p_mount.options == ["rbind", "rprivate", "rw"]
    i_mount.options == ["rbind", "rshared", "rw"]
}

allow_cap_storage_fs_group(p_storage, i_storage) if {
    p_storage.fs_group == i_storage.fs_group
}

allow_cap_storage_fs_group(p_storage, i_storage) if {
    p_storage.fs_group == null
    p_storage.options == ["fsgid=10001"]
    i_storage.options == []
    i_storage.fs_group.group_change_policy == 0
    i_storage.fs_group.group_id == 10001
}

allow_cap_storage_options(p_storage, i_storage) if {
    p_storage.options == i_storage.options
}

allow_cap_storage_options(p_storage, i_storage) if {
    p_storage.fs_group == null
    p_storage.options == ["fsgid=10001"]
    i_storage.options == []
    i_storage.fs_group.group_change_policy == 0
    i_storage.fs_group.group_id == 10001
}
"#;

    if policy_text.contains("allow_cap_mount_options")
        || (!policy_text.contains(MOUNT_OPTIONS_CHECK)
            && !policy_text.contains(STORAGE_FS_GROUP_CHECK)
            && !policy_text.contains(STORAGE_OPTIONS_CHECK))
    {
        return policy_text.to_string();
    }

    let normalized = policy_text
        .replace(MOUNT_OPTIONS_CHECK, MOUNT_OPTIONS_ALLOW)
        .replace(STORAGE_FS_GROUP_CHECK, STORAGE_FS_GROUP_ALLOW)
        .replace(STORAGE_OPTIONS_CHECK, STORAGE_OPTIONS_ALLOW);
    insert_policy_helper(&normalized, STORAGE_HELPERS)
}

fn normalize_cap_sandbox_storages(policy_text: &str) -> String {
    const SANDBOX_STORAGE_CHECK: &str = "    i_storage == p_storage\n";
    const SANDBOX_STORAGE_ALLOW: &str = "    allow_cap_sandbox_storage(p_storage, i_storage)\n";
    const SANDBOX_STORAGE_HELPERS: &str = r#"
allow_cap_sandbox_storage(p_storage, i_storage) if {
    i_storage == p_storage
}

allow_cap_sandbox_storage(_p_storage, i_storage) if {
    i_storage.driver == "9p"
    i_storage.driver_options == []
    i_storage.fs_group == null
    i_storage.fstype == "9p"
    i_storage.mount_point == "/run/kata-containers/shared/containers/"
    count(i_storage.options) == 3
    "trans=virtio,version=9p2000.L,cache=mmap" in i_storage.options
    "nodev" in i_storage.options
    "msize=8192" in i_storage.options
    i_storage.shared == false
    i_storage.source == "kataShared"
}
"#;

    if policy_text.contains("allow_cap_sandbox_storage")
        || !policy_text.contains(SANDBOX_STORAGE_CHECK)
    {
        return policy_text.to_string();
    }

    let normalized = policy_text.replace(SANDBOX_STORAGE_CHECK, SANDBOX_STORAGE_ALLOW);
    insert_policy_helper(&normalized, SANDBOX_STORAGE_HELPERS)
}

fn normalize_cap_extra_storages(policy_text: &str) -> String {
    const STORAGE_COUNT_CHECK: &str = "    p_count == i_count - img_pull_count\n";
    const STORAGE_COUNT_ALLOW: &str = r#"    cap_extra_storage_count := count([s | s := i_storages[_]; allow_cap_extra_storage(s, bundle_id, sandbox_id)])
    print("allow_storages: cap_extra_storage_count =", cap_extra_storage_count)
    p_count == i_count - img_pull_count - cap_extra_storage_count
"#;
    const EXTRA_STORAGE_HELPERS: &str = r#"
allow_storage(_p_storages, i_storage, bundle_id, sandbox_id) if {
    allow_cap_extra_storage(i_storage, bundle_id, sandbox_id)
}

allow_cap_extra_storage(i_storage, bundle_id, _sandbox_id) if {
    i_storage.driver == "watchable-bind"
    i_storage.driver_options == []
    i_storage.fs_group == null
    i_storage.fstype == "bind"
    i_storage.options == ["rbind", "rprivate", "ro"]
    i_storage.shared == false

    watchable_prefix := concat("", ["/run/kata-containers/shared/containers/watchable/", bundle_id, "-"])
    source_prefix := concat("", ["/run/kata-containers/shared/containers/", bundle_id, "-"])
    startswith(i_storage.mount_point, watchable_prefix)
    startswith(i_storage.source, source_prefix)
    replace(i_storage.mount_point, "/watchable/", "/") == i_storage.source
}
"#;

    if policy_text.contains("allow_cap_extra_storage") || !policy_text.contains(STORAGE_COUNT_CHECK)
    {
        return policy_text.to_string();
    }

    let normalized = policy_text.replace(STORAGE_COUNT_CHECK, STORAGE_COUNT_ALLOW);
    insert_policy_helper(&normalized, EXTRA_STORAGE_HELPERS)
}

fn insert_policy_helper(policy_text: &str, helper: &str) -> String {
    let insert_after = "default AllowRequestsFailingPolicy := false\n";
    if let Some(idx) = policy_text.find(insert_after) {
        let insert_at = idx + insert_after.len();
        let mut patched = String::with_capacity(policy_text.len() + helper.len());
        patched.push_str(&policy_text[..insert_at]);
        patched.push_str(helper);
        patched.push_str(&policy_text[insert_at..]);
        patched
    } else {
        format!("{helper}\n{policy_text}")
    }
}

fn normalize_privileged_caps_placeholder(policy_text: &str) -> String {
    policy_text.replace("\"CAP_$(privileged_caps)\"", "\"$(privileged_caps)\"")
}

fn render_pod_manifest(
    descriptor: &DeploymentDescriptor,
    log_encryption: Option<&LogEncryptionConfig>,
) -> Result<String> {
    // Duplicate resource names are ambiguous here: shape derivation reads the
    // first `memory` limit while ResourceMap serialization keeps the last, so
    // a duplicated name would render a manifest that disagrees with the
    // derived shape. Reject before any shape decision or manifest output.
    validate_unique_resource_names(descriptor)?;
    let pod_name = format!("{}-0", descriptor.app_name);
    let containers = vec![
        app_container(descriptor, log_encryption),
        attestation_proxy_container(descriptor)?,
        tenant_ingress_container(descriptor)?,
        enclava_init_container(log_encryption)?,
    ];
    let pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": descriptor.namespace,
            "annotations": cap_runtime_annotations(descriptor),
        },
        "spec": {
            "runtimeClassName": descriptor.expected_runtime_class,
            "shareProcessNamespace": true,
            "securityContext": {
                "fsGroup": 10001,
                // genpolicy 4.3.1 (guest_pull) always encodes the default GID 0 in
                // AdditionalGids and refuses generation unless the pod spec can
                // reproduce it in-guest.
                "supplementalGroups": [0, 6],
            },
            "initContainers": [
                enclava_tools_container(log_encryption.is_some())?,
            ],
            "containers": containers,
            "volumes": cap_volumes(descriptor, log_encryption.is_some()),
        },
    });
    serde_yaml::to_string(&pod).context("rendering genpolicy pod manifest")
}

fn cap_runtime_annotations(descriptor: &DeploymentDescriptor) -> BTreeMap<&'static str, String> {
    let mut annotations = BTreeMap::from([
        (
            KATA_RUNTIME_HANDLER_ANNOTATION,
            descriptor.expected_runtime_class.clone(),
        ),
        (
            KATA_KERNEL_PARAMS_ANNOTATION,
            format!(
                "agent.aa_kbc_params=cc_kbc::{} agent.guest_components_rest_api=all",
                trustee_kbs_url()
            ),
        ),
        (
            KATA_HYPERVISOR_CC_INIT_DATA_ANNOTATION,
            "enclava-dynamic-cc-init-data".to_string(),
        ),
        (
            KATA_RUNTIME_CC_INIT_DATA_ANNOTATION,
            "enclava-dynamic-cc-init-data".to_string(),
        ),
    ]);
    if is_small_shape(descriptor) {
        annotations.insert(
            KATA_DEFAULT_MEMORY_ANNOTATION,
            SMALL_VM_BASELINE_MIB.to_string(),
        );
    }
    if let Some(baseline) = vm_vcpu_baseline_annotation(descriptor) {
        annotations.insert(KATA_DEFAULT_VCPUS_ANNOTATION, baseline);
    }
    annotations
}

fn image_ref(repo: &str, digest: &str) -> String {
    format!("{repo}@{digest}")
}

fn storage_ownership_mode(unlock_mode: &str) -> Result<&'static str> {
    match unlock_mode {
        "auto" | "auto-unlock" => Ok("auto-unlock"),
        "password" => Ok("password"),
        other => bail!("descriptor.unlock_mode must be 'auto' or 'password', got '{other}'"),
    }
}

fn enclava_init_image() -> Result<String> {
    let image = match std::env::var("ENCLAVA_INIT_IMAGE") {
        Ok(image) => image,
        // Test default must be a publicly resolvable pinned ref: genpolicy resolves
        // every manifest image over the registry, including in the size-class test.
        Err(_err) if cfg!(test) => format!("{SIZE_CLASS_IMAGE_REPO}@{SIZE_CLASS_IMAGE_DIGEST}"),
        Err(err) => {
            return Err(err).context("ENCLAVA_INIT_IMAGE must be set for CAP genpolicy sidecars")
        }
    };
    if !image.contains("@sha256:") {
        bail!("ENCLAVA_INIT_IMAGE must be digest-pinned with @sha256:");
    }
    Ok(image)
}

fn value_env(name: &str, value: impl Into<String>) -> Value {
    json!({"name": name, "value": value.into()})
}

fn field_env(name: &str, field_path: &str) -> Value {
    json!({
        "name": name,
        "valueFrom": {
            "fieldRef": {
                "fieldPath": field_path,
            },
        },
    })
}

fn kubernetes_service_host() -> String {
    std::env::var("GENPOLICY_KUBERNETES_SERVICE_HOST").unwrap_or_else(|_| "10.43.0.1".to_string())
}

fn kubernetes_service_env() -> Vec<Value> {
    let host = kubernetes_service_host();
    vec![
        value_env("KUBERNETES_SERVICE_PORT", "443"),
        value_env("KUBERNETES_SERVICE_PORT_HTTPS", "443"),
        value_env("KUBERNETES_PORT", format!("tcp://{host}:443")),
        value_env("KUBERNETES_PORT_443_TCP", format!("tcp://{host}:443")),
        value_env("KUBERNETES_PORT_443_TCP_PROTO", "tcp"),
        value_env("KUBERNETES_PORT_443_TCP_PORT", "443"),
        value_env("KUBERNETES_PORT_443_TCP_ADDR", host.clone()),
        value_env("KUBERNETES_SERVICE_HOST", host),
    ]
}

fn with_kubernetes_service_env(mut env: Vec<Value>) -> Vec<Value> {
    // Kubelet still injects the built-in Kubernetes service variables into the
    // Kata CreateContainerRequest even when the pod has enableServiceLinks=false.
    env.extend(kubernetes_service_env());
    env
}

fn mount(name: &str, mount_path: &str, read_only: bool) -> Value {
    json!({
        "name": name,
        "mountPath": mount_path,
        "readOnly": read_only,
    })
}

fn mount_with_propagation(
    name: &str,
    mount_path: &str,
    read_only: bool,
    propagation: &str,
) -> Value {
    json!({
        "name": name,
        "mountPath": mount_path,
        "readOnly": read_only,
        "mountPropagation": propagation,
    })
}

fn caps(drop: &[&str], add: &[&str]) -> Value {
    let mut capabilities = Map::new();
    capabilities.insert(
        "drop".to_string(),
        Value::Array(drop.iter().map(|value| json!(value)).collect()),
    );
    if !add.is_empty() {
        capabilities.insert(
            "add".to_string(),
            Value::Array(add.iter().map(|value| json!(value)).collect()),
        );
    }
    Value::Object(capabilities)
}

fn caps_from_descriptor(capabilities: &Capabilities) -> Value {
    let drop = capabilities.drop.iter().map(|value| json!(value)).collect();
    let add = capabilities
        .add
        .iter()
        .map(|value| json!(value))
        .collect::<Vec<_>>();
    let mut out = Map::new();
    out.insert("drop".to_string(), Value::Array(drop));
    if !add.is_empty() {
        out.insert("add".to_string(), Value::Array(add));
    }
    Value::Object(out)
}

fn security_context(
    run_as_user: u32,
    run_as_group: u32,
    read_only_root_fs: bool,
    allow_privilege_escalation: bool,
    privileged: bool,
    capabilities: Value,
) -> Value {
    json!({
        "runAsUser": run_as_user,
        "runAsGroup": run_as_group,
        "readOnlyRootFilesystem": read_only_root_fs,
        "allowPrivilegeEscalation": allow_privilege_escalation,
        "privileged": privileged,
        "capabilities": capabilities,
    })
}

fn restricted_app_security_context() -> Value {
    security_context(10001, 10001, true, false, false, caps(&["ALL"], &[]))
}

fn descriptor_has_legacy_unset_security(oci: &OciRuntimeSpec) -> bool {
    oci.security_context.run_as_user == 0
        && oci.security_context.run_as_group == 0
        && !oci.security_context.read_only_root_fs
        && !oci.security_context.allow_privilege_escalation
        && !oci.security_context.privileged
        && oci.capabilities.add.is_empty()
        && oci.capabilities.drop.is_empty()
}

fn app_security_context_from_descriptor(oci: &OciRuntimeSpec) -> Value {
    if descriptor_has_legacy_unset_security(oci) {
        return restricted_app_security_context();
    }
    security_context(
        oci.security_context.run_as_user,
        oci.security_context.run_as_group,
        oci.security_context.read_only_root_fs,
        oci.security_context.allow_privilege_escalation,
        oci.security_context.privileged,
        caps_from_descriptor(&oci.capabilities),
    )
}

fn descriptor_uses_startup_fallback(descriptor: &DeploymentDescriptor) -> bool {
    descriptor.oci_runtime_spec.args.is_empty()
}

fn descriptor_uses_platform_managed_ssh_relay(descriptor: &DeploymentDescriptor) -> bool {
    let oci = &descriptor.oci_runtime_spec;
    oci.security_context.run_as_user == 0
        && oci.security_context.run_as_group == 0
        && oci.security_context.read_only_root_fs
        && !oci.security_context.allow_privilege_escalation
        && !oci.security_context.privileged
        && oci
            .capabilities
            .drop
            .iter()
            .any(|cap| cap.eq_ignore_ascii_case("ALL"))
        && oci.capabilities.add.len() == PLATFORM_MANAGED_SSH_RELAY_CAPS.len()
        && PLATFORM_MANAGED_SSH_RELAY_CAPS.iter().all(|required| {
            oci.capabilities
                .add
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case(required))
        })
}

fn descriptor_uses_rootful_sudo(descriptor: &DeploymentDescriptor) -> bool {
    let oci = &descriptor.oci_runtime_spec;
    oci.security_context.run_as_user == 0
        && oci.security_context.run_as_group == 0
        && !oci.security_context.read_only_root_fs
        && oci.security_context.allow_privilege_escalation
        && !oci.security_context.privileged
        && oci
            .capabilities
            .drop
            .iter()
            .any(|cap| cap.eq_ignore_ascii_case("ALL"))
        && oci.capabilities.add.len() == ROOTFUL_SUDO_CAPS.len()
        && ROOTFUL_SUDO_CAPS.iter().all(|required| {
            oci.capabilities
                .add
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case(required))
        })
}

fn descriptor_uses_root_managed_config(descriptor: &DeploymentDescriptor) -> bool {
    descriptor_uses_platform_managed_ssh_relay(descriptor)
        || descriptor_uses_rootful_sudo(descriptor)
}

fn required_config_keys_from_descriptor(descriptor: &DeploymentDescriptor) -> Option<String> {
    if let Some(value) = descriptor
        .oci_runtime_spec
        .env
        .iter()
        .find(|entry| entry.name == "ENCLAVA_REQUIRED_CONFIG_KEYS")
        .and_then(|entry| normalize_required_config_keys(&entry.value))
    {
        return Some(value);
    }
    descriptor
        .oci_runtime_spec
        .command
        .iter()
        .chain(descriptor.oci_runtime_spec.args.iter())
        .find_map(|arg| required_config_keys_from_arg(arg))
}

fn required_config_keys_from_arg(arg: &str) -> Option<String> {
    const PREFIX: &str = "ENCLAVA_REQUIRED_CONFIG_KEYS=";
    let value = arg.split_once(PREFIX)?.1;
    let value = value
        .split(|ch: char| ch.is_ascii_whitespace() || ch == ';')
        .next()
        .unwrap_or_default()
        .trim_matches('"')
        .trim_matches('\'');
    normalize_required_config_keys(value)
}

fn normalize_required_config_keys(value: &str) -> Option<String> {
    let keys = value
        .split(',')
        .map(str::trim)
        .filter(|key| !key.is_empty())
        .collect::<Vec<_>>();
    if keys.is_empty() || keys.iter().any(|key| !is_valid_config_key(key)) {
        return None;
    }
    Some(keys.join(","))
}

fn is_valid_config_key(key: &str) -> bool {
    let mut chars = key.chars();
    match chars.next() {
        Some(ch) if ch.is_ascii_alphabetic() || ch == '_' => {}
        _ => return false,
    }
    chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_')
}

fn resources(
    request_cpu: &str,
    request_memory: &str,
    limit_cpu: &str,
    limit_memory: &str,
) -> Value {
    json!({
        "requests": {
            "cpu": request_cpu,
            "memory": request_memory,
        },
        "limits": {
            "cpu": limit_cpu,
            "memory": limit_memory,
        },
    })
}

/// Mirrors CAP's shape derivation (manifest/shape.rs): an app memory limit
/// below the fixed standard request selects the small workload shape, which
/// renders standard sidecar budgets and a 1536Mi Kata baseline. The generated
/// policy must match the pod CAP actually renders, so the same derivation
/// runs here against the descriptor's signed resource limit.
const STANDARD_APP_REQUEST_MIB: f64 = 512.0;
const SMALL_VM_BASELINE_MIB: &str = "1536";
const KATA_DEFAULT_MEMORY_ANNOTATION: &str = "io.katacontainers.config.hypervisor.default_memory";

const KATA_DEFAULT_VCPUS_ANNOTATION: &str = "io.katacontainers.config.hypervisor.default_vcpus";
const COCO_DEV_RUNTIME_CLASS: &str = "kata-qemu-coco-dev";
/// Kata's baseline vCPU count (`default_vcpus`) for the SNP handler.
const KATA_BASELINE_VCPU_MILLIS: u64 = 1000;
/// The vCPU count whose SNP launch measurement the platform approves.
const APPROVED_SNP_VM_VCPUS: u64 = 4;
/// Summed CPU limit of the platform containers rendered below:
/// attestation-proxy and tenant-ingress (`sidecar_resources`) and enclava-init.
///
/// CAP's own derivation also has a legacy bootstrap layout without the
/// enclava-init sidecar (1000m). That layout is deliberately not mirrored:
/// this manifest always renders enclava-init, so a cluster running CAP with
/// `LEGACY_BOOTSTRAP_SCRIPT` cannot use this genpolicy path at all. Do not
/// add a legacy switch here without rendering the legacy pod as well.
const PLATFORM_CONTAINER_CPU_LIMIT_MILLIS: u64 = 1500;

/// A CPU quantity (`250m`, `1`, `1.5`) in millicores, rounded up to the next
/// whole millicore as Kubernetes rounds a container limit. Mirrors CAP's
/// `manifest::shape::cpu_quantity_millis`.
fn cpu_quantity_millis(value: &str) -> Option<u64> {
    if value.is_empty() || value.trim() != value {
        return None;
    }
    let (number, millis_per_unit) = match value.strip_suffix('m') {
        Some(number) => (number, 1u64),
        None => (value, 1000u64),
    };
    let (whole, fraction) = number.split_once('.').unwrap_or((number, ""));
    if whole.is_empty() && fraction.is_empty() {
        return None;
    }
    if !whole
        .bytes()
        .chain(fraction.bytes())
        .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let whole: u64 = if whole.is_empty() {
        0
    } else {
        whole.parse().ok()?
    };
    let mut millis = whole.checked_mul(millis_per_unit)?;
    let kept_digits = if millis_per_unit == 1000 { 3 } else { 0 };
    let mut scale = millis_per_unit;
    let mut round_up = false;
    for (index, digit) in fraction.bytes().enumerate() {
        let digit = u64::from(digit - b'0');
        if index < kept_digits {
            scale /= 10;
            millis = millis.checked_add(digit * scale)?;
        } else if digit != 0 {
            round_up = true;
        }
    }
    if round_up {
        millis = millis.checked_add(1)?;
    }
    Some(millis)
}

fn app_cpu_limit_millis(descriptor: &DeploymentDescriptor) -> Option<u64> {
    descriptor
        .oci_runtime_spec
        .resources
        .limits
        .iter()
        .find(|entry| entry.name == "cpu")
        .and_then(|entry| cpu_quantity_millis(&entry.value))
}

/// Mirrors CAP's `manifest::shape::vm_vcpu_baseline_annotation`: an app CPU
/// limit that would boot fewer vCPUs than the approved count gets a Kata
/// `default_vcpus` baseline that brings baseline plus pod limits to 3.5,
/// which Kata rounds to four. CAP renders this annotation on the pod, and the
/// generated agent policy rejects any annotation it did not see here, so the
/// derivation must stay identical on both sides.
fn vm_vcpu_baseline_annotation(descriptor: &DeploymentDescriptor) -> Option<String> {
    if descriptor.expected_runtime_class == COCO_DEV_RUNTIME_CLASS {
        return None;
    }
    let pod = PLATFORM_CONTAINER_CPU_LIMIT_MILLIS.checked_add(app_cpu_limit_millis(descriptor)?)?;
    let unpadded_vcpus = KATA_BASELINE_VCPU_MILLIS.checked_add(pod)?.div_ceil(1000);
    if unpadded_vcpus >= APPROVED_SNP_VM_VCPUS {
        return None;
    }
    let millis = APPROVED_SNP_VM_VCPUS * 1000 - 500 - pod;
    let fraction = format!("{:03}", millis % 1000);
    let fraction = fraction.trim_end_matches('0');
    Some(if fraction.is_empty() {
        (millis / 1000).to_string()
    } else {
        format!("{}.{fraction}", millis / 1000)
    })
}

fn memory_limit_mib(value: &str) -> Option<f64> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed != value {
        return None;
    }
    let units = [
        ("TiB", 1024.0 * 1024.0),
        ("Ti", 1024.0 * 1024.0),
        ("GiB", 1024.0),
        ("Gi", 1024.0),
        ("MiB", 1.0),
        ("Mi", 1.0),
    ];
    let (number, multiplier) = units
        .iter()
        .find_map(|(suffix, multiplier)| trimmed.strip_suffix(suffix).map(|n| (n, *multiplier)))?;
    let parsed: f64 = number.parse().ok()?;
    if !parsed.is_finite() || parsed < 0.0 {
        return None;
    }
    Some(parsed * multiplier)
}

fn app_memory_limit_mib(descriptor: &DeploymentDescriptor) -> Option<f64> {
    descriptor
        .oci_runtime_spec
        .resources
        .limits
        .iter()
        .find(|entry| entry.name == "memory")
        .and_then(|entry| memory_limit_mib(&entry.value))
}

fn is_small_shape(descriptor: &DeploymentDescriptor) -> bool {
    app_memory_limit_mib(descriptor)
        .map(|mib| mib < STANDARD_APP_REQUEST_MIB)
        .unwrap_or(false)
}

/// Sidecar budgets must match what CAP renders for the resolved shape: the
/// kata agent policy checks each container's OCI memory limit against this
/// manifest.
fn sidecar_resources() -> Value {
    // Both shapes render the same sidecar budget: the working set is fixed
    // platform overhead that does not shrink with the app, and the
    // attestation proxy's claim path demonstrably exceeds a reduced budget.
    resources("100m", "128Mi", "500m", "256Mi")
}

fn app_container(
    descriptor: &DeploymentDescriptor,
    log_encryption: Option<&LogEncryptionConfig>,
) -> Value {
    let oci = &descriptor.oci_runtime_spec;
    let mut volume_mounts = vec![mount("enclava-tools", "/enclava-tools", true)];
    if descriptor_uses_startup_fallback(descriptor) {
        volume_mounts.push(mount("startup", "/startup", true));
    }
    volume_mounts.push(mount("unlock-socket", "/run/enclava", false));
    volume_mounts.push(mount_with_propagation(
        "state-mount",
        "/state",
        false,
        "HostToContainer",
    ));
    if log_encryption.is_some() {
        volume_mounts.push(mount_with_propagation(
            "logs",
            ENCLAVA_LOG_SPOOL_DIR,
            false,
            "HostToContainer",
        ));
    }
    let mut env_vars: Vec<Value> = oci
        .env
        .iter()
        .map(|env| value_env(&env.name, &env.value))
        .collect();
    if let Some(log_encryption) = log_encryption {
        env_vars.extend([
            value_env("ENCLAVA_LOG_ENCRYPTION_KEY_ID", &log_encryption.key_id),
            value_env("ENCLAVA_LOG_ORG_ID", &descriptor.org_slug),
            value_env("ENCLAVA_LOG_APP_NAME", &descriptor.app_name),
            value_env(
                "ENCLAVA_LOG_DEPLOYMENT_ID",
                descriptor.deploy_id.to_string(),
            ),
            value_env(
                "ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_BASE64URL",
                &log_encryption.public_key_base64url,
            ),
            value_env(
                "ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_SHA256",
                &log_encryption.public_key_sha256,
            ),
            value_env("ENCLAVA_LOG_CONTAINER_NAME", "web"),
            value_env("ENCLAVA_LOG_SPOOL_PATH", log_spool_path(log_encryption)),
        ]);
    }
    let env = with_kubernetes_service_env(env_vars);

    json!({
        "name": "web",
        "image": descriptor.image_ref,
        "command": if oci.command.is_empty() {
            vec![ENCLAVA_WAIT_EXEC_PATH.to_string()]
        } else {
            oci.command.clone()
        },
        "args": oci.args,
        "env": env,
        "ports": oci.ports.iter().map(|port| json!({
            "containerPort": port.container_port,
            "protocol": port.protocol,
        })).collect::<Vec<_>>(),
        "volumeMounts": volume_mounts,
        "securityContext": app_security_context_from_descriptor(oci),
        "resources": ResourcesYaml::from(&oci.resources),
    })
}

fn attestation_proxy_container(descriptor: &DeploymentDescriptor) -> Result<Value> {
    let amd_kds_base_url = amd_kds_base_url();
    attestation_proxy_container_with_amd_kds_base_url(descriptor, amd_kds_base_url.as_deref())
}

fn attestation_proxy_container_with_amd_kds_base_url(
    descriptor: &DeploymentDescriptor,
    amd_kds_base_url: Option<&str>,
) -> Result<Value> {
    let mut env_vars = vec![
        value_env("ATTESTATION_WORKLOAD_CONTAINER", "web"),
        field_env("ATTESTATION_POD_NAME", "metadata.name"),
        field_env("ATTESTATION_POD_NAMESPACE", "metadata.namespace"),
        value_env("ATTESTATION_PROFILE", "coco-sev-snp"),
        value_env(
            "ATTESTATION_RUNTIME_CLASS",
            descriptor.expected_runtime_class.clone(),
        ),
        value_env("ATTESTATION_WORKLOAD_IMAGE", descriptor.image_ref.clone()),
        value_env("ATTESTATION_BIND", "127.0.0.1"),
        value_env("ATTESTATION_TLS_BIND", "0.0.0.0"),
        value_env("ATTESTATION_TLS_PORT", "8443"),
        value_env("TEE_DOMAIN", descriptor.tee_domain.clone()),
    ];
    if !descriptor.api_signing_pubkey.trim().is_empty() {
        env_vars.push(value_env(
            "CAP_API_SIGNING_PUBKEY",
            descriptor.api_signing_pubkey.clone(),
        ));
    }
    env_vars.extend([
        value_env("CAP_CONFIG_DIR", "/state/.enclava/config"),
        value_env("CAP_CONFIG_READY_MARKER", CAP_CONFIG_READY_MARKER),
        value_env(
            "STORAGE_OWNERSHIP_MODE",
            storage_ownership_mode(&descriptor.unlock_mode)?,
        ),
        value_env(
            "INSTANCE_ID",
            format!("{}-{}", descriptor.namespace, descriptor.app_name),
        ),
        value_env("OWNER_CIPHERTEXT_BACKEND", "kbs-resource"),
        value_env("OWNER_SEED_HANDOFF_SLOTS", "app-data"),
        value_env("OWNERSHIP_MOUNT_PATH", "/run/ownership-signal"),
        value_env("KBS_RESOURCE_URL", trustee_kbs_resource_url()),
        value_env("KBS_RESOURCE_CACHE_SECONDS", "300"),
        value_env("KBS_RESOURCE_FAILURE_CACHE_SECONDS", "30"),
        value_env("KBS_FETCH_RETRIES", "120"),
        value_env("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
        value_env("KBS_FETCH_MAX_SLEEP_SECONDS", "10"),
        value_env("KBS_FETCH_REQUEST_TIMEOUT_SECONDS", "10"),
    ]);
    if !descriptor_uses_root_managed_config(descriptor) {
        env_vars.push(value_env("CAP_CONFIG_FILE_GID", CAP_CONFIG_FILE_GID));
    }
    if let Some(url) = amd_kds_base_url {
        env_vars.push(value_env("AMD_KDS_BASE_URL", url));
    }
    if let Some(keys) = required_config_keys_from_descriptor(descriptor) {
        env_vars.push(value_env("CAP_CONFIG_REQUIRED_KEYS", keys));
    }
    env_vars.push(value_env("ENCLAVA_CONTAINER_NAME", "attestation-proxy"));
    env_vars.push(value_env("ENCLAVA_STARTED_DIR", "/run/enclava/containers"));
    env_vars.push(value_env(
        "ENCLAVA_INIT_UNLOCK_SOCKET",
        "/run/enclava-unlock/unlock.sock",
    ));
    if descriptor.independent_verification {
        env_vars.push(value_env(
            "PROOF_TLS_CERT_PATH",
            "/run/enclava/public-tls/certificates/tls.crt",
        ));
    }
    if let Some(cert) = trustee_kbs_ca_cert_pem() {
        env_vars.push(value_env("KBS_RESOURCE_CA_CERT_PEM", cert));
    }

    let mut volume_mounts = vec![
        mount("ownership-signal", "/run/ownership-signal", false),
        mount_with_propagation("state-mount", "/data", false, "HostToContainer"),
        mount_with_propagation("state-mount", "/state", false, "HostToContainer"),
        mount("unlock-socket", "/run/enclava", false),
    ];
    if descriptor.independent_verification {
        volume_mounts.push(mount(
            "verification-material",
            "/etc/enclava-verification",
            true,
        ));
    }
    volume_mounts.push(mount("unlock-channel", "/run/enclava-unlock", false));

    Ok(json!({
        "name": "attestation-proxy",
        "image": image_ref(sidecar_image_repo(&attestation_proxy_image_repo()), &descriptor.sidecars.attestation_proxy_digest),
        "command": ["/attestation-proxy"],
        "ports": [
            {"containerPort": 8081, "name": "attest-http"},
            {"containerPort": 8443, "name": "attestation"},
        ],
        "env": with_kubernetes_service_env(env_vars),
        "volumeMounts": volume_mounts,
        "securityContext": security_context(0, 0, true, false, false, caps(&["ALL"], &["CHOWN", "MKNOD", "SYS_PTRACE"])),
        "resources": sidecar_resources(),
    }))
}

fn tenant_ingress_container(descriptor: &DeploymentDescriptor) -> Result<Value> {
    Ok(tenant_ingress_container_for_mode(
        descriptor,
        tenant_caddy_tls_mode()?,
    ))
}

fn tenant_ingress_container_for_mode(
    descriptor: &DeploymentDescriptor,
    tls_mode: CaddyTlsMode,
) -> Value {
    let tls_port = match tls_mode {
        CaddyTlsMode::Acme | CaddyTlsMode::Dns01Broker => CADDY_ACME_TLS_PORT,
        CaddyTlsMode::Internal => CADDY_INTERNAL_TLS_PORT,
    };
    let args = match tls_mode {
        CaddyTlsMode::Dns01Broker => vec![
            "/bin/sh".to_string(),
            "-ec".to_string(),
            CADDY_DNS01_BROKER_TLS_HANDOFF_SCRIPT.to_string(),
        ],
        CaddyTlsMode::Acme | CaddyTlsMode::Internal => vec![
            "/usr/bin/caddy".to_string(),
            "run".to_string(),
            "--config".to_string(),
            "/etc/caddy/Caddyfile".to_string(),
        ],
    };
    let (volume_mount_point, xdg_data_home, xdg_config_home, home) = (
        CADDY_INTERNAL_RUNTIME_PATH.to_string(),
        CADDY_INTERNAL_RUNTIME_PATH.to_string(),
        format!("{CADDY_INTERNAL_RUNTIME_PATH}/config"),
        CADDY_INTERNAL_RUNTIME_PATH.to_string(),
    );

    json!({
        "name": "tenant-ingress",
        "image": image_ref(sidecar_image_repo(CADDY_INGRESS_IMAGE_REPO), &descriptor.sidecars.caddy_digest),
        "command": [ENCLAVA_WAIT_EXEC_PATH],
        "args": args,
        "ports": [
            {"containerPort": tls_port, "name": "https"},
        ],
        "env": with_kubernetes_service_env(vec![
            field_env("POD_NAME", "metadata.name"),
            field_env("POD_NAMESPACE", "metadata.namespace"),
            value_env("CADDY_SEED_PATH", "/state/caddy/seed"),
            value_env("VOLUME_MOUNT_POINT", volume_mount_point),
            value_env("XDG_DATA_HOME", xdg_data_home),
            value_env("XDG_CONFIG_HOME", xdg_config_home),
            value_env("HOME", home),
            value_env("ENCLAVA_CONTAINER_NAME", "tenant-ingress"),
            value_env("ENCLAVA_STARTED_DIR", "/run/enclava/containers"),
            value_env("ENCLAVA_INIT_READY_FILE", "/run/enclava/init-ready"),
        ]),
        "volumeMounts": [
            mount("tenant-ingress-caddyfile", "/etc/caddy", true),
            mount("enclava-tools", "/enclava-tools", true),
            mount("unlock-socket", "/run/enclava", false),
        ],
        "securityContext": security_context(10002, 10002, false, false, false, caps(&["ALL"], &[])),
        "resources": sidecar_resources(),
    })
}

fn enclava_tools_container(log_enabled: bool) -> Result<Value> {
    let mut volume_mounts = vec![
        mount("enclava-tools", "/work", false),
        mount("unlock-socket", "/run/enclava", false),
    ];
    if log_enabled {
        volume_mounts.push(mount("logs", ENCLAVA_LOG_SPOOL_DIR, false));
    }
    Ok(json!({
        "name": "enclava-tools",
        "image": enclava_init_image()?,
        "command": [
            "/bin/sh",
            "-eu",
            "-c",
            if log_enabled {
                ENCLAVA_TOOLS_INIT_COMMAND
            } else {
                ENCLAVA_TOOLS_INIT_COMMAND_NO_LOGS
            },
        ],
        "volumeMounts": volume_mounts,
        "securityContext": security_context(0, 0, true, false, false, caps(&["ALL"], &[])),
        "resources": resources("10m", "16Mi", "50m", "64Mi"),
    }))
}

fn enclava_init_container(log_encryption: Option<&LogEncryptionConfig>) -> Result<Value> {
    let mut env = vec![
        value_env("ENCLAVA_INIT_CONFIG", "/etc/enclava-init/config.toml"),
        value_env("ENCLAVA_INIT_STAY_ALIVE", "true"),
        value_env("ENCLAVA_INIT_READY_FILE", "/run/enclava/init-ready"),
        value_env("ENCLAVA_INIT_STARTED_DIR", "/run/enclava/containers"),
        value_env("ENCLAVA_INIT_UNLOCK_SOCKET_GID", "10001"),
        value_env(
            "ENCLAVA_INIT_WAIT_FOR_CONTAINERS",
            ENCLAVA_INIT_WAIT_FOR_CONTAINERS,
        ),
        value_env("KBS_FETCH_RETRIES", "120"),
        value_env("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
        value_env("KBS_FETCH_REQUEST_TIMEOUT_SECONDS", "10"),
    ];
    let mut volume_mounts = vec![
        mount_with_propagation("state-mount", "/state", false, "Bidirectional"),
        mount_with_propagation(
            "tls-state-mount",
            "/state/tls-state",
            false,
            "Bidirectional",
        ),
        mount("unlock-socket", "/run/enclava", false),
        mount("unlock-channel", "/run/enclava-unlock", false),
        mount("luks-material", "/run/enclava-luks", false),
        mount("enclava-init-config", "/etc/enclava-init", true),
    ];
    if let Some(log_encryption) = log_encryption {
        env.push(value_env(
            "ENCLAVA_LOG_RELAY_BIND",
            format!("127.0.0.1:{ENCLAVA_LOG_RELAY_PORT}"),
        ));
        env.push(value_env("ENCLAVA_LOG_RELAY_CONTAINER", "web"));
        env.push(value_env(
            "ENCLAVA_LOG_RELAY_SPOOL_PATH",
            log_spool_path(log_encryption),
        ));
        volume_mounts.push(mount_with_propagation(
            "logs",
            ENCLAVA_LOG_SPOOL_DIR,
            false,
            "Bidirectional",
        ));
    }
    Ok(json!({
        "name": "enclava-init",
        "image": enclava_init_image()?,
        "command": ["/usr/local/bin/enclava-init"],
        "readinessProbe": {
            "exec": {
                "command": ["/usr/local/bin/enclava-init", "--probe-ready"],
            },
            "failureThreshold": 6,
            "periodSeconds": 5,
            "successThreshold": 1,
            "timeoutSeconds": 2,
        },
        "env": with_kubernetes_service_env(env),
        "volumeMounts": volume_mounts,
        "volumeDevices": [
            {"name": "state", "devicePath": "/dev/csi0"},
            {"name": "tls-state", "devicePath": "/dev/csi1"},
        ],
        "securityContext": security_context(0, 0, true, true, true, caps(&["ALL"], &["$(privileged_caps)"])),
        "resources": resources("50m", "64Mi", "500m", "512Mi"),
    }))
}

fn cap_volumes(descriptor: &DeploymentDescriptor, log_encryption_enabled: bool) -> Vec<Value> {
    let mut volumes = vec![
        json!({"name": "ownership-signal", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        config_map_volume(
            "tenant-ingress-caddyfile",
            format!("{}-tenant-ingress", descriptor.app_name),
        ),
        // Match CAP's guest-memory helpers/mountpoints; raw PVCs stay disk-backed.
        // Kata does not currently forward these sizeLimit declarations as guest hard bounds.
        json!({"name": "enclava-tools", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}}),
        json!({"name": "unlock-socket", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}}),
        json!({"name": "unlock-channel", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        json!({"name": "luks-material", "emptyDir": {"medium": "Memory", "sizeLimit": "48Mi"}}),
        json!({"name": "state-mount", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        json!({"name": "tls-state-mount", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        config_map_volume(
            "enclava-init-config",
            format!("{}-enclava-init", descriptor.app_name),
        ),
    ];
    if log_encryption_enabled {
        // v2 layout: a 1Mi Memory mountpoint enclava-init rebinds onto the
        // encrypted state PVC; only pre-unlock bootstrap writes land in it.
        volumes.insert(
            0,
            json!({"name": "logs", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        );
    }
    if descriptor_uses_startup_fallback(descriptor) {
        // Index 3 lands after the fixed bootstrap header whether or not the
        // logs volume is present above it.
        volumes.insert(
            3,
            config_map_volume("startup", format!("{}-startup", descriptor.app_name)),
        );
    }
    if descriptor.independent_verification {
        volumes.push(config_map_volume(
            "verification-material",
            format!("{}-verification", descriptor.app_name),
        ));
    }
    volumes
}

fn config_map_volume(name: &str, config_map_name: String) -> Value {
    json!({
        "name": name,
        "configMap": {
            "name": config_map_name,
        },
    })
}

#[derive(Serialize)]
struct ResourcesYaml<'a> {
    requests: ResourceMap<'a>,
    limits: ResourceMap<'a>,
}

impl<'a> From<&'a Resources> for ResourcesYaml<'a> {
    fn from(value: &'a Resources) -> Self {
        Self {
            requests: ResourceMap(&value.requests),
            limits: ResourceMap(&value.limits),
        }
    }
}

struct ResourceMap<'a>(&'a [EnvVar]);

impl Serialize for ResourceMap<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut sorted: Vec<&EnvVar> = self.0.iter().collect();
        sorted.sort_by(|a, b| a.name.cmp(&b.name));
        let mut map = serializer.serialize_map(Some(sorted.len()))?;
        for entry in sorted {
            map.serialize_entry(&entry.name, &entry.value)?;
        }
        map.end()
    }
}

#[allow(dead_code)]
fn _assert_manifest_path(_: &Path) {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::descriptor::{
        tests::fixed_descriptor, Capabilities, EnvVar, Mount, SecurityContext,
    };
    #[allow(unused_imports)]
    use std::process::Command;

    fn synthetic_memory_policy() -> String {
        let mut containers = [
            ("web", vec![("state-mount", "/state")]),
            ("attestation-proxy", vec![("state-mount", "/data"), ("state-mount", "/state")]),
            ("enclava-init", vec![("state-mount", "/state"), ("tls-state-mount", "/state/tls-state")]),
        ].into_iter().map(|(name, mounts)| json!({
            "OCI": {
                "Annotations": {"io.kubernetes.cri.container-name": name},
                "Mounts": mounts.into_iter().map(|(volume, destination)| json!({
                    "destination": destination, "type_": "bind",
                    "source": format!("^/run/kata-containers/sandbox/ephemeral/{volume}$"),
                    "options": ["rbind", "rprivate", "rw"]
                })).chain([json!({"destination": "/enclava-tools", "type_": "bind", "source": "^/run/kata-containers/sandbox/ephemeral/enclava-tools$", "options": ["rbind", "rprivate", "ro"]}),
                    json!({"destination": "/logs", "type_": "bind", "source": "", "options": ["rbind", "rprivate", "rw"]})]).collect::<Vec<_>>()
            }, "storages": [{"driver": "ephemeral", "source": "tmpfs"}]
        })).collect::<Vec<_>>();
        containers.push(json!({"OCI": {"Annotations": {"io.kubernetes.cri.container-name": "unrelated"}, "Mounts": [{"destination": "/state", "type_": "bind", "source": "/unrelated", "options": ["rbind", "rprivate", "rw"]}]}}));
        format!(
            "package agent_policy\nimport future.keywords.if\n\npolicy_data := {}",
            json!({"containers": containers, "common": {"sfprefix": "", "cpath": ""}})
        )
    }

    #[test]
    fn memory_propagation_corrects_only_five_expected_policy_mounts() {
        let policy = synthetic_memory_policy();
        let corrected = normalize_guest_memory_mount_propagation(&policy).unwrap();
        let original: Value =
            serde_json::from_str(policy.rsplit_once("\npolicy_data := ").unwrap().1).unwrap();
        let mut expected = original.clone();
        for (container, mount, propagation) in [
            (0, 0, "rslave"),
            (1, 0, "rslave"),
            (1, 1, "rslave"),
            (2, 0, "rshared"),
            (2, 1, "rshared"),
        ] {
            expected["containers"][container]["OCI"]["Mounts"][mount]["options"] =
                json!(["rbind", propagation, "rw"]);
        }
        let actual: Value =
            serde_json::from_str(corrected.rsplit_once("\npolicy_data := ").unwrap().1).unwrap();
        assert_eq!(actual, expected); // Includes unchanged helper, disk and storages.
        assert_eq!(
            policy.split_once("\npolicy_data := ").unwrap().0,
            corrected.split_once("\npolicy_data := ").unwrap().0
        );
    }

    #[test]
    fn memory_propagation_corrects_v2_log_spool_mounts_when_present() {
        let policy = synthetic_memory_policy();
        let (rules, data) = policy.rsplit_once("\npolicy_data := ").unwrap();
        let mut data: Value = serde_json::from_str(data).unwrap();
        for container in [0, 2] {
            data["containers"][container]["OCI"]["Mounts"]
                .as_array_mut()
                .unwrap()
                .push(json!({
                    "destination": "/run/enclava-logs", "type_": "bind",
                    "source": "^/run/kata-containers/sandbox/ephemeral/logs$",
                    "options": ["rbind", "rprivate", "rw"]
                }));
        }
        let corrected =
            normalize_guest_memory_mount_propagation(&format!("{rules}\npolicy_data := {data}"))
                .unwrap();
        let corrected_data: Value =
            serde_json::from_str(corrected.rsplit_once("\npolicy_data := ").unwrap().1).unwrap();
        for (container, propagation) in [(0, "rslave"), (2, "rshared")] {
            let mounts = corrected_data["containers"][container]["OCI"]["Mounts"]
                .as_array()
                .unwrap();
            let logs = mounts
                .iter()
                .find(|mount| mount["destination"] == "/run/enclava-logs")
                .unwrap();
            assert_eq!(logs["options"], json!(["rbind", propagation, "rw"]));
        }
        // A duplicated optional spool mount still fails closed.
        let mut data: Value =
            serde_json::from_str(policy.rsplit_once("\npolicy_data := ").unwrap().1).unwrap();
        let logs_mount = json!({
            "destination": "/run/enclava-logs", "type_": "bind",
            "source": "^/run/kata-containers/sandbox/ephemeral/logs$",
            "options": ["rbind", "rprivate", "rw"]
        });
        let mounts = data["containers"][0]["OCI"]["Mounts"]
            .as_array_mut()
            .unwrap();
        mounts.push(logs_mount.clone());
        mounts.push(logs_mount);
        assert!(normalize_guest_memory_mount_propagation(&format!(
            "{rules}\npolicy_data := {data}"
        ))
        .is_err());
    }

    #[test]
    fn memory_propagation_rejects_unexpected_generated_shapes() {
        for (field, value) in [
            (
                "source",
                json!("^/run/kata-containers/sandbox/ephemeral/enclava-tools$"),
            ),
            ("source", json!("^/arbitrary/path$")),
            ("destination", json!("/unexpected")),
            ("type_", json!("tmpfs")),
            ("options", json!(["rbind", "rprivate", "ro"])),
            ("options", json!(["rbind", "rshared", "rw"])),
            ("options", json!(["rbind", "rprivate", "rw", "exec"])),
        ] {
            for (container, mount) in [(0, 0), (1, 0), (1, 1), (2, 0), (2, 1)] {
                let policy = synthetic_memory_policy();
                let (rules, data) = policy.rsplit_once("\npolicy_data := ").unwrap();
                let mut data: Value = serde_json::from_str(data).unwrap();
                data["containers"][container]["OCI"]["Mounts"][mount][field] = value.clone();
                assert!(normalize_guest_memory_mount_propagation(&format!(
                    "{rules}\npolicy_data := {data}"
                ))
                .is_err());
            }
        }
        for malformed in [
            "package agent_policy",
            "package agent_policy\npolicy_data := {}",
            "package agent_policy\npolicy_data := {invalid}",
            "package agent_policy\npolicy_data := {\"containers\": {}}",
        ] {
            assert!(normalize_guest_memory_mount_propagation(malformed).is_err());
        }
        let policy = synthetic_memory_policy();
        assert!(normalize_guest_memory_mount_propagation(&format!("{policy}\n")).is_ok());
        assert!(normalize_guest_memory_mount_propagation(&format!("{policy}\njunk")).is_err());
        let (rules, data) = policy.rsplit_once("\npolicy_data := ").unwrap();
        let mut data: Value = serde_json::from_str(data).unwrap();
        data["containers"][0]["OCI"]["Mounts"] = json!({});
        assert!(normalize_guest_memory_mount_propagation(&format!(
            "{rules}\npolicy_data := {data}"
        ))
        .is_err());
        for mutation in 0..4 {
            let policy = synthetic_memory_policy();
            let (rules, data) = policy.rsplit_once("\npolicy_data := ").unwrap();
            let mut data: Value = serde_json::from_str(data).unwrap();
            match mutation {
                0 => {
                    data["containers"].as_array_mut().unwrap().remove(0);
                }
                1 => {
                    let duplicate = data["containers"][0].clone();
                    data["containers"].as_array_mut().unwrap().push(duplicate);
                }
                2 => {
                    data["containers"][0]["OCI"]["Mounts"]
                        .as_array_mut()
                        .unwrap()
                        .remove(0);
                }
                _ => {
                    let duplicate = data["containers"][0]["OCI"]["Mounts"][0].clone();
                    data["containers"][0]["OCI"]["Mounts"]
                        .as_array_mut()
                        .unwrap()
                        .push(duplicate);
                }
            }
            assert!(normalize_guest_memory_mount_propagation(&format!(
                "{rules}\npolicy_data := {data}"
            ))
            .is_err());
        }
    }

    #[test]
    #[ignore = "requires OPA_BIN and KATA_POLICY_RULES; optional GENPOLICY_BIN/SETTINGS runs real generator"]
    fn memory_propagation_runtime_shapes_pass_strict_rego_checks() {
        let opa = std::env::var("OPA_BIN").expect("OPA_BIN is required");
        let fixture = if let Ok(binary) = std::env::var("GENPOLICY_BIN") {
            let settings =
                std::env::var("GENPOLICY_SETTINGS").expect("GENPOLICY_SETTINGS is required");
            let dir = tempfile::tempdir().unwrap();
            let containers = [
                ("web", vec![("state-mount", "/state", "HostToContainer"), ("logs", "/run/enclava-logs", "HostToContainer")]),
                ("attestation-proxy", vec![("state-mount", "/data", "HostToContainer"), ("state-mount", "/state", "HostToContainer")]),
                ("enclava-init", vec![("state-mount", "/state", "Bidirectional"), ("tls-state-mount", "/state/tls-state", "Bidirectional"), ("logs", "/run/enclava-logs", "Bidirectional")]),
            ].into_iter().map(|(name, mounts)| json!({
                "name": name,
                "image": "ghcr.io/enclava-labs/enclava-init@sha256:ede2934373ba3e4414ebe6fb358416046f41c0fb7d70dd4a9d607fa248183073",
                "command": ["/bin/true"],
                "volumeMounts": mounts.into_iter().map(|(name, path, propagation)| mount_with_propagation(name, path, false, propagation)).collect::<Vec<_>>()
            })).collect::<Vec<_>>();
            let manifest = json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "synthetic-mount-check", "namespace": "synthetic"}, "spec": {
                "containers": containers,
                "volumes": [{"name": "state-mount", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}, {"name": "tls-state-mount", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}, {"name": "logs", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}]
            }});
            let path = dir.path().join("synthetic.yaml");
            fs::write(&path, serde_yaml::to_string(&manifest).unwrap()).unwrap();
            let args = vec![
                "-y".to_string(),
                path.display().to_string(),
                "-p".to_string(),
                format!("{settings}/rules.rego"),
                "-j".to_string(),
                settings,
                "-r".to_string(),
                "-u".to_string(),
            ];
            // The fixture pulls only the public test image, without inheriting
            // local registry credentials.
            let auth = dir.path().join("config.json");
            fs::write(&auth, r#"{"auths":{}}"#).unwrap();
            let output = Command::new(&binary)
                .args(&args)
                .current_dir(dir.path())
                .env("DOCKER_CONFIG", dir.path())
                .env("REGISTRY_AUTH_FILE", &auth)
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "synthetic genpolicy failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            String::from_utf8(output.stdout).unwrap()
        } else {
            // Same logs mounts the real generator produces for the fixture
            // above, injected into the synthetic policy_data.
            let policy = synthetic_memory_policy();
            let (rules, data) = policy.rsplit_once("\npolicy_data := ").unwrap();
            let mut data: Value = serde_json::from_str(data).unwrap();
            for container in [0, 2] {
                data["containers"][container]["OCI"]["Mounts"]
                    .as_array_mut()
                    .unwrap()
                    .push(json!({
                        "destination": "/run/enclava-logs", "type_": "bind",
                        "source": "^/run/kata-containers/sandbox/ephemeral/logs$",
                        "options": ["rbind", "rprivate", "rw"]
                    }));
            }
            format!("{rules}\npolicy_data := {data}")
        };
        let corrected = normalize_guest_memory_mount_propagation(&fixture).unwrap();
        // Evaluate the actual pinned check_mount through the production
        // normalizer. This is mount-level evidence, not full CreateContainer.
        let kata_rules = fs::read_to_string(
            std::env::var("KATA_POLICY_RULES").expect("KATA_POLICY_RULES is required"),
        )
        .unwrap();
        let rules = r#"
default allowed := false
allowed if {
    p_mount := policy_data.containers[input.container].OCI.Mounts[input.mount]
    check_mount(p_mount, input.request, "synthetic-bundle", "synthetic-sandbox")
}
"#;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("policy.rego");
        fs::write(
            &path,
            normalize_cap_generated_policy(&format!(
                "{kata_rules}\n{rules}\npolicy_data := input.policy_data"
            )),
        )
        .unwrap();
        let data: Value =
            serde_json::from_str(corrected.rsplit_once("\npolicy_data := ").unwrap().1).unwrap();
        let original: Value =
            serde_json::from_str(fixture.rsplit_once("\npolicy_data := ").unwrap().1).unwrap();
        for (name, destination, propagation) in [
            ("web", "/state", "rslave"),
            ("web", "/run/enclava-logs", "rslave"),
            ("attestation-proxy", "/data", "rslave"),
            ("attestation-proxy", "/state", "rslave"),
            ("enclava-init", "/state", "rshared"),
            ("enclava-init", "/state/tls-state", "rshared"),
            ("enclava-init", "/run/enclava-logs", "rshared"),
        ] {
            let container = data["containers"]
                .as_array()
                .unwrap()
                .iter()
                .position(|container| {
                    container
                        .pointer("/OCI/Annotations/io.kubernetes.cri.container-name")
                        .and_then(Value::as_str)
                        == Some(name)
                })
                .unwrap();
            let mount = data["containers"][container]["OCI"]["Mounts"]
                .as_array()
                .unwrap()
                .iter()
                .position(|mount| mount["destination"] == destination)
                .unwrap();
            let mut request = data["containers"][container]["OCI"]["Mounts"][mount].clone();
            request["options"] = json!(["rbind", propagation, "rw"]);
            request["source"] = json!(request["source"]
                .as_str()
                .unwrap()
                .trim_start_matches('^')
                .trim_end_matches('$'));
            let mut cases = vec![(request.clone(), true)];
            for (field, value) in [
                (
                    "options",
                    json!([
                        "rbind",
                        if propagation == "rslave" {
                            "rshared"
                        } else {
                            "rslave"
                        },
                        "rw"
                    ]),
                ),
                ("options", json!(["rbind", propagation, "ro"])),
                ("options", json!(["rbind", propagation, "rw", "exec"])),
                (
                    "source",
                    json!("/run/kata-containers/sandbox/ephemeral/enclava-tools"),
                ),
                ("source", json!("/arbitrary/path")),
                ("destination", json!("/unexpected")),
                ("type_", json!("tmpfs")),
            ] {
                let mut invalid = request.clone();
                invalid[field] = value;
                cases.push((invalid, false));
            }
            for (request, expected) in cases {
                // Every permitted runtime shape must fail with the original
                // generator's rprivate data, proving the pre-fix mismatch.
                for (policy_data, expected) in
                    std::iter::once((&data, expected)).chain(expected.then_some((&original, false)))
                {
                    let input = dir.path().join("input.json");
                    fs::write(
                    &input,
                    json!({"container": container, "mount": mount, "request": request, "policy_data": policy_data}).to_string(),
                )
                .unwrap();
                    let output = Command::new(&opa)
                        .args(["eval", "--v0-compatible", "--format=raw", "--data"])
                        .arg(&path)
                        .arg("--input")
                        .arg(&input)
                        .arg("data.agent_policy.allowed")
                        .output()
                        .unwrap();
                    assert!(
                        output.status.success(),
                        "{} {}",
                        String::from_utf8_lossy(&output.stderr),
                        String::from_utf8_lossy(&output.stdout)
                    );
                    assert_eq!(
                        String::from_utf8(output.stdout).unwrap().trim(),
                        expected.to_string()
                    );
                }
            }
        }
    }
    #[test]
    #[ignore = "requires OPA_BIN; GENPOLICY_BIN/GENPOLICY_SETTINGS run the real generator"]
    fn guest_pull_storage_matches_literal_root_path() {
        // Regression: kata 4.3.1 guest-pull sends image_guest_pull storages
        // whose mount_point is the literal /run/kata-containers/<id>/rootfs.
        // policy_data.common.root_path must stay literal so
        // `expect_root_path == i_storage.mount_point` holds; the removed
        // overlay regex rewrite made this check unsatisfiable.
        let opa = std::env::var("OPA_BIN").expect("OPA_BIN is required");
        let binary = std::env::var("GENPOLICY_BIN").expect("GENPOLICY_BIN is required");
        let settings = std::env::var("GENPOLICY_SETTINGS").expect("GENPOLICY_SETTINGS is required");
        let dir = tempfile::tempdir().unwrap();
        let containers = [
            ("web", vec![("state-mount", "/state", "HostToContainer")]),
            (
                "attestation-proxy",
                vec![
                    ("state-mount", "/data", "HostToContainer"),
                    ("state-mount", "/state", "HostToContainer"),
                ],
            ),
            (
                "enclava-init",
                vec![
                    ("state-mount", "/state", "Bidirectional"),
                    ("tls-state-mount", "/state/tls-state", "Bidirectional"),
                ],
            ),
        ]
        .into_iter()
        .map(|(name, mounts)| {
            json!({
                "name": name,
                "image": "ghcr.io/enclava-labs/enclava-init@sha256:ede2934373ba3e4414ebe6fb358416046f41c0fb7d70dd4a9d607fa248183073",
                "command": ["/bin/true"],
                "volumeMounts": mounts.into_iter().map(|(name, path, propagation)| mount_with_propagation(name, path, false, propagation)).collect::<Vec<_>>()
            })
        })
        .collect::<Vec<_>>();
        let manifest = json!({"apiVersion": "v1", "kind": "Pod", "metadata": {"name": "guest-pull-check", "namespace": "synthetic"}, "spec": {
            "containers": containers,
            "volumes": [{"name": "state-mount", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}, {"name": "tls-state-mount", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}]
        }});
        let path = dir.path().join("synthetic.yaml");
        fs::write(&path, serde_yaml::to_string(&manifest).unwrap()).unwrap();
        let args = vec![
            "-y".to_string(),
            path.display().to_string(),
            "-p".to_string(),
            format!("{settings}/rules.rego"),
            "-j".to_string(),
            settings,
            "-r".to_string(),
            "-u".to_string(),
            "-s".to_string(),
        ];
        let auth = dir.path().join("config.json");
        fs::write(&auth, r#"{"auths":{}}"#).unwrap();
        let output = Command::new(&binary)
            .args(&args)
            .current_dir(dir.path())
            .env("DOCKER_CONFIG", dir.path())
            .env("REGISTRY_AUTH_FILE", &auth)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "synthetic genpolicy failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let fixture = String::from_utf8(output.stdout).unwrap();
        let corrected = normalize_guest_memory_mount_propagation(&fixture).unwrap();
        let policy_text = normalize_cap_generated_policy(&corrected);
        let data: Value =
            serde_json::from_str(policy_text.rsplit_once("\npolicy_data := ").unwrap().1).unwrap();
        assert_eq!(
            data["common"]["root_path"],
            json!("/run/kata-containers/$(bundle-id)/rootfs"),
            "common.root_path must stay the literal template for guest-pull storage checks"
        );
        let p_container = data["containers"]
            .as_array()
            .unwrap()
            .iter()
            .find(|container| {
                container
                    .pointer("/OCI/Annotations/io.kubernetes.cri.container-type")
                    .and_then(Value::as_str)
                    == Some("sandbox")
            })
            .unwrap()
            .clone();
        let bundle_id = "d6131bce165819e670253d2cecdad00fbf00fa411467c5e8562188c2dbeefb59";
        // Captured live image_guest_pull storage from the denied 4.3.1
        // CreateContainerRequest (source "pause", literal rootfs path).
        let i_storage = json!({
            "driver": "image_guest_pull", "driver_options": [], "fs_group": null,
            "fstype": "overlay",
            "mount_point": format!("/run/kata-containers/{bundle_id}/rootfs"),
            "options": [], "shared": false, "source": "pause"
        });
        let mut wrong_storage = i_storage.clone();
        wrong_storage["mount_point"] = json!(format!(
            "/run/kata-containers/shared/containers/{bundle_id}/rootfs"
        ));
        let mut other_storage = i_storage.clone();
        other_storage["mount_point"] = json!("/run/kata-containers/other-id/rootfs");
        let rules = r#"
default allowed := false
allowed if {
    allow_storage(input.p_container, input.i_storage, input.bundle_id, input.sandbox_id)
}
"#;
        let policy = format!(
            "{}\n{rules}\npolicy_data := {}",
            policy_text.rsplit_once("\npolicy_data := ").unwrap().0,
            data
        );
        let path = dir.path().join("policy.rego");
        fs::write(&path, &policy).unwrap();
        for (storage, expected) in [
            (&i_storage, true),
            (&wrong_storage, false),
            (&other_storage, false),
        ] {
            let input = dir.path().join("input.json");
            fs::write(
                &input,
                json!({
                    "p_container": p_container, "i_storage": storage,
                    "bundle_id": bundle_id, "sandbox_id": bundle_id,
                })
                .to_string(),
            )
            .unwrap();
            let output = Command::new(&opa)
                .args(["eval", "--v0-compatible", "--format=raw", "--data"])
                .arg(&path)
                .arg("--input")
                .arg(&input)
                .arg("data.agent_policy.allowed")
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{} {}",
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            );
            assert_eq!(
                String::from_utf8(output.stdout).unwrap().trim(),
                expected.to_string()
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn public_registry_pull_retries_without_rejected_credentials() {
        // (d3) the anonymous-registry retry path still works: the first
        // attempt fails fast, the second succeeds with the anonymous
        // config — now under the budgeted async runner.
        use std::os::unix::fs::PermissionsExt;

        let work = tempfile::tempdir().unwrap();
        let binary = work.path().join("fake-genpolicy");
        fs::write(
            &binary,
            r#"#!/bin/sh
case "$REGISTRY_AUTH_FILE" in
  */anonymous-registry/config.json)
    test "$(cat "$REGISTRY_AUTH_FILE")" = '{"auths":{}}'
    test "$DOCKER_CONFIG" = "$(dirname "$REGISTRY_AUTH_FILE")"
    printf 'anonymous policy'
    exit 0
    ;;
esac
echo registry client failed >&2
exit 101
"#,
        )
        .unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();

        let output = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                run_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    std::time::Duration::from_secs(30),
                    None,
                    "test://workload-image",
                )
                .await
            })
            .unwrap();

        assert!(output.status.success());
        assert_eq!(output.stdout, b"anonymous policy");
    }

    fn env_entry<'a>(container: &'a Value, name: &str) -> &'a Value {
        container
            .pointer("/env")
            .and_then(Value::as_array)
            .expect("container env is rendered")
            .iter()
            .find(|entry| entry.pointer("/name") == Some(&json!(name)))
            .unwrap_or_else(|| panic!("{name} env is rendered"))
    }

    fn env_value<'a>(container: &'a Value, name: &str) -> Option<&'a Value> {
        env_entry(container, name).pointer("/value")
    }

    #[test]
    fn bootstrap_volume_backing_matches_cap_with_conditional_log_spool() {
        for logs_enabled in [false, true] {
            let volumes = cap_volumes(&fixed_descriptor(), logs_enabled);
            for (name, size) in [
                ("enclava-tools", "16Mi"),
                ("state-mount", "1Mi"),
                ("tls-state-mount", "1Mi"),
            ] {
                let volume = volumes.iter().find(|v| v["name"] == name).unwrap();
                assert_eq!(
                    volume["emptyDir"],
                    json!({"medium": "Memory", "sizeLimit": size})
                );
            }
            let logs = volumes.iter().find(|v| v["name"] == "logs");
            match (logs_enabled, logs) {
                (true, Some(volume)) => assert_eq!(
                    volume["emptyDir"],
                    json!({"medium": "Memory", "sizeLimit": "1Mi"})
                ),
                (false, None) => {}
                _ => panic!("logs volume presence must follow log encryption"),
            }
        }
    }

    #[test]
    fn generated_policy_marks_the_volume_layout_before_hashing() {
        let policy = "package agent_policy\n";
        assert_eq!(
            normalize_cap_generated_policy(policy),
            "# enclava-cap-volume-layout: guest-memory-v2\npackage agent_policy\n"
        );
    }

    #[test]
    fn invocation_pins_binary_settings_and_manifest_input() {
        let config = GenpolicyConfig {
            binary: PathBuf::from("/opt/kata/bin/genpolicy"),
            version_pin: "kata-containers-3.12.0".to_string(),
            rules_path: PathBuf::from("/etc/enclava/genpolicy/rules.rego"),
            settings_dir: Some(PathBuf::from("/etc/enclava/genpolicy")),
            total_budget: std::time::Duration::from_secs(30),
            max_concurrent: 2,
        };
        let invocation = config.build_invocation(&fixed_descriptor()).unwrap();

        assert_eq!(invocation.binary, PathBuf::from("/opt/kata/bin/genpolicy"));
        assert_eq!(
            invocation.args,
            vec![
                "-y".to_string(),
                "pod.yaml".to_string(),
                "-p".to_string(),
                "/etc/enclava/genpolicy/rules.rego".to_string(),
                "-r".to_string(),
                "-j".to_string(),
                "/etc/enclava/genpolicy".to_string()
            ]
        );
        assert_eq!(invocation.version_pin, "kata-containers-3.12.0");
        assert!(invocation
            .manifest_yaml
            .contains("runtimeClassName: kata-qemu-snp"));
        assert!(invocation.manifest_yaml.contains("name: demo-0"));
        assert!(invocation.manifest_yaml.contains("initContainers:"));
        assert!(invocation
            .manifest_yaml
            .contains("io.containerd.cri.runtime-handler: kata-qemu-snp"));
        assert!(invocation.manifest_yaml.contains(
            "io.katacontainers.config.hypervisor.kernel_params: agent.aa_kbc_params=cc_kbc::http://kbs-service.trustee-operator-system.svc.cluster.local:8080 agent.guest_components_rest_api=all"
        ));
        assert!(invocation.manifest_yaml.contains(
            "io.katacontainers.config.hypervisor.cc_init_data: enclava-dynamic-cc-init-data"
        ));
        assert!(invocation.manifest_yaml.contains(
            "io.katacontainers.config.runtime.cc_init_data: enclava-dynamic-cc-init-data"
        ));
        assert!(!invocation.manifest_yaml.contains("serviceAccountName:"));
        assert!(!invocation
            .manifest_yaml
            .contains("automountServiceAccountToken"));
        assert!(!invocation.manifest_yaml.contains("enableServiceLinks"));
        assert!(invocation
            .manifest_yaml
            .contains("shareProcessNamespace: true"));
        assert!(invocation
            .manifest_yaml
            .contains("mountPropagation: HostToContainer"));
        assert!(invocation
            .manifest_yaml
            .contains("mountPropagation: Bidirectional"));
        assert!(invocation.manifest_yaml.contains("fsGroup: 10001"));
        assert!(invocation.manifest_yaml.contains("supplementalGroups:"));
        assert!(!invocation.manifest_yaml.contains("defaultMode"));
        assert!(invocation
            .manifest_yaml
            .contains("name: KUBERNETES_SERVICE_HOST"));
        assert!(invocation.manifest_yaml.contains("value: 10.43.0.1"));
        assert!(invocation
            .manifest_yaml
            .contains("name: STORAGE_OWNERSHIP_MODE"));
        assert!(invocation.manifest_yaml.contains("value: password"));
        assert!(invocation.manifest_yaml.contains("name: ATTESTATION_BIND"));
        assert!(invocation.manifest_yaml.contains("value: 127.0.0.1"));
        assert!(invocation
            .manifest_yaml
            .contains("name: ATTESTATION_TLS_BIND"));
        assert!(invocation.manifest_yaml.contains("value: 0.0.0.0"));
        assert!(invocation.manifest_yaml.contains("name: KBS_RESOURCE_URL"));
        assert!(invocation.manifest_yaml.contains(
            "value: http://kbs-service.trustee-operator-system.svc.cluster.local:8080/kbs/v0/resource"
        ));
        assert!(invocation
            .manifest_yaml
            .contains("name: ENCLAVA_INIT_UNLOCK_SOCKET"));
        assert!(invocation
            .manifest_yaml
            .contains("value: /run/enclava-unlock/unlock.sock"));
        assert!(invocation.manifest_yaml.contains("name: enclava-tools"));
        assert!(invocation
            .manifest_yaml
            .contains("cp /usr/local/bin/enclava-wait-exec /work/enclava-wait-exec"));
        assert!(invocation.manifest_yaml.contains("- -eu"));
        assert!(invocation
            .manifest_yaml
            .contains("install -d -m 02770 -o 0 -g 10001 /run/enclava/containers"));
        assert!(invocation.manifest_yaml.contains("not-ready"));
        assert!(invocation.manifest_yaml.contains("/run/enclava/init-ready"));
        assert!(invocation
            .manifest_yaml
            .contains("chmod 0644 /run/enclava/init-ready"));
        assert!(invocation.manifest_yaml.contains("mountPath: /work"));
        assert!(invocation.manifest_yaml.contains("mountPath: /run/enclava"));
        assert!(invocation.manifest_yaml.contains("name: unlock-channel"));
        assert!(invocation
            .manifest_yaml
            .contains("mountPath: /run/enclava-unlock"));
        assert!(invocation.manifest_yaml.contains("name: luks-material"));
        assert!(invocation
            .manifest_yaml
            .contains("mountPath: /run/enclava-luks"));
        assert!(invocation.manifest_yaml.contains("name: CADDY_SEED_PATH"));
        assert!(invocation
            .manifest_yaml
            .contains("value: /state/caddy/seed"));
        assert!(!invocation
            .manifest_yaml
            .contains("value: /run/enclava/seeds/caddy/seed"));
        assert!(invocation
            .manifest_yaml
            .contains("name: CAP_API_SIGNING_PUBKEY"));
        assert!(invocation
            .manifest_yaml
            .contains("value: test-api-signing-pubkey"));
        assert!(invocation
            .manifest_yaml
            .contains("name: ENCLAVA_INIT_UNLOCK_SOCKET_GID"));
        assert!(invocation.manifest_yaml.contains("value: '10001'"));
        assert!(invocation
            .manifest_yaml
            .contains("image: ghcr.io/enclava-labs/demo@sha256:aaaa"));
        assert!(invocation.manifest_yaml.contains(&format!(
            "image: {}@sha256:1111",
            sidecar_image_repo(DEFAULT_ATTESTATION_PROXY_IMAGE_REPO)
        )));
        assert!(invocation.manifest_yaml.contains(&format!(
            "image: {}@sha256:2222",
            sidecar_image_repo(CADDY_INGRESS_IMAGE_REPO)
        )));
        assert!(!invocation.manifest_yaml.contains("ghcr.io/enclava-ai/"));
        assert!(invocation
            .manifest_yaml
            .contains("- /enclava-tools/enclava-wait-exec"));
        assert!(!invocation
            .manifest_yaml
            .contains("- /usr/local/bin/enclava-wait-exec"));
        assert!(invocation.manifest_yaml.contains("$(privileged_caps)"));
        assert!(invocation.manifest_yaml.contains("readinessProbe:"));
        assert!(invocation.manifest_yaml.contains("--probe-ready"));
        assert!(invocation.manifest_yaml.contains("name: XDG_CONFIG_HOME"));
        assert!(invocation
            .manifest_yaml
            .contains("value: /run/enclava/caddy-runtime/config"));
        assert!(invocation.manifest_yaml.contains("containerPort: 10443"));
        assert!(invocation.manifest_yaml.contains("- name: A"));
        assert!(invocation.manifest_yaml.contains("value: '1'"));
        assert!(invocation.manifest_yaml.contains("mountPath: /data"));
        assert!(invocation.manifest_yaml.contains("name: state-mount"));
    }

    fn small_descriptor() -> DeploymentDescriptor {
        let mut descriptor = fixed_descriptor();
        descriptor.oci_runtime_spec.resources = Resources {
            requests: vec![
                EnvVar {
                    name: "cpu".to_string(),
                    value: "250m".to_string(),
                },
                EnvVar {
                    name: "memory".to_string(),
                    value: "128Mi".to_string(),
                },
            ],
            limits: vec![
                EnvVar {
                    name: "cpu".to_string(),
                    value: "1".to_string(),
                },
                EnvVar {
                    name: "memory".to_string(),
                    value: "128Mi".to_string(),
                },
            ],
        };
        descriptor.expected_runtime_class = "kata-qemu-snp-small".to_string();
        descriptor
    }

    #[test]
    fn small_shape_manifest_matches_cap_rendering() {
        let config = GenpolicyConfig {
            binary: PathBuf::from("/opt/kata/bin/genpolicy"),
            version_pin: "kata-containers-3.12.0".to_string(),
            rules_path: PathBuf::from("/etc/enclava/genpolicy/rules.rego"),
            settings_dir: Some(PathBuf::from("/etc/enclava/genpolicy")),
            total_budget: std::time::Duration::from_secs(30),
            max_concurrent: 2,
        };
        let descriptor = small_descriptor();
        assert!(is_small_shape(&descriptor));
        let invocation = config.build_invocation(&descriptor).unwrap();
        let yaml = &invocation.manifest_yaml;

        // The signed class flows through every runtime-class surface.
        assert!(yaml.contains("runtimeClassName: kata-qemu-snp-small"));
        assert!(yaml.contains("io.containerd.cri.runtime-handler: kata-qemu-snp-small"));
        assert!(!yaml.contains("runtime-handler: kata-qemu-snp\n"));
        // Kata baseline and sidecar budgets match CAP's small shape: the
        // 1536Mi baseline and standard sidecar budgets.
        assert!(yaml.contains("io.katacontainers.config.hypervisor.default_memory: '1536'"));
        assert!(yaml.contains("memory: 256Mi"));
        assert!(yaml.contains("name: ATTESTATION_RUNTIME_CLASS"));
        assert!(yaml.contains("value: kata-qemu-snp-small"));
    }

    #[test]
    fn standard_shape_manifest_keeps_existing_rendering() {
        let descriptor = fixed_descriptor();
        assert!(!is_small_shape(&descriptor));
        // An explicit >=512Mi limit also stays standard.
        let mut big = small_descriptor();
        big.oci_runtime_spec.resources.limits[1].value = "1Gi".to_string();
        big.expected_runtime_class = "kata-qemu-snp".to_string();
        assert!(!is_small_shape(&big));
        let annotations = cap_runtime_annotations(&big);
        assert!(!annotations.contains_key(KATA_DEFAULT_MEMORY_ANNOTATION));
        let container = attestation_proxy_container(&big).unwrap();
        let yaml = serde_yaml::to_string(&container).unwrap();
        assert!(yaml.contains("memory: 256Mi"));
    }

    fn descriptor_with_cpu_limit(cpu: &str) -> DeploymentDescriptor {
        let mut descriptor = small_descriptor();
        descriptor.oci_runtime_spec.resources.limits[0].value = cpu.to_string();
        descriptor.oci_runtime_spec.resources.limits[1].value = "512Mi".to_string();
        descriptor.expected_runtime_class = "kata-qemu-snp".to_string();
        descriptor
    }

    #[test]
    fn low_cpu_manifest_carries_cap_vcpu_baseline_annotation() {
        // cap#392: CAP pads a low-CPU pod to the approved vCPU count with the
        // Kata default_vcpus annotation. The agent policy rejects annotations
        // missing from this manifest, so it must carry the same key and value.
        for (cpu, baseline) in [
            ("0.5", "1.5"),
            ("500m", "1.5"),
            ("250m", "1.75"),
            ("100m", "1.9"),
            ("1m", "1.999"),
        ] {
            let descriptor = descriptor_with_cpu_limit(cpu);
            let annotations = cap_runtime_annotations(&descriptor);
            assert_eq!(
                annotations
                    .get(KATA_DEFAULT_VCPUS_ANNOTATION)
                    .map(String::as_str),
                Some(baseline),
                "cpu={cpu}"
            );
        }

        let config = GenpolicyConfig {
            binary: PathBuf::from("/opt/kata/bin/genpolicy"),
            version_pin: "kata-containers-3.12.0".to_string(),
            rules_path: PathBuf::from("/etc/enclava/genpolicy/rules.rego"),
            settings_dir: Some(PathBuf::from("/etc/enclava/genpolicy")),
            total_budget: std::time::Duration::from_secs(30),
            max_concurrent: 2,
        };
        let invocation = config
            .build_invocation(&descriptor_with_cpu_limit("100m"))
            .unwrap();
        assert!(
            invocation
                .manifest_yaml
                .contains("io.katacontainers.config.hypervisor.default_vcpus: '1.9'"),
            "{}",
            invocation.manifest_yaml
        );
    }

    /// CAP renders the annotation on the real pod and checks its own
    /// implementation against the same vector file
    /// (`crates/enclava-engine/tests/fixtures/` in enclava-labs/cap). The
    /// two copies are kept byte-identical, so a one-sided change to the
    /// arithmetic fails here instead of at deploy time.
    #[test]
    fn vcpu_baseline_annotation_matches_cap_golden_vectors() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../fixtures/cap-vm-vcpu-baseline-vectors.json"
        ))
        .expect("golden vector fixture is valid JSON");
        let vectors = fixture["vectors"].as_array().expect("vectors array");
        assert!(!vectors.is_empty());
        for vector in vectors {
            let cpu_limit = vector["cpu_limit"].as_str().expect("cpu_limit string");
            let expected = vector["default_vcpus"].as_str();
            let annotations = cap_runtime_annotations(&descriptor_with_cpu_limit(cpu_limit));
            assert_eq!(
                annotations
                    .get(KATA_DEFAULT_VCPUS_ANNOTATION)
                    .map(String::as_str),
                expected,
                "cpu_limit={cpu_limit}"
            );
        }
    }

    #[test]
    fn standard_cpu_manifest_keeps_existing_annotations() {
        // Limits the runtime baseline already sizes to the approved count,
        // limits above it, unparseable limits and the unmeasured dev class
        // all render exactly as before.
        for cpu in ["501m", "1", "1.5", "2", "bogus"] {
            let annotations = cap_runtime_annotations(&descriptor_with_cpu_limit(cpu));
            assert!(
                !annotations.contains_key(KATA_DEFAULT_VCPUS_ANNOTATION),
                "cpu={cpu}"
            );
        }
        assert!(!cap_runtime_annotations(&fixed_descriptor())
            .contains_key(KATA_DEFAULT_VCPUS_ANNOTATION));
        let mut dev = descriptor_with_cpu_limit("100m");
        dev.expected_runtime_class = COCO_DEV_RUNTIME_CLASS.to_string();
        assert!(!cap_runtime_annotations(&dev).contains_key(KATA_DEFAULT_VCPUS_ANNOTATION));
    }

    fn duplicate_limits_descriptor() -> DeploymentDescriptor {
        // Two `memory` limits: first-match shape derivation would read 1Gi
        // (standard) while ResourceMap serialization keeps 128Mi — the exact
        // ambiguity the validation must reject rather than resolve.
        let mut descriptor = small_descriptor();
        descriptor.oci_runtime_spec.resources.limits = vec![
            EnvVar {
                name: "memory".to_string(),
                value: "1Gi".to_string(),
            },
            EnvVar {
                name: "memory".to_string(),
                value: "128Mi".to_string(),
            },
        ];
        descriptor
    }

    #[test]
    fn duplicate_memory_limits_are_rejected_before_rendering() {
        let config = GenpolicyConfig {
            binary: PathBuf::from("/opt/kata/bin/genpolicy"),
            version_pin: "kata-containers-3.12.0".to_string(),
            rules_path: PathBuf::from("/etc/enclava/genpolicy/rules.rego"),
            settings_dir: None,
            total_budget: std::time::Duration::from_secs(30),
            max_concurrent: 2,
        };
        let descriptor = duplicate_limits_descriptor();
        let err = config.build_invocation(&descriptor).unwrap_err();
        assert!(
            err.to_string()
                .contains("resources.limits contains duplicate resource name 'memory'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn duplicate_resource_names_are_rejected_in_requests_and_limits() {
        // Any duplicated name in either list is ambiguous, not just `memory`.
        let mut descriptor = fixed_descriptor();
        descriptor.oci_runtime_spec.resources.requests = vec![
            EnvVar {
                name: "cpu".to_string(),
                value: "250m".to_string(),
            },
            EnvVar {
                name: "cpu".to_string(),
                value: "500m".to_string(),
            },
        ];
        let err = render_pod_manifest(&descriptor, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("resources.requests contains duplicate resource name 'cpu'"),
            "unexpected error: {err}"
        );

        let mut descriptor = fixed_descriptor();
        descriptor.oci_runtime_spec.resources.limits = vec![
            EnvVar {
                name: "ephemeral-storage".to_string(),
                value: "1Gi".to_string(),
            },
            EnvVar {
                name: "ephemeral-storage".to_string(),
                value: "2Gi".to_string(),
            },
        ];
        let err = render_pod_manifest(&descriptor, None).unwrap_err();
        assert!(
            err.to_string()
                .contains("resources.limits contains duplicate resource name 'ephemeral-storage'"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn unique_resource_names_pass_validation() {
        // CAP's emitted shape — one cpu + one memory per list — must stay
        // valid; the same name appearing in BOTH requests and limits is the
        // normal Kubernetes shape and is not a duplicate.
        assert!(validate_unique_resource_names(&fixed_descriptor()).is_ok());
        assert!(validate_unique_resource_names(&small_descriptor()).is_ok());
        assert!(validate_unique_resource_names(&duplicate_limits_descriptor()).is_err());
    }

    #[test]
    fn tenant_ingress_internal_tls_manifest_uses_high_port_and_shared_runtime() {
        let container =
            tenant_ingress_container_for_mode(&fixed_descriptor(), CaddyTlsMode::Internal);
        let yaml = serde_yaml::to_string(&container).unwrap();
        assert!(yaml.contains("containerPort: 10443"));
        assert!(yaml.contains("name: XDG_DATA_HOME"));
        assert!(yaml.contains("value: /run/enclava/caddy-runtime"));
        assert!(yaml.contains("name: XDG_CONFIG_HOME"));
        assert!(yaml.contains("value: /run/enclava/caddy-runtime/config"));
        assert!(yaml.contains("name: HOME"));
    }

    #[test]
    fn tenant_ingress_dns01_broker_waits_for_tls_handoff_before_starting_caddy() {
        let container =
            tenant_ingress_container_for_mode(&fixed_descriptor(), CaddyTlsMode::Dns01Broker);
        assert_eq!(
            container.pointer("/command/0"),
            Some(&json!(ENCLAVA_WAIT_EXEC_PATH))
        );
        assert_eq!(container.pointer("/args/0"), Some(&json!("/bin/sh")));
        assert_eq!(container.pointer("/args/1"), Some(&json!("-ec")));
        let script = container
            .pointer("/args/2")
            .and_then(Value::as_str)
            .expect("DNS01 handoff script is rendered");
        assert!(script.contains("tenant-ingress waiting for TLS certificate handoff"));
        assert!(script.contains("\n  if [ -r '/run/enclava/caddy-runtime/certificates/tls.crt' ]"));
        assert!(script.contains("/usr/bin/caddy validate --config /etc/caddy/Caddyfile"));
        assert!(script.contains("/usr/bin/caddy run --config /etc/caddy/Caddyfile"));
        assert!(script.contains("certstamp"));
        assert!(script.contains("kill \"$caddy_pid\" 2>/dev/null || true"));
        assert!(script.contains("kill -9 \"$caddy_pid\" 2>/dev/null || true"));
    }

    #[test]
    fn enclava_tools_manifest_is_an_init_container_like_live_cap_manifest() {
        let manifest: Value =
            serde_yaml::from_str(&render_pod_manifest(&fixed_descriptor(), None).unwrap()).unwrap();
        let init_containers = manifest
            .pointer("/spec/initContainers")
            .and_then(Value::as_array)
            .expect("CAP genpolicy manifest must include initContainers");
        let enclava_tools = init_containers
            .iter()
            .find(|container| container.pointer("/name") == Some(&json!("enclava-tools")))
            .expect("enclava-tools init container is present");
        assert_eq!(
            enclava_tools.pointer("/securityContext/readOnlyRootFilesystem"),
            Some(&json!(true))
        );
        assert_eq!(enclava_tools.pointer("/command/1"), Some(&json!("-eu")));
        let command = enclava_tools
            .pointer("/command/3")
            .and_then(Value::as_str)
            .expect("enclava-tools init command is rendered");
        assert_eq!(command, ENCLAVA_TOOLS_INIT_COMMAND_NO_LOGS);
        assert!(!command.contains("/run/enclava-logs"));
        assert!(command.contains("install -d -m 02770 -o 0 -g 10001 /run/enclava/containers"));
        assert!(command.contains("printf 'not-ready\\n' > /run/enclava/init-ready"));
        let tool_mounts = enclava_tools
            .pointer("/volumeMounts")
            .and_then(Value::as_array)
            .expect("enclava-tools volumeMounts are present");
        assert!(tool_mounts.iter().any(|mount| {
            mount.pointer("/name") == Some(&json!("unlock-socket"))
                && mount.pointer("/mountPath") == Some(&json!("/run/enclava"))
                && mount.pointer("/readOnly") == Some(&json!(false))
        }));
        assert!(
            tool_mounts
                .iter()
                .all(|mount| mount.pointer("/name") != Some(&json!("logs"))),
            "logging-disabled pod mounts no logs volume into enclava-tools"
        );
        assert!(
            !manifest
                .pointer("/spec/volumes")
                .and_then(Value::as_array)
                .expect("volumes are present")
                .iter()
                .any(|volume| volume.pointer("/name") == Some(&json!("logs"))),
            "logging-disabled pod declares no logs volume"
        );

        let app_containers = manifest
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .unwrap();
        assert!(
            app_containers
                .iter()
                .all(|container| container.pointer("/name") != Some(&json!("enclava-tools"))),
            "enclava-tools is an init container in the live CAP manifest"
        );
    }

    #[test]
    fn log_encryption_manifest_matches_live_cap_log_contract() {
        let log_encryption = LogEncryptionConfig {
            algorithm: "x25519-hpke-v1".to_string(),
            key_id: "logs-prod".to_string(),
            public_key_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            public_key_sha256: "sha256:Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU".to_string(),
        };
        let descriptor = fixed_descriptor();
        let manifest: Value =
            serde_yaml::from_str(&render_pod_manifest(&descriptor, Some(&log_encryption)).unwrap())
                .unwrap();
        let containers = manifest
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .expect("CAP genpolicy manifest must include containers");
        let app = containers
            .iter()
            .find(|container| container.pointer("/name") == Some(&json!("web")))
            .expect("workload container is present");
        let app_env = app
            .pointer("/env")
            .and_then(Value::as_array)
            .expect("workload env is present");
        let deployment_id = descriptor.deploy_id.to_string();
        for (name, value) in [
            ("ENCLAVA_LOG_ENCRYPTION_KEY_ID", "logs-prod"),
            ("ENCLAVA_LOG_ORG_ID", descriptor.org_slug.as_str()),
            ("ENCLAVA_LOG_APP_NAME", descriptor.app_name.as_str()),
            ("ENCLAVA_LOG_DEPLOYMENT_ID", deployment_id.as_str()),
            (
                "ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_BASE64URL",
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            ),
            (
                "ENCLAVA_LOG_ENCRYPTION_PUBLIC_KEY_SHA256",
                "sha256:Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU",
            ),
            ("ENCLAVA_LOG_CONTAINER_NAME", "web"),
            (
                "ENCLAVA_LOG_SPOOL_PATH",
                "/run/enclava-logs/web-Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU.jsonl",
            ),
        ] {
            assert!(
                app_env.iter().any(|entry| {
                    entry.pointer("/name") == Some(&json!(name))
                        && entry.pointer("/value") == Some(&json!(value))
                }),
                "workload env {name} must match CAP"
            );
        }
        let app_mounts = app
            .pointer("/volumeMounts")
            .and_then(Value::as_array)
            .expect("workload volume mounts are present");
        assert!(app_mounts.iter().any(|mount| {
            mount.pointer("/name") == Some(&json!("logs"))
                && mount.pointer("/mountPath") == Some(&json!(ENCLAVA_LOG_SPOOL_DIR))
                && mount.pointer("/readOnly") == Some(&json!(false))
                && mount.pointer("/mountPropagation") == Some(&json!("HostToContainer"))
        }));

        assert!(
            !containers
                .iter()
                .any(|container| container.pointer("/name") == Some(&json!("encrypted-log-relay"))),
            "encrypted log relay must be embedded in enclava-init, not a separate sidecar"
        );
        let enclava_init = containers
            .iter()
            .find(|container| container.pointer("/name") == Some(&json!("enclava-init")))
            .expect("enclava-init sidecar is present");
        assert_eq!(
            env_value(enclava_init, "ENCLAVA_LOG_RELAY_SPOOL_PATH"),
            Some(&json!(
                "/run/enclava-logs/web-Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU.jsonl"
            ))
        );
        assert_eq!(
            env_value(enclava_init, "ENCLAVA_LOG_RELAY_BIND"),
            Some(&json!("127.0.0.1:8082"))
        );
        assert_eq!(
            env_value(enclava_init, "ENCLAVA_LOG_RELAY_CONTAINER"),
            Some(&json!("web"))
        );
        let init_mounts = enclava_init
            .pointer("/volumeMounts")
            .and_then(Value::as_array)
            .expect("enclava-init volume mounts are present");
        assert!(init_mounts.iter().any(|mount| {
            mount.pointer("/name") == Some(&json!("logs"))
                && mount.pointer("/mountPath") == Some(&json!(ENCLAVA_LOG_SPOOL_DIR))
                && mount.pointer("/readOnly") == Some(&json!(false))
                && mount.pointer("/mountPropagation") == Some(&json!("Bidirectional"))
        }));
        let enclava_tools = manifest
            .pointer("/spec/initContainers/0")
            .expect("enclava-tools init container is present");
        assert_eq!(
            enclava_tools.pointer("/command/3"),
            Some(&json!(ENCLAVA_TOOLS_INIT_COMMAND))
        );
        assert!(enclava_tools
            .pointer("/volumeMounts")
            .and_then(Value::as_array)
            .expect("enclava-tools volumeMounts are present")
            .iter()
            .any(|mount| {
                mount.pointer("/name") == Some(&json!("logs"))
                    && mount.pointer("/mountPath") == Some(&json!(ENCLAVA_LOG_SPOOL_DIR))
                    && mount.pointer("/readOnly") == Some(&json!(false))
            }));
        let volumes = manifest
            .pointer("/spec/volumes")
            .and_then(Value::as_array)
            .expect("volumes are present");
        let logs_volume = volumes
            .iter()
            .find(|volume| volume.pointer("/name") == Some(&json!("logs")))
            .expect("log encryption renders the logs mountpoint volume");
        assert_eq!(
            logs_volume.pointer("/emptyDir"),
            Some(&json!({"medium": "Memory", "sizeLimit": "1Mi"}))
        );
        assert!(!volumes
            .iter()
            .any(|volume| volume.pointer("/name") == Some(&json!("log-relay-tmp"))));
    }

    #[test]
    fn enclava_init_env_matches_live_cap_sidecar_contract() {
        let manifest: Value =
            serde_yaml::from_str(&render_pod_manifest(&fixed_descriptor(), None).unwrap()).unwrap();
        let containers = manifest
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .expect("CAP genpolicy manifest must include containers");
        assert_eq!(containers.last().unwrap()["name"], "enclava-init");
        let enclava_init = containers
            .iter()
            .find(|container| container.pointer("/name") == Some(&json!("enclava-init")))
            .expect("enclava-init container is present");
        let env = enclava_init
            .pointer("/env")
            .and_then(Value::as_array)
            .expect("enclava-init env is present");
        let wait_for_containers = env
            .iter()
            .find(|entry| {
                entry.pointer("/name") == Some(&json!("ENCLAVA_INIT_WAIT_FOR_CONTAINERS"))
            })
            .expect("enclava-init wait-list env is present");

        assert_eq!(
            wait_for_containers.pointer("/value"),
            Some(&json!(ENCLAVA_INIT_WAIT_FOR_CONTAINERS))
        );
        assert_eq!(
            wait_for_containers.pointer("/value"),
            Some(&json!("web,tenant-ingress,attestation-proxy"))
        );

        for (name, value) in [
            ("KBS_FETCH_RETRIES", "120"),
            ("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
            ("KBS_FETCH_REQUEST_TIMEOUT_SECONDS", "10"),
        ] {
            let entry = env
                .iter()
                .find(|entry| entry.pointer("/name") == Some(&json!(name)))
                .unwrap_or_else(|| panic!("enclava-init env {name} is present"));
            assert_eq!(entry.pointer("/value"), Some(&json!(value)));
        }
    }

    #[test]
    fn attestation_proxy_can_create_sev_guest_device_for_auto_unlock() {
        let container = attestation_proxy_container(&fixed_descriptor()).unwrap();
        assert_eq!(
            container.pointer("/securityContext/runAsUser"),
            Some(&json!(0))
        );
        assert_eq!(
            container.pointer("/securityContext/runAsGroup"),
            Some(&json!(0))
        );
        assert_eq!(
            container.pointer("/securityContext/readOnlyRootFilesystem"),
            Some(&json!(true))
        );
        assert_eq!(
            container.pointer("/securityContext/capabilities/drop/0"),
            Some(&json!("ALL"))
        );
        let added_caps = container
            .pointer("/securityContext/capabilities/add")
            .and_then(Value::as_array)
            .expect("attestation-proxy capabilities are rendered");
        for cap in ["CHOWN", "MKNOD", "SYS_PTRACE"] {
            assert!(
                added_caps.iter().any(|value| value == &json!(cap)),
                "missing {cap}"
            );
        }
        let manifest = serde_yaml::to_string(&container).unwrap();
        assert!(manifest.contains("name: CAP_CONFIG_DIR"));
        assert!(manifest.contains("value: /state/.enclava/config"));
        assert_eq!(
            env_value(&container, "CAP_CONFIG_READY_MARKER"),
            Some(&json!(CAP_CONFIG_READY_MARKER))
        );
        assert!(manifest.contains("name: CAP_CONFIG_FILE_GID"));
        assert!(manifest.contains("value: '10001'"));
        assert_eq!(
            env_value(&container, "ENCLAVA_CONTAINER_NAME"),
            Some(&json!("attestation-proxy"))
        );
        assert_eq!(
            env_value(&container, "ENCLAVA_STARTED_DIR"),
            Some(&json!("/run/enclava/containers"))
        );
        assert_eq!(
            env_value(&container, "ENCLAVA_INIT_UNLOCK_SOCKET"),
            Some(&json!("/run/enclava-unlock/unlock.sock"))
        );
        assert!(manifest.contains("mountPath: /state"));
        let mounts = container
            .pointer("/volumeMounts")
            .and_then(Value::as_array)
            .unwrap();
        let ready_mount = mounts
            .iter()
            .find(|mount| {
                mount.pointer("/name") == Some(&json!("unlock-socket"))
                    && mount.pointer("/mountPath") == Some(&json!("/run/enclava"))
            })
            .expect("attestation-proxy can write container-start readiness state");
        assert_eq!(ready_mount.pointer("/readOnly"), Some(&json!(false)));
    }

    #[test]
    fn attestation_proxy_policy_includes_amd_kds_relay() {
        let container = attestation_proxy_container_with_amd_kds_base_url(
            &fixed_descriptor(),
            Some("http://amd-kds-relay.enclava-dev.svc.cluster.local:8080/vcek/v1"),
        )
        .unwrap();
        assert_eq!(
            env_value(&container, "AMD_KDS_BASE_URL"),
            Some(&json!(
                "http://amd-kds-relay.enclava-dev.svc.cluster.local:8080/vcek/v1"
            ))
        );
    }

    #[test]
    fn independent_verification_proxy_matches_live_cap_evidence_mounts() {
        let mut descriptor = fixed_descriptor();
        descriptor.independent_verification = true;
        let manifest: Value =
            serde_yaml::from_str(&render_pod_manifest(&descriptor, None).unwrap()).unwrap();
        let proxy = manifest
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .find(|container| container.pointer("/name") == Some(&json!("attestation-proxy")))
            .unwrap();

        assert_eq!(
            env_value(proxy, "PROOF_TLS_CERT_PATH"),
            Some(&json!("/run/enclava/public-tls/certificates/tls.crt"))
        );
        let mounts = proxy
            .pointer("/volumeMounts")
            .and_then(Value::as_array)
            .unwrap();
        assert!(mounts.iter().any(|mount| {
            mount.pointer("/name") == Some(&json!("verification-material"))
                && mount.pointer("/mountPath") == Some(&json!("/etc/enclava-verification"))
                && mount.pointer("/readOnly") == Some(&json!(true))
        }));
        assert!(manifest
            .pointer("/spec/volumes")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .any(|volume| volume.pointer("/name") == Some(&json!("verification-material"))));
    }

    #[test]
    fn attestation_proxy_derives_required_config_keys_from_descriptor_env() {
        let mut descriptor = fixed_descriptor();
        descriptor.oci_runtime_spec.env.push(EnvVar {
            name: "ENCLAVA_REQUIRED_CONFIG_KEYS".to_string(),
            value: " FRP_SERVER_ADDR,FRP_AUTH_TOKEN ,DEBIAN_SSH_AUTHORIZED_KEYS ".to_string(),
        });

        let container = attestation_proxy_container(&descriptor).unwrap();

        assert_eq!(
            env_value(&container, "CAP_CONFIG_REQUIRED_KEYS"),
            Some(&json!(
                "FRP_SERVER_ADDR,FRP_AUTH_TOKEN,DEBIAN_SSH_AUTHORIZED_KEYS"
            ))
        );
    }

    #[test]
    fn attestation_proxy_derives_required_config_keys_from_descriptor_command() {
        let mut descriptor = fixed_descriptor();
        descriptor.oci_runtime_spec.command = vec![
            "/bin/sh".to_string(),
            "-c".to_string(),
            "ENCLAVA_REQUIRED_CONFIG_KEYS='FRP_SERVER_ADDR,FRP_AUTH_TOKEN' exec /app".to_string(),
        ];

        let container = attestation_proxy_container(&descriptor).unwrap();

        assert_eq!(
            env_value(&container, "CAP_CONFIG_REQUIRED_KEYS"),
            Some(&json!("FRP_SERVER_ADDR,FRP_AUTH_TOKEN"))
        );
    }

    #[test]
    fn attestation_proxy_derives_required_config_keys_from_descriptor_args() {
        let mut descriptor = fixed_descriptor();
        descriptor.oci_runtime_spec.command = vec![ENCLAVA_WAIT_EXEC_PATH.to_string()];
        descriptor.oci_runtime_spec.args = vec![
            "/bin/sh".to_string(),
            "-lc".to_string(),
            "DEBIAN_SSH_RESTART_WRAPPER=1 ENCLAVA_REQUIRED_CONFIG_KEYS=FRP_SERVER_ADDR,FRP_SERVER_PORT,FRP_AUTH_TOKEN exec /usr/local/bin/debian-ssh-frp-entrypoint".to_string(),
        ];

        let container = attestation_proxy_container(&descriptor).unwrap();

        assert_eq!(
            env_value(&container, "CAP_CONFIG_REQUIRED_KEYS"),
            Some(&json!("FRP_SERVER_ADDR,FRP_SERVER_PORT,FRP_AUTH_TOKEN"))
        );
    }

    #[test]
    fn platform_managed_ssh_relay_descriptor_renders_root_supervisor_policy_input() {
        let mut descriptor = fixed_descriptor();
        descriptor.oci_runtime_spec.command = vec![ENCLAVA_WAIT_EXEC_PATH.to_string()];
        descriptor.oci_runtime_spec.args =
            vec!["/usr/local/bin/debian-ssh-frp-entrypoint".to_string()];
        descriptor.oci_runtime_spec.env.push(EnvVar {
            name: "ENCLAVA_REQUIRED_CONFIG_KEYS".to_string(),
            value: "FRP_SERVER_ADDR,FRP_AUTH_TOKEN,DEBIAN_SSH_AUTHORIZED_KEYS".to_string(),
        });
        descriptor.oci_runtime_spec.capabilities = Capabilities {
            drop: vec!["ALL".to_string()],
            add: PLATFORM_MANAGED_SSH_RELAY_CAPS
                .iter()
                .map(|cap| (*cap).to_string())
                .collect(),
        };
        descriptor.oci_runtime_spec.security_context = SecurityContext {
            run_as_user: 0,
            run_as_group: 0,
            read_only_root_fs: true,
            allow_privilege_escalation: false,
            privileged: false,
        };

        let container = app_container(&descriptor, None);
        assert_eq!(
            container.pointer("/securityContext/runAsUser"),
            Some(&json!(0))
        );
        assert_eq!(
            container.pointer("/securityContext/runAsGroup"),
            Some(&json!(0))
        );
        assert_eq!(
            container.pointer("/securityContext/readOnlyRootFilesystem"),
            Some(&json!(true))
        );
        assert_eq!(
            container.pointer("/securityContext/allowPrivilegeEscalation"),
            Some(&json!(false))
        );
        assert_eq!(
            container.pointer("/securityContext/privileged"),
            Some(&json!(false))
        );
        assert_eq!(
            container.pointer("/securityContext/capabilities/drop/0"),
            Some(&json!("ALL"))
        );
        let added_caps = container
            .pointer("/securityContext/capabilities/add")
            .and_then(Value::as_array)
            .expect("relay capabilities are rendered");
        for cap in PLATFORM_MANAGED_SSH_RELAY_CAPS {
            assert!(
                added_caps.iter().any(|value| value == &json!(cap)),
                "missing {cap}"
            );
        }
        assert!(
            container
                .pointer("/volumeMounts")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .all(|mount| mount.pointer("/name") != Some(&json!("startup"))),
            "explicit-command relay apps must not mount startup"
        );

        let proxy = attestation_proxy_container(&descriptor).unwrap();
        let env = proxy
            .pointer("/env")
            .and_then(Value::as_array)
            .expect("proxy env is rendered");
        assert!(
            env.iter()
                .all(|entry| entry.pointer("/name") != Some(&json!("CAP_CONFIG_FILE_GID"))),
            "relay profile keeps managed config root-only"
        );
        assert_eq!(
            env_value(&proxy, "CAP_CONFIG_READY_MARKER"),
            Some(&json!(CAP_CONFIG_READY_MARKER))
        );
        assert_eq!(
            env_value(&proxy, "CAP_CONFIG_REQUIRED_KEYS"),
            Some(&json!(
                "FRP_SERVER_ADDR,FRP_AUTH_TOKEN,DEBIAN_SSH_AUTHORIZED_KEYS"
            ))
        );
        assert_eq!(
            env_value(&proxy, "ENCLAVA_CONTAINER_NAME"),
            Some(&json!("attestation-proxy"))
        );
        assert_eq!(
            env_value(&proxy, "ENCLAVA_STARTED_DIR"),
            Some(&json!("/run/enclava/containers"))
        );

        let volumes = cap_volumes(&descriptor, false);
        assert!(
            volumes
                .iter()
                .all(|volume| volume.pointer("/name") != Some(&json!("startup"))),
            "explicit-command relay apps must not include unused startup volume"
        );
    }

    #[test]
    fn rootful_sudo_descriptor_renders_writable_root_policy_input() {
        let mut descriptor = fixed_descriptor();
        descriptor.oci_runtime_spec.command = vec![ENCLAVA_WAIT_EXEC_PATH.to_string()];
        descriptor.oci_runtime_spec.args =
            vec!["/usr/local/bin/debian-ssh-frp-entrypoint".to_string()];
        descriptor.oci_runtime_spec.env.push(EnvVar {
            name: "ENCLAVA_REQUIRED_CONFIG_KEYS".to_string(),
            value: "FRP_SERVER_ADDR,FRP_AUTH_TOKEN,DEBIAN_SSH_AUTHORIZED_KEYS".to_string(),
        });
        descriptor.oci_runtime_spec.capabilities = Capabilities {
            drop: vec!["ALL".to_string()],
            add: ROOTFUL_SUDO_CAPS
                .iter()
                .map(|cap| (*cap).to_string())
                .collect(),
        };
        descriptor.oci_runtime_spec.security_context = SecurityContext {
            run_as_user: 0,
            run_as_group: 0,
            read_only_root_fs: false,
            allow_privilege_escalation: true,
            privileged: false,
        };

        let container = app_container(&descriptor, None);
        assert_eq!(
            container.pointer("/securityContext/runAsUser"),
            Some(&json!(0))
        );
        assert_eq!(
            container.pointer("/securityContext/runAsGroup"),
            Some(&json!(0))
        );
        assert_eq!(
            container.pointer("/securityContext/readOnlyRootFilesystem"),
            Some(&json!(false))
        );
        assert_eq!(
            container.pointer("/securityContext/allowPrivilegeEscalation"),
            Some(&json!(true))
        );
        assert_eq!(
            container.pointer("/securityContext/privileged"),
            Some(&json!(false))
        );
        assert_eq!(
            container.pointer("/securityContext/capabilities/drop/0"),
            Some(&json!("ALL"))
        );
        let added_caps = container
            .pointer("/securityContext/capabilities/add")
            .and_then(Value::as_array)
            .expect("rootful-sudo capabilities are rendered");
        for cap in ROOTFUL_SUDO_CAPS {
            assert!(
                added_caps.iter().any(|value| value == &json!(cap)),
                "missing {cap}"
            );
        }
        assert!(
            container
                .pointer("/volumeMounts")
                .and_then(Value::as_array)
                .unwrap()
                .iter()
                .all(|mount| mount.pointer("/name") != Some(&json!("startup"))),
            "explicit-command rootful-sudo apps must not mount startup"
        );

        let proxy = attestation_proxy_container(&descriptor).unwrap();
        let env = proxy
            .pointer("/env")
            .and_then(Value::as_array)
            .expect("proxy env is rendered");
        assert!(
            env.iter()
                .all(|entry| entry.pointer("/name") != Some(&json!("CAP_CONFIG_FILE_GID"))),
            "rootful-sudo profile keeps managed config root-only"
        );
        assert_eq!(
            env_value(&proxy, "CAP_CONFIG_REQUIRED_KEYS"),
            Some(&json!(
                "FRP_SERVER_ADDR,FRP_AUTH_TOKEN,DEBIAN_SSH_AUTHORIZED_KEYS"
            ))
        );

        let volumes = cap_volumes(&descriptor, false);
        assert!(
            volumes
                .iter()
                .all(|volume| volume.pointer("/name") != Some(&json!("startup"))),
            "explicit-command rootful-sudo apps must not include unused startup volume"
        );
    }

    #[test]
    fn descriptor_subpath_mounts_are_bound_by_enclava_init_not_kubernetes_subpath() {
        let mut descriptor = fixed_descriptor();
        descriptor.oci_runtime_spec.mounts = vec![
            Mount {
                source: "state-mount".to_string(),
                destination: "/state".to_string(),
                mount_type: "kubernetes-volume".to_string(),
                options: vec!["rw".to_string()],
            },
            Mount {
                source: "state-mount:data".to_string(),
                destination: "/data".to_string(),
                mount_type: "kubernetes-volume-subpath".to_string(),
                options: vec!["rw".to_string()],
            },
        ];

        let manifest = render_pod_manifest(&descriptor, None).unwrap();

        assert!(manifest.contains("mountPath: /state"));
        assert_eq!(manifest.matches("mountPath: /data").count(), 1);
        assert!(!manifest.contains("subPath:"));
    }

    #[test]
    fn auto_unlock_descriptor_renders_auto_unlock_proxy_mode() {
        let mut descriptor = fixed_descriptor();
        descriptor.unlock_mode = "auto".to_string();
        let manifest = render_pod_manifest(&descriptor, None).unwrap();
        assert!(manifest.contains("name: STORAGE_OWNERSHIP_MODE"));
        assert!(manifest.contains("value: auto-unlock"));
    }

    #[test]
    fn invalid_unlock_mode_is_rejected() {
        let mut descriptor = fixed_descriptor();
        descriptor.unlock_mode = "manual".to_string();
        let err = render_pod_manifest(&descriptor, None).unwrap_err();
        assert!(err.to_string().contains("descriptor.unlock_mode"));
    }

    #[test]
    fn rejects_unpinned_version_label() {
        let config = GenpolicyConfig {
            binary: PathBuf::from("genpolicy"),
            version_pin: "kata-containers/genpolicy-unpinned-dev".to_string(),
            rules_path: PathBuf::from("rules.rego"),
            settings_dir: None,
            total_budget: std::time::Duration::from_secs(30),
            max_concurrent: 2,
        };
        assert!(config.require_pinned_version().is_err());
    }

    #[test]
    fn removes_default_service_account_token_mounts_from_settings() {
        let mut settings = json!({
            "other_container": {
                "Mounts": [
                    {"destination": "/etc/hosts"},
                    {"destination": "/var/run/secrets/kubernetes.io/serviceaccount"},
                    {"destination": "/var/run/secrets/azure/tokens"}
                ]
            },
            "mount_destinations": [
                "/etc/hosts",
                "/var/run/secrets/kubernetes.io/serviceaccount",
                "/var/run/secrets/azure/tokens"
            ]
        });

        remove_service_account_token_mounts(&mut settings);

        let mounts = settings["other_container"]["Mounts"].as_array().unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0]["destination"], "/etc/hosts");
        let destinations = settings["mount_destinations"].as_array().unwrap();
        assert_eq!(destinations, &[json!("/etc/hosts")]);
    }

    #[test]
    fn allows_kata_rshared_rootfs_propagation() {
        let policy = r#"default AllowRequestsFailingPolicy := false

allow_create_container_input if {
    count(i_linux.RootfsPropagation) == 0
}
"#;

        let normalized = normalize_cap_generated_policy(policy);

        assert!(normalized.contains("allow_cap_rootfs_propagation(i_linux.RootfsPropagation)"));
        assert!(normalized.contains("rootfs_propagation == \"rshared\""));
        assert!(normalized.contains("rootfs_propagation == \"rslave\""));
        assert!(!normalized.contains("count(i_linux.RootfsPropagation) == 0"));
    }

    #[test]
    fn allows_sandbox_container_without_shared_pid_namespace() {
        let policy = r#"default AllowRequestsFailingPolicy := false

allow_create_container_input(p_container) if {
    p_pidns := p_container.sandbox_pidns
    i_pidns := input.sandbox_pidns
    print("CreateContainerRequest: p_pidns =", p_pidns, "i_pidns =", i_pidns)
    p_pidns == i_pidns
}
"#;

        let normalized = normalize_cap_generated_policy(policy);

        assert!(normalized.contains("allow_cap_sandbox_pidns(p_container, p_pidns, i_pidns)"));
        assert!(normalized.contains(
            r#"p_container.OCI.Annotations["io.kubernetes.cri.container-type"] == "sandbox""#
        ));
        assert!(normalized.contains("i_pidns == false"));
        assert!(normalized.contains(
            r#"print("CreateContainerRequest: p_pidns =", p_pidns, "i_pidns =", i_pidns)
    allow_cap_sandbox_pidns(p_container, p_pidns, i_pidns)"#
        ));
    }

    #[test]
    fn normalizes_privileged_caps_placeholder() {
        let policy = r#"policy_data := {
  "containers": [
    {
      "OCI": {
        "Process": {
          "Capabilities": {
            "Bounding": [
              "CAP_$(privileged_caps)"
            ],
            "Effective": [
              "CAP_$(privileged_caps)"
            ],
            "Permitted": [
              "CAP_$(privileged_caps)"
            ]
          }
        }
      }
    }
  ]
}
"#;

        let normalized = normalize_cap_generated_policy(policy);

        assert!(normalized.contains("\"$(privileged_caps)\""));
        assert!(!normalized.contains("CAP_$(privileged_caps)"));
    }

    #[test]
    fn allows_cap_state_storage_runtime_mount_options_and_fs_group() {
        let policy = r#"default AllowRequestsFailingPolicy := false

check_mount(p_mount, i_mount, bundle_id, sandbox_id) if {
    p_mount.destination == i_mount.destination
    p_mount.type_ == i_mount.type_
    p_mount.options == i_mount.options

    mount_source_allows(p_mount, i_mount, bundle_id, sandbox_id)
}

allow_storage_base(p_storage, i_storage, bundle_id, sandbox_id) if {
    p_storage.driver_options == i_storage.driver_options
    p_storage.fs_group       == i_storage.fs_group
    p_storage.fstype         == i_storage.fstype
}

allow_storage_options(p_storage, i_storage) if {
    p_storage.driver != "overlayfs"
    p_storage.options == i_storage.options
}

allow_sandbox_storage(p_storages, i_storage) if {
    some p_storage in p_storages
    i_storage == p_storage
}

allow_storages(p_storages, i_storages, bundle_id, sandbox_id) if {
    p_count := count(p_storages)
    i_count := count(i_storages)
    img_pull_count := count([s | s := i_storages[_]; s.driver == "image_guest_pull"])
    p_count == i_count - img_pull_count

    every i_storage in i_storages {
        allow_storage(p_storages, i_storage, bundle_id, sandbox_id)
    }
}
"#;

        let normalized = normalize_cap_generated_policy(policy);

        assert!(normalized.contains("allow_cap_mount_options(p_mount, i_mount)"));
        assert!(normalized.contains("allow_cap_sandbox_storage(p_storage, i_storage)"));
        assert!(normalized.contains(r#"i_mount.options == ["rbind", "rslave", "rw"]"#));
        assert!(normalized.contains(r#"i_mount.options == ["rbind", "rslave", "ro"]"#));
        assert!(normalized.contains(r#"i_mount.options == ["rbind", "rshared", "rw"]"#));
        assert!(normalized.contains("allow_cap_storage_fs_group(p_storage, i_storage)"));
        assert!(normalized.contains("allow_cap_storage_options(p_storage, i_storage)"));
        assert!(normalized.contains(r#"p_storage.options == ["fsgid=10001"]"#));
        assert!(normalized.contains("i_storage.fs_group.group_id == 10001"));
        assert!(normalized.contains(r#"i_storage.driver == "9p""#));
        assert!(normalized.contains(r#"i_storage.source == "kataShared""#));
        assert!(normalized.contains("allow_cap_extra_storage(i_storage, bundle_id, sandbox_id)"));
        assert!(normalized.contains("cap_extra_storage_count := count"));
        assert!(
            normalized.contains("p_count == i_count - img_pull_count - cap_extra_storage_count")
        );
        assert!(normalized.contains(r#"i_storage.driver == "watchable-bind""#));
        assert!(normalized
            .contains(r#"replace(i_storage.mount_point, "/watchable/", "/") == i_storage.source"#));
        assert!(!normalized.contains(
            "    p_mount.type_ == i_mount.type_\n    p_mount.options == i_mount.options\n\n    mount_source_allows"
        ));
        assert!(!normalized.contains(
            "    p_storage.driver_options == i_storage.driver_options\n    p_storage.fs_group       == i_storage.fs_group\n"
        ));
    }

    // Generator-growth detector: the deploy-side caps are sized to this policy class
    // (API-side `MAX_POLICY_TEXT_BYTES` 160 KiB JSON-escaped and the composed
    // proof-bundle budget 196,608; ~89-91 KiB raw measured on genpolicy 4.3.1 with
    // the stand-in image during the upgrade audit; CI prints exact sizes). A
    // genpolicy, rules, or settings change that grows the output must fail here
    // first: coordinate the deploy-side caps, then raise this bound in the same change.
    const GENERATED_POLICY_SIZE_CLASS_MAX_BYTES: usize = 128 * 1024;
    const GENERATED_POLICY_SIZE_CLASS_MIN_BYTES: usize = 64 * 1024;

    // Production container layout with tiny pinned public images in place of the
    // platform images (hermeticity: no coupling to platform-package availability,
    // visibility, or registry rate limits in CI). The size class is dominated by
    // genpolicy boilerplate (~116 KiB of ~117 KiB live baseline), so image choice
    // moves the total by a KiB or two.
    fn size_class_descriptor() -> DeploymentDescriptor {
        let mut descriptor = fixed_descriptor();
        descriptor.image_ref = format!("{SIZE_CLASS_IMAGE_REPO}@{SIZE_CLASS_IMAGE_DIGEST}");
        descriptor.image_digest = SIZE_CLASS_IMAGE_DIGEST.to_string();
        descriptor.sidecars.attestation_proxy_digest = SIZE_CLASS_IMAGE_DIGEST.to_string();
        descriptor.sidecars.caddy_digest = SIZE_CLASS_IMAGE_DIGEST.to_string();
        descriptor
    }

    #[test]
    fn generated_policy_size_class_stays_within_the_deploy_budget() {
        // Skip only when the generator binary itself is absent (dev workstations):
        // missing settings, broken config, or an explicitly configured GENPOLICY_BIN
        // are real failures and must not be masked as a skip.
        if std::env::var_os("GENPOLICY_BIN").is_none()
            && matches!(
                std::process::Command::new("genpolicy").arg("--help").output(),
                Err(err) if err.kind() == std::io::ErrorKind::NotFound
            )
        {
            eprintln!("skipping size-class check: genpolicy binary not installed");
            return;
        }
        let config = GenpolicyConfig::from_env();
        let descriptor = size_class_descriptor();
        let log_encryption = LogEncryptionConfig {
            algorithm: "x25519-hpke-v1".to_string(),
            key_id: "logs-size-class".to_string(),
            public_key_base64url: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            public_key_sha256: "sha256:Zmh6rfhivXdsj8GLjp-OIAiXFIVu4jOzkCpZHQ1fKSU".to_string(),
        };
        // Both production generation entry points (main.rs): plain and log-encrypted.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let sizes = [
            runtime.block_on(config.run(&descriptor)),
            runtime.block_on(async {
                config
                    .run_with_log_encryption(&descriptor, Some(&log_encryption))
                    .await
            }),
        ]
        .map(|result| {
            result
                .unwrap_or_else(|err| panic!("genpolicy run failed: {err:#}"))
                .policy_text
                .len()
        });
        for size in sizes {
            eprintln!("generated policy size class: {size} bytes");
            assert!(
                size <= GENERATED_POLICY_SIZE_CLASS_MAX_BYTES,
                "genpolicy output grew to {size} bytes (bound {GENERATED_POLICY_SIZE_CLASS_MAX_BYTES}); \
                 the deploy-side caps are sized to this policy class — coordinate the caps before \
                 raising this bound"
            );
            assert!(
                size >= GENERATED_POLICY_SIZE_CLASS_MIN_BYTES,
                "genpolicy output shrank to {size} bytes (bound {GENERATED_POLICY_SIZE_CLASS_MIN_BYTES}); \
                 imploded generator output is as surprising as growth — verify the generation shape \
                 before adjusting this bound"
            );
        }
    }

    #[test]
    fn platform_sidecar_repo_constants_stay_pinned() {
        // The cfg(test) stand-in swap at the use site must never hide drift in the
        // production repo strings — no other test sees them.
        assert_eq!(
            DEFAULT_ATTESTATION_PROXY_IMAGE_REPO,
            "ghcr.io/enclava-labs/attestation-proxy"
        );
        assert_eq!(
            CADDY_INGRESS_IMAGE_REPO,
            "ghcr.io/enclava-labs/caddy-ingress"
        );
    }

    fn write_fake_genpolicy(dir: &Path, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let binary = dir.join("fake-genpolicy");
        fs::write(&binary, body).unwrap();
        fs::set_permissions(&binary, fs::Permissions::from_mode(0o755)).unwrap();
        binary
    }

    fn current_thread_runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    #[test]
    fn stalled_genpolicy_fails_inside_the_budget_with_the_attempt_named() {
        // (d1) The outage shape: a genpolicy child that never exits. The
        // step fails FAST (inside the injected budget) with an error that
        // names the attempt and the budget — never an unbounded wait.
        let work = tempfile::tempdir().unwrap();
        let binary = write_fake_genpolicy(work.path(), "#!/bin/sh\nsleep 300\n");
        let started = std::time::Instant::now();
        let error = current_thread_runtime()
            .block_on(async {
                run_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    std::time::Duration::from_millis(300),
                    None,
                    "test://d1-workload-image",
                )
                .await
            })
            .expect_err("a stalled child must hit the budget");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("genpolicy timed out: attempt 1"),
            "error must name the attempt: {rendered}"
        );
        assert!(
            rendered.contains("exceeded the total budget"),
            "error must name the budget: {rendered}"
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "returned inside the budget, not after the child's 300 s sleep"
        );
    }

    #[tokio::test]
    async fn healthz_style_work_answers_during_the_stalled_child_wait() {
        // (d2) DISCRIMINATING worker-parking proof: async work must make
        // progress WHILE the stalled child is still being waited on, not
        // after the generation future resolves. The clock is captured
        // BEFORE `tokio::join!` (t0), so BOTH parking shapes are caught:
        // (1) a blocking std wait restored inside the attempt (the
        //     pre-fix shape; S2) — the runtime parks for the whole child
        //     runtime, healthz answers only after it, elapsed >> 1s;
        // (2) a bounded worker park right after spawn (std sleep 8 s
        //     between spawn and the timeout await) — the single-threaded
        //     test runtime cannot poll healthz until the park ends, so
        //     elapsed >= 8s.
        // Both sabotages were RUN at this head: each goes RED on the
        // elapsed assert below (and shape (1) also trips the is_err
        // assert — the budget never fires while parked).
        let work = tempfile::tempdir().unwrap();
        let binary = write_fake_genpolicy(work.path(), "#!/bin/sh\nsleep 10\n");
        let t0 = std::time::Instant::now();
        let genpolicy = async {
            run_genpolicy(
                &binary,
                &[],
                work.path(),
                std::time::Duration::from_secs(5),
                None,
                "test://d2-workload-image",
            )
            .await
        };
        let healthz = async {
            let mut ticks = 0;
            while ticks < 5 {
                tokio::task::yield_now().await;
                ticks += 1;
            }
            // Measured INSIDE the future from the pre-join t0: if the
            // worker is parked, this timestamp still reflects the park.
            (ticks, t0.elapsed())
        };
        let (result, (ticks, healthz_elapsed)) = tokio::join!(genpolicy, healthz);
        assert!(result.is_err(), "the stalled child hits the budget");
        assert_eq!(ticks, 5);
        assert!(
            healthz_elapsed < std::time::Duration::from_secs(1),
            "async work progressed DURING the wait (healthz answered {healthz_elapsed:?} after t0, captured before the join), not after the generation future resolved"
        );
    }

    #[test]
    fn budget_expiry_terminates_the_childs_spawned_helper() {
        // (d1b / Devin T1): the group kill must reach helpers the child
        // spawned, via the OS API (no `kill` executable exists in the
        // shipped image). The fake genpolicy spawns a 60 s sleeper and
        // reports its pid; after the budget the sleeper must be gone.
        let work = tempfile::tempdir().unwrap();
        let helper = work.path().join("helper.sh");
        fs::write(&helper, "#!/bin/sh\nsleep 60\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&helper, fs::Permissions::from_mode(0o755)).unwrap();
        let pid_file = work.path().join("helper.pid");
        let binary = write_fake_genpolicy(
            work.path(),
            &format!(
                "#!/bin/sh\nsh \"{help}\" &\necho $! > \"{pfile}\"\nsleep 30\n",
                help = helper.display(),
                pfile = pid_file.display(),
            ),
        );
        let error = current_thread_runtime()
            .block_on(async {
                run_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    std::time::Duration::from_millis(400),
                    None,
                    "test://d1b-workload-image",
                )
                .await
            })
            .expect_err("budget must fire");
        assert!(format!("{error:#}").contains("genpolicy timed out"));
        let helper_pid: i32 = fs::read_to_string(&pid_file)
            .expect("helper pid recorded")
            .trim()
            .parse()
            .expect("helper pid numeric");
        // Reap window for the TERM, then the helper must be gone: kill(0)
        // fails with ESRCH once no such process exists.
        let mut gone = false;
        for _ in 0..50 {
            let rc = unsafe { libc::kill(helper_pid, 0) };
            if rc != 0 {
                gone = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(gone, "the spawned helper was TERMed with the group");
        // NOTE (QA F-4, reported as asked): this pins the OUTCOME — the
        // helper is gone after expiry. It deliberately does not
        // discriminate WHICH kill path TERMed it: the explicit
        // budget-branch kill and the ProcessGroupGuard's Drop are
        // belt-and-braces by design (the guard fires on EVERY
        // cancellation path; the explicit kill fires first, before the
        // expiry WARN is emitted), and no-op-ing either one alone keeps
        // this test green — which is the intended redundancy, not a gap.
    }

    /// io::Write sink shared with the tracing subscriber so tests can
    /// grep the exact log lines production emits.
    #[derive(Clone)]
    struct SharedLogSink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for SharedLogSink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl tracing_subscriber::fmt::MakeWriter<'_> for SharedLogSink {
        type Writer = SharedLogSink;
        fn make_writer(&self) -> Self::Writer {
            self.clone()
        }
    }

    #[test]
    fn logged_tails_carry_content_but_never_the_childs_credentials() {
        // (ADDENDUM 1 + 2; QA F-1/F-2) — one test, both paths:
        // SUCCESS: the child dumps its own auth file to stderr (the
        //   worst-case leak attempt — REGISTRY_AUTH_FILE is exactly the
        //   credential channel in production) and a benign marker to
        //   stdout, then exits 0: the INFO finish line carries BOTH
        //   redacted tails; the benign marker IS logged, the credential
        //   marker is NOT.
        // KILL: the same child then sleeps past the budget: the WARN
        //   expiry line names attempt / auth mode / image reference /
        //   elapsed (ADDENDUM 1) and carries the same redacted tails
        //   (ADDENDUM 2, kill path — the reader tasks keep the bytes
        //   past the group TERM); the credential marker appears in NO
        //   captured log line.
        let work = tempfile::tempdir().unwrap();
        let secret_marker = "SECRETMARKER-DO-NOT-LOG==";
        let docker_dir = work.path().join("creds");
        fs::create_dir_all(&docker_dir).unwrap();
        let auth_file = docker_dir.join("config.json");
        fs::write(
            &auth_file,
            format!(r#"{{"auths":{{"ghcr.io":{{"auth":"{secret_marker}"}}}}}}"#),
        )
        .unwrap();
        let leak = r#"cat "$REGISTRY_AUTH_FILE" 1>&2"#;
        // Distinct files: write_fake_genpolicy always uses the same name,
        // so the second write would silently replace the first.
        let write_named = |name: &str, body: String| {
            use std::os::unix::fs::PermissionsExt;
            let path = work.path().join(name);
            fs::write(&path, body).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
            path
        };
        let success_binary = write_named(
            "leak-success-genpolicy",
            format!("#!/bin/sh\n{leak}\necho BENIGN-TAIL-MARKER\n"),
        );
        let stalling_binary = write_named(
            "leak-stall-genpolicy",
            format!("#!/bin/sh\n{leak}\necho BENIGN-TAIL-MARKER\nsleep 30\n"),
        );
        let logs = SharedLogSink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        let env = Some((auth_file.as_path(), docker_dir.as_path()));
        tracing::subscriber::with_default(subscriber, || {
            current_thread_runtime().block_on(async {
                let success = attempt_genpolicy(
                    &success_binary,
                    &[],
                    work.path(),
                    env,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                    7,
                    "configured",
                    "test://redaction-image",
                )
                .await
                .expect("success-path child exits 0");
                assert!(success.status.success());
                let error = attempt_genpolicy(
                    &stalling_binary,
                    &[],
                    work.path(),
                    env,
                    tokio::time::Instant::now() + std::time::Duration::from_millis(300),
                    9,
                    "configured",
                    "test://redaction-image",
                )
                .await
                .expect_err("the stalling child hits the budget");
                assert!(
                    format!("{error:#}").contains("genpolicy timed out: attempt 9"),
                    "error names the attempt: {error:#}"
                );
            })
        });
        let captured = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
        // Tails carry real content on BOTH paths...
        assert!(
            captured.contains("BENIGN-TAIL-MARKER"),
            "tails log child stdout/stderr content: {captured}"
        );
        assert!(
            captured.contains("stdout_bytes=") && captured.contains("stderr_bytes="),
            "byte counts still present: {captured}"
        );
        // ...ADDENDUM 1: the expiry WARN names all four facts...
        let warn_line = captured
            .lines()
            .find(|line| line.contains("genpolicy budget expired"))
            .expect("a WARN line for the expiry path");
        for expected in [
            "attempt=9",
            "auth=\"configured\"",
            "image_ref=\"test://redaction-image\"",
        ] {
            assert!(
                warn_line.contains(expected),
                "WARN line must name {expected}: {warn_line}"
            );
        }
        assert!(
            warn_line.contains("elapsed_ms="),
            "WARN line names the elapsed time: {warn_line}"
        );
        // ...and the credential NEVER leaks into any captured log line.
        assert!(
            !captured.contains(secret_marker),
            "the child's credential marker must not appear in any log line: {captured}"
        );
        assert!(
            captured.contains("[redacted]"),
            "redaction replaced the credential bytes, not just dropped them: {captured}"
        );
    }

    #[test]
    fn boundary_split_secret_never_leaks_into_the_tail() {
        // QA probe F-A (qa-probe2.log): the child prints 100 P's, the
        // credential, then 500 Q's (625 B) so the secret straddles the
        // 512-byte tail boundary. Slicing before redaction leaked the
        // secret's trailing bytes ("DO-NOT-LOG==QQQ..."); redaction must
        // run over the whole buffer FIRST (redact-then-slice).
        let work = tempfile::tempdir().unwrap();
        let secret_marker = "SECRETMARKER-DO-NOT-LOG==";
        let docker_dir = work.path().join("creds");
        fs::create_dir_all(&docker_dir).unwrap();
        let auth_file = docker_dir.join("config.json");
        fs::write(
            &auth_file,
            format!(r#"{{"auths":{{"ghcr.io":{{"auth":"{secret_marker}"}}}}}}"#),
        )
        .unwrap();
        // QA's exact geometry: 100 P's + the marker alone (read from the
        // auth file, no JSON wrapper) + 500 Q's = 625 B, so the marker's
        // trailing "DO-NOT-LOG==" straddles the 512-byte boundary.
        let pad = "P".repeat(100);
        let tail_pad = "Q".repeat(500);
        let binary = write_fake_genpolicy(
            work.path(),
            &format!(
                "#!/bin/sh\nprintf '%s' '{pad}'\ncut -d'\"' -f8 \"$REGISTRY_AUTH_FILE\" | tr -d '\\n'\nprintf '%s' '{tail_pad}'\n"
            ),
        );
        let logs = SharedLogSink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        let env = Some((auth_file.as_path(), docker_dir.as_path()));
        tracing::subscriber::with_default(subscriber, || {
            current_thread_runtime().block_on(async {
                let success = attempt_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    env,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                    1,
                    "configured",
                    "test://f-a-image",
                )
                .await
                .unwrap();
                assert!(success.status.success());
            })
        });
        let captured = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
        assert!(
            !captured.contains("DO-NOT-LOG"),
            "the secret's trailing bytes leaked across the tail boundary: {captured}"
        );
        assert!(
            !captured.contains(secret_marker),
            "the secret itself leaked: {captured}"
        );
        // No "[redacted]-present" assertion here by design: with the
        // secret at the boundary the replacement marker itself may sit
        // across the window edge; the contract under test is that NO part
        // of the secret survives, which the two asserts above pin.
    }

    #[test]
    fn encoded_credentials_never_leak_into_the_tail() {
        // QA probe F-B (qa-probe2.log): the child echoes od -tx1 (hex) and
        // base64 of its auth file; byte-string redaction alone let the
        // whole credential through, recoverable by decoding the log line.
        let work = tempfile::tempdir().unwrap();
        let secret_marker = "SECRETMARKER-DO-NOT-LOG==";
        let docker_dir = work.path().join("creds");
        fs::create_dir_all(&docker_dir).unwrap();
        let auth_file = docker_dir.join("config.json");
        let auth_body = format!(r#"{{"auths":{{"ghcr.io":{{"auth":"{secret_marker}"}}}}}}"#);
        fs::write(&auth_file, &auth_body).unwrap();
        let binary = write_fake_genpolicy(
            work.path(),
            "#!/bin/sh\nod -An -tx1 \"$REGISTRY_AUTH_FILE\" | tr -d ' \\n'\necho\nbase64 -w0 \"$REGISTRY_AUTH_FILE\"\necho\n",
        );
        let logs = SharedLogSink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        let env = Some((auth_file.as_path(), docker_dir.as_path()));
        tracing::subscriber::with_default(subscriber, || {
            current_thread_runtime().block_on(async {
                let success = attempt_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    env,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                    1,
                    "configured",
                    "test://f-b-image",
                )
                .await
                .unwrap();
                assert!(success.status.success());
            })
        });
        let captured = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
        let file_bytes = auth_body.as_bytes();
        let hex_of_file = hex::encode(file_bytes);
        assert!(
            !captured.contains(&hex_of_file),
            "the hex-encoded credential leaked: {captured}"
        );
        use base64::Engine;
        let b64_of_file = base64::engine::general_purpose::STANDARD.encode(file_bytes);
        assert!(
            !captured.contains(&b64_of_file),
            "the base64-encoded credential leaked: {captured}"
        );
        assert!(
            captured.contains("[redacted]"),
            "encodings were redacted, not just cut: {captured}"
        );
    }

    #[test]
    fn echoed_credential_value_never_leaks_into_the_tail() {
        // QA probe F-C (qa-probe-b.log): the child echoes a proper
        // SUBSTRING of the credential — here the realistic worst case, the
        // base64-DECODED password of its docker-config auth token, with
        // characters that also stress percent and JSON-escape forms.
        // Whole-file byte redaction does not match substrings; extracted
        // credential values must be redacted in their own right.
        let work = tempfile::tempdir().unwrap();
        let user = "qa-user";
        let password = "pa@ss \"x/y+z:w\"ord";
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        let docker_dir = work.path().join("creds");
        fs::create_dir_all(&docker_dir).unwrap();
        let auth_file = docker_dir.join("config.json");
        fs::write(
            &auth_file,
            format!(r#"{{"auths":{{"ghcr.io":{{"auth":"{token}"}}}}}}"#),
        )
        .unwrap();
        // The child decodes its own token (auth files are JSON with the
        // token as the 8th double-quoted field) and echoes the pair.
        let binary = write_fake_genpolicy(
            work.path(),
            "#!/bin/sh\nPAIR=$(cut -d'\"' -f8 \"$REGISTRY_AUTH_FILE\" | base64 -d)\nprintf '%s\\n' \"$PAIR\"\nprintf '%s' \"$PAIR\" | od -An -tx1 | tr -d ' \\n'; echo\nprintf '%s' \"$PAIR\" | base64 -w0; echo\nprintf '%s' \"$PAIR\" | od -An -tx1 | tr -d ' \\n' | sed 's/../%&/g'; echo\nprintf '%s' \"$PAIR\" | sed 's/\"/\\\\\"/g'; echo\n",
        );
        let logs = SharedLogSink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        let env = Some((auth_file.as_path(), docker_dir.as_path()));
        tracing::subscriber::with_default(subscriber, || {
            current_thread_runtime().block_on(async {
                let success = attempt_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    env,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                    1,
                    "configured",
                    "test://f-c-image",
                )
                .await
                .unwrap();
                assert!(success.status.success());
            })
        });
        let captured = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
        for (label, forbidden) in [
            (
                "the decoded user:password pair",
                format!("{user}:{password}"),
            ),
            (
                "the hex-encoded pair (emitted)",
                hex::encode(format!("{user}:{password}")),
            ),
            ("the base64-encoded pair (emitted)", {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"))
            }),
            (
                "the percent-encoded pair (emitted)",
                format!("{user}:{password}")
                    .bytes()
                    .map(|b| format!("%{b:02x}"))
                    .collect::<String>(),
            ),
            ("the decoded password", password.to_string()),
            (
                "the percent-encoded password",
                password
                    .bytes()
                    .map(|b| format!("%{b:02X}"))
                    .collect::<String>(),
            ),
            ("the JSON-escaped password", {
                let mut escaped = String::new();
                for c in password.chars() {
                    match c {
                        '"' => escaped.push_str("\\\""),
                        '\\' => escaped.push_str("\\\\"),
                        _ => escaped.push(c),
                    }
                }
                escaped
            }),
            ("the hex-encoded password", hex::encode(password)),
            (
                "the base64-encoded password",
                base64::engine::general_purpose::STANDARD.encode(password),
            ),
        ] {
            assert!(
                !captured.contains(&forbidden),
                "{label} leaked into the log tail: {captured}"
            );
        }
        assert!(
            captured.contains("[redacted]"),
            "the echoed value was redacted: {captured}"
        );
    }

    #[test]
    fn secret_variants_cover_the_common_encodings() {
        // Guards the encoding table itself: raw, hex (both cases), base64
        // (std + URL-safe), percent, and JSON-escaped forms of a secret
        // with special characters are all present as needles.
        let secret = b"pa@ss \"x/y+z:w\"ord".to_vec();
        let variants = secret_variants(&secret);
        let contains = |needle: &[u8]| variants.iter().any(|variant| variant == needle);
        assert!(contains(&secret));
        assert!(contains(hex::encode(&secret).as_bytes()));
        assert!(contains(hex::encode_upper(&secret).as_bytes()));
        use base64::Engine;
        assert!(contains(
            base64::engine::general_purpose::STANDARD
                .encode(&secret)
                .as_bytes()
        ));
        assert!(contains(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(&secret)
                .as_bytes()
        ));
        let percent: String = secret.iter().map(|b| format!("%{b:02X}")).collect();
        assert!(contains(percent.as_bytes()));
        let percent_lower: String = secret.iter().map(|b| format!("%{b:02x}")).collect();
        assert!(contains(percent_lower.as_bytes()));
        // JSON short escapes (Devin T5): a tab must produce \\t, not only \\u0009.
        let tab_secret = b"pa\tss".to_vec();
        for variant in secret_variants(&tab_secret) {
            if variant == b"pa\\tss" {
                // found
            }
        }
        assert!(
            secret_variants(&tab_secret)
                .iter()
                .any(|variant| variant == b"pa\\tss"),
            "the JSON short escape of a tab is a needle"
        );
        let json_escaped: String = secret
            .iter()
            .map(|&b| match b {
                b'"' => "\\\"".to_string(),
                b'\\' => "\\\\".to_string(),
                0x20..=0x7E => (b as char).to_string(),
                _ => format!("\\u{b:04x}"),
            })
            .collect();
        assert!(contains(json_escaped.as_bytes()));
    }

    #[test]
    fn retry_does_not_reset_the_shared_budget() {
        // (d4 / Devin T4): the deadline spans BOTH attempts. Attempt 1
        // CONSUMES MOST OF THE BUDGET (sleeps 500 ms of the 600 ms, then
        // fails with 101); attempt 2 stalls. With the shared deadline,
        // attempt 2 is killed ~100 ms in and the total stays ~600 ms
        // (GREEN). With the reset bug (attempt 2 handed a FRESH 600 ms
        // deadline — the sabotage RUN at this head: attempt 2's call site
        // passes now + total_budget), attempt 2 runs its own full budget
        // and the total lands ~1.1 s, outside the 1.5x bound (RED).
        let work = tempfile::tempdir().unwrap();
        let binary = write_fake_genpolicy(
            work.path(),
            r#"#!/bin/sh
case "$REGISTRY_AUTH_FILE" in
  */anonymous-registry/config.json)
    sleep 30
    ;;
  *)
    sleep 0.5
    exit 101
    ;;
esac
"#,
        );
        let budget = std::time::Duration::from_millis(600);
        let started = std::time::Instant::now();
        let error = current_thread_runtime()
            .block_on(async {
                run_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    budget,
                    None,
                    "test://d4-workload-image",
                )
                .await
            })
            .expect_err("the stalled retry must hit the SHARED budget");
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("genpolicy timed out: attempt 2"),
            "error names the retry attempt: {rendered}"
        );
        let elapsed = started.elapsed();
        assert!(
            elapsed < budget + budget.div_f32(2.0),
            "total elapsed {elapsed:?} stays within ~1.5x the single budget {budget:?} — the deadline is shared, not reset"
        );
    }

    #[test]
    fn first_attempt_failure_succeeds_through_the_anonymous_retry() {
        // (d3) The retry path under the async runner: attempt 1 fails
        // fast, attempt 2 (anonymous-registry env) succeeds.
        let work = tempfile::tempdir().unwrap();
        let binary = write_fake_genpolicy(
            work.path(),
            r#"#!/bin/sh
case "$REGISTRY_AUTH_FILE" in
  */anonymous-registry/config.json)
    test "$(cat "$REGISTRY_AUTH_FILE")" = '{"auths":{}}'
    printf 'anonymous policy'
    exit 0
    ;;
esac
echo registry client failed >&2
exit 101
"#,
        );
        let output = current_thread_runtime()
            .block_on(async {
                run_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    std::time::Duration::from_secs(30),
                    None,
                    "test://workload-image",
                )
                .await
            })
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"anonymous policy");
    }

    #[tokio::test]
    async fn concurrency_cap_queues_a_third_genpolicy_step() {
        // (Devin T5): at most max_concurrent generator steps run at once;
        // the third waits for a permit instead of starting under the same
        // container limits. PROVEN BY EVENT ORDER, not wall-clock
        // thresholds: every child appends "start"/"end" markers (with its
        // pid) to one O_APPEND file in the shared work dir, and the third
        // starter's start marker must appear AFTER some other child's end
        // marker — a permit frees only when a whole step completes, so a
        // third child can only spawn after an earlier one ended. With the
        // cap removed (sabotage RUN at this head: the semaphore acquire
        // dropped) all three start markers precede the first end marker
        // and the ordering assert goes RED. Immune to box load: no timing
        // bounds on the children themselves.
        let work = tempfile::tempdir().unwrap();
        let binary = write_fake_genpolicy(
            work.path(),
            "#!/bin/sh\necho \"start $$\" >> markers.log\nsleep 1\necho \"end $$\" >> markers.log\n",
        );
        let budget = std::time::Duration::from_secs(30);
        let cap = std::sync::Arc::new(tokio::sync::Semaphore::new(2));
        let mut handles = Vec::new();
        for _ in 0..3 {
            let binary = binary.clone();
            let work_dir = work.path().to_path_buf();
            let permits = cap.clone();
            handles.push(tokio::spawn(async move {
                run_genpolicy(
                    &binary,
                    &[],
                    &work_dir,
                    budget,
                    Some(&*permits),
                    "test://t5-workload-image",
                )
                .await
                .is_ok()
            }));
        }
        for handle in handles {
            assert!(handle.await.unwrap(), "every step succeeds");
        }
        let markers = fs::read_to_string(work.path().join("markers.log"))
            .expect("children appended their markers");
        let events: Vec<(&str, &str)> = markers
            .lines()
            .filter_map(|line| {
                let mut parts = line.split_whitespace();
                match (parts.next(), parts.next()) {
                    (Some(kind), Some(_pid)) => Some((kind, line)),
                    _ => None,
                }
            })
            .collect();
        let starts = events.iter().filter(|(kind, _)| *kind == "start").count();
        let ends = events.iter().filter(|(kind, _)| *kind == "end").count();
        assert_eq!((starts, ends), (3, 3), "marker log: {markers}");
        // The third START (by append order) must come after some END.
        let mut starts_seen = 0;
        let mut ends_before_third_start = 0;
        for (kind, _) in &events {
            if *kind == "start" {
                starts_seen += 1;
                if starts_seen == 3 {
                    break;
                }
            } else if *kind == "end" {
                ends_before_third_start += 1;
            }
        }
        assert_eq!(starts_seen, 3, "marker log: {markers}");
        assert!(
            ends_before_third_start >= 1,
            "the third child started only after an earlier step released its permit; marker log: {markers}"
        );
    }

    #[test]
    fn overlapping_needles_redact_longest_first() {
        // (Devin T3): when one needle's text contains another (here the
        // username is a PREFIX of the password, so the decoded pair embeds
        // both), a shorter-first pass replaces the inner match first,
        // breaks the longer needle, and leaves readable fragments
        // ("-secret-tail" below). Needles are applied LONGEST-FIRST.
        let work = tempfile::tempdir().unwrap();
        let user = "abcd";
        let password = "abcd-secret-tail";
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        let docker_dir = work.path().join("creds");
        fs::create_dir_all(&docker_dir).unwrap();
        let auth_file = docker_dir.join("config.json");
        fs::write(
            &auth_file,
            format!(r#"{{"auths":{{"ghcr.io":{{"auth":"{token}"}}}}}}"#),
        )
        .unwrap();
        let binary = write_fake_genpolicy(
            work.path(),
            "#!/bin/sh\ncut -d'\"' -f8 \"$REGISTRY_AUTH_FILE\" | base64 -d\necho\n",
        );
        let logs = SharedLogSink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        let env = Some((auth_file.as_path(), docker_dir.as_path()));
        tracing::subscriber::with_default(subscriber, || {
            current_thread_runtime().block_on(async {
                let success = attempt_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    env,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                    1,
                    "configured",
                    "test://t3-image",
                )
                .await
                .unwrap();
                assert!(success.status.success());
            })
        });
        let captured = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
        assert!(
            !captured.contains("secret-tail"),
            "the password fragment survived an overlapping replacement: {captured}"
        );
        assert!(
            !captured.contains("abcd:"),
            "the pair structure survived: {captured}"
        );
        assert!(
            captured.contains("[redacted]"),
            "the pair was replaced wholesale: {captured}"
        );
    }

    #[test]
    fn short_credential_values_still_get_redacted() {
        // (Devin T4): a password under four bytes is still a credential;
        // the >=4 floor applies only to ENCODING expansion, never to the
        // raw value needles.
        let work = tempfile::tempdir().unwrap();
        let user = "qa";
        let password = "Zq9";
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        let docker_dir = work.path().join("creds");
        fs::create_dir_all(&docker_dir).unwrap();
        let auth_file = docker_dir.join("config.json");
        fs::write(
            &auth_file,
            format!(r#"{{"auths":{{"ghcr.io":{{"auth":"{token}"}}}}}}"#),
        )
        .unwrap();
        let binary = write_fake_genpolicy(
            work.path(),
            "#!/bin/sh\ncut -d'\"' -f8 \"$REGISTRY_AUTH_FILE\" | base64 -d | cut -d: -f2\necho SHORTOK\n",
        );
        let logs = SharedLogSink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        let env = Some((auth_file.as_path(), docker_dir.as_path()));
        tracing::subscriber::with_default(subscriber, || {
            current_thread_runtime().block_on(async {
                let success = attempt_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    env,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                    1,
                    "configured",
                    "test://t4-image",
                )
                .await
                .unwrap();
                assert!(success.status.success());
            })
        });
        let captured = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
        let tail_line = captured
            .lines()
            .find(|line| line.contains("stdout_tail="))
            .expect("a finish line with a tail");
        let tail_field = tail_line.split("stdout_tail=").nth(1).unwrap_or("");
        assert!(
            !tail_field.contains(password),
            "the 3-byte password survived redaction: {tail_line}"
        );
        assert!(
            tail_field.contains("SHORTOK"),
            "benign content still logged: {tail_line}"
        );
    }

    #[test]
    fn tab_short_escape_password_is_redacted() {
        // (Devin T5): serializers emit the SHORT escapes (\\t before
        // \\u0009); a tab-containing password quoted that way must match a
        // needle. The child emits the serde-style short-escaped form.
        let work = tempfile::tempdir().unwrap();
        let user = "qa-user";
        let password = "pa\tss-TabX9";
        use base64::Engine;
        let token = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{password}"));
        let docker_dir = work.path().join("creds");
        fs::create_dir_all(&docker_dir).unwrap();
        let auth_file = docker_dir.join("config.json");
        fs::write(
            &auth_file,
            format!(r#"{{"auths":{{"ghcr.io":{{"auth":"{token}"}}}}}}"#),
        )
        .unwrap();
        let binary = write_fake_genpolicy(
            work.path(),
            "#!/bin/sh\ncut -d'\"' -f8 \"$REGISTRY_AUTH_FILE\" | base64 -d | sed 's/\\x09/\\\\t/g'\necho\n",
        );
        let logs = SharedLogSink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(logs.clone())
            .with_ansi(false)
            .finish();
        let env = Some((auth_file.as_path(), docker_dir.as_path()));
        tracing::subscriber::with_default(subscriber, || {
            current_thread_runtime().block_on(async {
                let success = attempt_genpolicy(
                    &binary,
                    &[],
                    work.path(),
                    env,
                    tokio::time::Instant::now() + std::time::Duration::from_secs(5),
                    1,
                    "configured",
                    "test://t5-image",
                )
                .await
                .unwrap();
                assert!(success.status.success());
            })
        });
        let captured = String::from_utf8_lossy(&logs.0.lock().unwrap()).to_string();
        assert!(
            !captured.contains("TabX9"),
            "the tab-containing password survived its JSON short-escape quoting: {captured}"
        );
        assert!(
            captured.contains("[redacted]"),
            "the short-escaped form was redacted: {captured}"
        );
    }
}
