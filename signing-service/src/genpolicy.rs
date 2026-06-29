use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::descriptor::{Capabilities, DeploymentDescriptor, EnvVar, OciRuntimeSpec, Resources};

const KATA_RUNTIME_HANDLER_ANNOTATION: &str = "io.containerd.cri.runtime-handler";
const KATA_KERNEL_PARAMS_ANNOTATION: &str = "io.katacontainers.config.hypervisor.kernel_params";
const KATA_HYPERVISOR_CC_INIT_DATA_ANNOTATION: &str =
    "io.katacontainers.config.hypervisor.cc_init_data";
const KATA_RUNTIME_CC_INIT_DATA_ANNOTATION: &str = "io.katacontainers.config.runtime.cc_init_data";
const KATA_RUNTIME_HANDLER: &str = "kata-qemu-snp";
const DEFAULT_KBS_URL: &str = "http://kbs-service.trustee-operator-system.svc.cluster.local:8080";
const DEFAULT_ATTESTATION_PROXY_IMAGE_REPO: &str = "ghcr.io/enclava-labs/attestation-proxy";
const CADDY_INGRESS_IMAGE_REPO: &str = "ghcr.io/enclava-labs/caddy-ingress";
const ENCLAVA_WAIT_EXEC_PATH: &str = "/enclava-tools/enclava-wait-exec";
const ENCLAVA_TOOLS_INIT_COMMAND: &str = "cp /usr/local/bin/enclava-wait-exec /work/enclava-wait-exec && chmod 0555 /work/enclava-wait-exec && install -d -m 02770 -o 0 -g 10001 /run/enclava/containers && printf 'not-ready\\n' > /run/enclava/init-ready && chmod 0644 /run/enclava/init-ready";
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
    "while true; do\n",
    "  rc=0\n",
    "  if /usr/bin/caddy validate --config /etc/caddy/Caddyfile; then\n",
    "    /usr/bin/caddy run --config /etc/caddy/Caddyfile || rc=$?\n",
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

#[derive(Debug, Clone)]
pub struct GenpolicyConfig {
    pub binary: PathBuf,
    pub version_pin: String,
    pub rules_path: PathBuf,
    pub settings_dir: Option<PathBuf>,
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
        let manifest_yaml = render_pod_manifest(descriptor)?;
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

    pub fn run(&self, descriptor: &DeploymentDescriptor) -> Result<GeneratedAgentPolicy> {
        let invocation = self.build_invocation(descriptor)?;
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

        let output = Command::new(&self.binary)
            .args(&args)
            .current_dir(dir.path())
            .output()
            .with_context(|| format!("executing genpolicy binary {}", self.binary.display()))?;
        if !output.status.success() {
            bail!(
                "genpolicy failed with status {}: {}",
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let policy_text =
            String::from_utf8(output.stdout).context("genpolicy output is not UTF-8")?;
        Ok(GeneratedAgentPolicy {
            policy_text: normalize_cap_generated_policy(&policy_text),
            invocation,
        })
    }
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
    let mut lines = policy_text
        .split_inclusive('\n')
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let mut idx = 0;

    while idx < lines.len() {
        if !lines[idx].contains("\"User\": {") {
            idx += 1;
            continue;
        }

        let mut user_end = idx;
        let mut uid = None;
        let mut gids_start = None;
        let mut gids_end = None;

        idx += 1;
        while idx < lines.len() {
            let trimmed = lines[idx].trim();
            if let Some(raw_uid) = trimmed
                .strip_prefix("\"UID\": ")
                .and_then(|value| value.trim_end_matches(',').parse::<u32>().ok())
            {
                uid = Some(raw_uid);
            }
            if trimmed == "\"AdditionalGids\": [" {
                gids_start = Some(idx);
                let mut end = idx + 1;
                while end < lines.len() {
                    if lines[end].trim_start().starts_with(']') {
                        gids_end = Some(end);
                        break;
                    }
                    end += 1;
                }
            }
            if trimmed.starts_with('}') {
                user_end = idx;
                break;
            }
            idx += 1;
        }

        if uid.is_some_and(|uid| uid != 0) {
            if let (Some(start), Some(end)) = (gids_start, gids_end) {
                let normalized_gids = normalized_additional_gids(&lines[(start + 1)..end]);
                lines.splice((start + 1)..end, normalized_gids);
                idx = start + 1;
                continue;
            }
        }

        idx = user_end + 1;
    }

    let normalized = lines.concat();
    let normalized = normalize_cap_overlay_root_path(&normalized);
    let normalized = normalize_cap_sandbox_pidns(&normalized);
    let normalized = normalize_rootfs_propagation(&normalized);
    let normalized = normalize_cap_storage_mounts(&normalized);
    let normalized = normalize_cap_sandbox_storages(&normalized);
    let normalized = normalize_cap_extra_storages(&normalized);
    normalize_privileged_caps_placeholder(&normalized)
}

fn normalize_cap_overlay_root_path(policy_text: &str) -> String {
    const DEFAULT_ROOT_PATH: &str = r#""root_path": "/run/kata-containers/$(bundle-id)/rootfs""#;
    const OVERLAY_ROOT_PATH: &str =
        r#""root_path": "/run/kata-containers/(?:shared/containers/)?$(bundle-id)/rootfs""#;

    policy_text.replace(DEFAULT_ROOT_PATH, OVERLAY_ROOT_PATH)
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

fn normalized_additional_gids(group_lines: &[String]) -> Vec<String> {
    group_lines
        .iter()
        .filter(|line| {
            let trimmed = line.trim();
            trimmed != "0" && trimmed != "0,"
        })
        .cloned()
        .collect()
}

fn render_pod_manifest(descriptor: &DeploymentDescriptor) -> Result<String> {
    let pod_name = format!("{}-0", descriptor.app_name);
    let pod = json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": pod_name,
            "namespace": descriptor.namespace,
            "annotations": cap_runtime_annotations(),
        },
        "spec": {
            "runtimeClassName": descriptor.expected_runtime_class,
            "shareProcessNamespace": true,
            "securityContext": {
                "fsGroup": 10001,
                "supplementalGroups": [6],
            },
            "initContainers": [
                enclava_tools_container()?,
            ],
            "containers": [
                app_container(descriptor),
                attestation_proxy_container(descriptor)?,
                tenant_ingress_container(descriptor)?,
                enclava_init_container()?,
            ],
            "volumes": cap_volumes(descriptor),
        },
    });
    serde_yaml::to_string(&pod).context("rendering genpolicy pod manifest")
}

fn cap_runtime_annotations() -> BTreeMap<&'static str, String> {
    BTreeMap::from([
        (
            KATA_RUNTIME_HANDLER_ANNOTATION,
            KATA_RUNTIME_HANDLER.to_string(),
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
    ])
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
        Err(_err) if cfg!(test) => {
            "ghcr.io/enclava-labs/enclava-init@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
        }
        Err(err) => return Err(err).context("ENCLAVA_INIT_IMAGE must be set for CAP genpolicy sidecars"),
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
        && PLATFORM_MANAGED_SSH_RELAY_CAPS.iter().all(|required| {
            oci.capabilities
                .add
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case(required))
        })
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

fn app_container(descriptor: &DeploymentDescriptor) -> Value {
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
    let env = with_kubernetes_service_env(
        oci.env
            .iter()
            .map(|env| value_env(&env.name, &env.value))
            .collect(),
    );

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
    let mut env_vars = vec![
        value_env("ATTESTATION_WORKLOAD_CONTAINER", "web"),
        field_env("ATTESTATION_POD_NAME", "metadata.name"),
        field_env("ATTESTATION_POD_NAMESPACE", "metadata.namespace"),
        value_env("ATTESTATION_PROFILE", "coco-sev-snp"),
        value_env("ATTESTATION_RUNTIME_CLASS", "kata-qemu-snp"),
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
    if !descriptor_uses_platform_managed_ssh_relay(descriptor) {
        env_vars.push(value_env("CAP_CONFIG_FILE_GID", CAP_CONFIG_FILE_GID));
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
    if let Some(cert) = trustee_kbs_ca_cert_pem() {
        env_vars.push(value_env("KBS_RESOURCE_CA_CERT_PEM", cert));
    }

    Ok(json!({
        "name": "attestation-proxy",
        "image": image_ref(&attestation_proxy_image_repo(), &descriptor.sidecars.attestation_proxy_digest),
        "command": ["/attestation-proxy"],
        "ports": [
            {"containerPort": 8081, "name": "attest-http"},
            {"containerPort": 8443, "name": "attestation"},
        ],
        "env": with_kubernetes_service_env(env_vars),
        "volumeMounts": [
            mount("ownership-signal", "/run/ownership-signal", false),
            mount_with_propagation("state-mount", "/data", false, "HostToContainer"),
            mount_with_propagation("state-mount", "/state", false, "HostToContainer"),
            mount("unlock-socket", "/run/enclava", false),
            mount("unlock-channel", "/run/enclava-unlock", false),
        ],
        "securityContext": security_context(0, 0, true, false, false, caps(&["ALL"], &["CHOWN", "MKNOD", "SYS_PTRACE"])),
        "resources": resources("100m", "128Mi", "500m", "256Mi"),
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
        "image": image_ref(CADDY_INGRESS_IMAGE_REPO, &descriptor.sidecars.caddy_digest),
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
        "resources": resources("100m", "128Mi", "500m", "256Mi"),
    })
}

fn enclava_tools_container() -> Result<Value> {
    Ok(json!({
        "name": "enclava-tools",
        "image": enclava_init_image()?,
        "command": [
            "/bin/sh",
            "-eu",
            "-c",
            ENCLAVA_TOOLS_INIT_COMMAND,
        ],
        "volumeMounts": [
            mount("enclava-tools", "/work", false),
            mount("unlock-socket", "/run/enclava", false),
        ],
        "securityContext": security_context(0, 0, true, false, false, caps(&["ALL"], &[])),
        "resources": resources("10m", "16Mi", "50m", "64Mi"),
    }))
}

fn enclava_init_container() -> Result<Value> {
    Ok(json!({
        "name": "enclava-init",
        "image": enclava_init_image()?,
        "command": ["/usr/local/bin/enclava-init"],
        "readinessProbe": {
            "exec": {
                "command": ["/usr/local/bin/enclava-init", "--probe-ready"],
            },
            "failureThreshold": 17280,
            "periodSeconds": 5,
            "successThreshold": 1,
            "timeoutSeconds": 2,
        },
        "env": with_kubernetes_service_env(vec![
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
        ]),
        "volumeMounts": [
            mount_with_propagation("state-mount", "/state", false, "Bidirectional"),
            mount_with_propagation("tls-state-mount", "/state/tls-state", false, "Bidirectional"),
            mount("unlock-socket", "/run/enclava", false),
            mount("unlock-channel", "/run/enclava-unlock", false),
            mount("enclava-init-config", "/etc/enclava-init", true),
        ],
        "volumeDevices": [
            {"name": "state", "devicePath": "/dev/csi0"},
            {"name": "tls-state", "devicePath": "/dev/csi1"},
        ],
        "securityContext": security_context(0, 0, true, true, true, caps(&["ALL"], &["$(privileged_caps)"])),
        "resources": resources("50m", "64Mi", "250m", "512Mi"),
    }))
}

fn cap_volumes(descriptor: &DeploymentDescriptor) -> Vec<Value> {
    let mut volumes = vec![
        json!({"name": "logs", "emptyDir": {}}),
        json!({"name": "ownership-signal", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        config_map_volume(
            "tenant-ingress-caddyfile",
            format!("{}-tenant-ingress", descriptor.app_name),
        ),
        json!({"name": "enclava-tools", "emptyDir": {}}),
        json!({"name": "unlock-socket", "emptyDir": {"medium": "Memory", "sizeLimit": "16Mi"}}),
        json!({"name": "unlock-channel", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        json!({"name": "state-mount", "emptyDir": {}}),
        json!({"name": "tls-state-mount", "emptyDir": {}}),
        config_map_volume(
            "enclava-init-config",
            format!("{}-enclava-init", descriptor.app_name),
        ),
    ];
    if descriptor_uses_startup_fallback(descriptor) {
        volumes.insert(
            3,
            config_map_volume("startup", format!("{}-startup", descriptor.app_name)),
        );
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
    fn invocation_pins_binary_settings_and_manifest_input() {
        let config = GenpolicyConfig {
            binary: PathBuf::from("/opt/kata/bin/genpolicy"),
            version_pin: "kata-containers-3.12.0".to_string(),
            rules_path: PathBuf::from("/etc/enclava/genpolicy/rules.rego"),
            settings_dir: Some(PathBuf::from("/etc/enclava/genpolicy")),
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
        assert!(invocation
            .manifest_yaml
            .contains("image: ghcr.io/enclava-labs/attestation-proxy@sha256:1111"));
        assert!(invocation
            .manifest_yaml
            .contains("image: ghcr.io/enclava-labs/caddy-ingress@sha256:2222"));
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
    }

    #[test]
    fn enclava_tools_manifest_is_an_init_container_like_live_cap_manifest() {
        let manifest: Value =
            serde_yaml::from_str(&render_pod_manifest(&fixed_descriptor()).unwrap()).unwrap();
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
        assert_eq!(
            enclava_tools.pointer("/command/3"),
            Some(&json!(ENCLAVA_TOOLS_INIT_COMMAND))
        );
        let tool_mounts = enclava_tools
            .pointer("/volumeMounts")
            .and_then(Value::as_array)
            .expect("enclava-tools volumeMounts are present");
        assert!(tool_mounts.iter().any(|mount| {
            mount.pointer("/name") == Some(&json!("unlock-socket"))
                && mount.pointer("/mountPath") == Some(&json!("/run/enclava"))
                && mount.pointer("/readOnly") == Some(&json!(false))
        }));

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
    fn enclava_init_env_matches_live_cap_sidecar_contract() {
        let manifest: Value =
            serde_yaml::from_str(&render_pod_manifest(&fixed_descriptor()).unwrap()).unwrap();
        let containers = manifest
            .pointer("/spec/containers")
            .and_then(Value::as_array)
            .expect("CAP genpolicy manifest must include containers");
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

        let container = app_container(&descriptor);
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

        let volumes = cap_volumes(&descriptor);
        assert!(
            volumes
                .iter()
                .all(|volume| volume.pointer("/name") != Some(&json!("startup"))),
            "explicit-command relay apps must not include unused startup volume"
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

        let manifest = render_pod_manifest(&descriptor).unwrap();

        assert!(manifest.contains("mountPath: /state"));
        assert_eq!(manifest.matches("mountPath: /data").count(), 1);
        assert!(!manifest.contains("subPath:"));
    }

    #[test]
    fn auto_unlock_descriptor_renders_auto_unlock_proxy_mode() {
        let mut descriptor = fixed_descriptor();
        descriptor.unlock_mode = "auto".to_string();
        let manifest = render_pod_manifest(&descriptor).unwrap();
        assert!(manifest.contains("name: STORAGE_OWNERSHIP_MODE"));
        assert!(manifest.contains("value: auto-unlock"));
    }

    #[test]
    fn invalid_unlock_mode_is_rejected() {
        let mut descriptor = fixed_descriptor();
        descriptor.unlock_mode = "manual".to_string();
        let err = render_pod_manifest(&descriptor).unwrap_err();
        assert!(err.to_string().contains("descriptor.unlock_mode"));
    }

    #[test]
    fn rejects_unpinned_version_label() {
        let config = GenpolicyConfig {
            binary: PathBuf::from("genpolicy"),
            version_pin: "kata-containers/genpolicy-unpinned-dev".to_string(),
            rules_path: PathBuf::from("rules.rego"),
            settings_dir: None,
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
    fn removes_root_supplemental_group_from_non_root_generated_users() {
        let policy = r#"policy_data := {
  "containers": [
    {
      "OCI": {
        "Process": {
          "User": {
            "UID": 65532,
            "GID": 65532,
            "AdditionalGids": [
              0,
              6,
              10001,
              65532
            ],
            "Username": ""
          }
        }
      }
    },
    {
      "OCI": {
        "Process": {
          "User": {
            "UID": 0,
            "GID": 0,
            "AdditionalGids": [
              0,
              6,
              10001
            ],
            "Username": ""
          }
        }
      }
    }
  ]
}
"#;

        let normalized = normalize_cap_generated_policy(policy);

        assert!(normalized.contains(
            r#""UID": 65532,
            "GID": 65532,
            "AdditionalGids": [
              6,
              10001,
              65532
            ]"#
        ));
        assert!(normalized.contains(
            r#""UID": 0,
            "GID": 0,
            "AdditionalGids": [
              0,
              6,
              10001
            ]"#
        ));
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
    fn allows_kata_overlay_shared_container_rootfs_paths() {
        let policy = r#"policy_data := {
  "common": {
    "root_path": "/run/kata-containers/$(bundle-id)/rootfs"
  }
}
"#;

        let normalized = normalize_cap_generated_policy(policy);

        assert!(normalized.contains(
            r#""root_path": "/run/kata-containers/(?:shared/containers/)?$(bundle-id)/rootfs""#
        ));
        assert!(!normalized.contains(r#""root_path": "/run/kata-containers/$(bundle-id)/rootfs""#));
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
}
