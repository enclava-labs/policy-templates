use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use anyhow::{bail, Context, Result};
use serde::Serialize;
use serde_json::{json, Map, Value};

use crate::descriptor::{DeploymentDescriptor, EnvVar, Resources};

const KATA_RUNTIME_HANDLER_ANNOTATION: &str = "io.containerd.cri.runtime-handler";
const KATA_KERNEL_PARAMS_ANNOTATION: &str = "io.katacontainers.config.hypervisor.kernel_params";
const KATA_HYPERVISOR_CC_INIT_DATA_ANNOTATION: &str =
    "io.katacontainers.config.hypervisor.cc_init_data";
const KATA_RUNTIME_CC_INIT_DATA_ANNOTATION: &str = "io.katacontainers.config.runtime.cc_init_data";
const KATA_RUNTIME_HANDLER: &str = "kata-qemu-snp";
const KBS_URL: &str = "http://kbs-service.trustee-operator-system.svc.cluster.local:8080";
const ATTESTATION_PROXY_IMAGE_REPO: &str = "ghcr.io/enclava-ai/attestation-proxy";
const CADDY_INGRESS_IMAGE_REPO: &str = "ghcr.io/enclava-ai/caddy-ingress";
const ENCLAVA_WAIT_EXEC_PATH: &str = "/usr/local/bin/enclava-wait-exec";

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
            "containers": [
                app_container(descriptor),
                attestation_proxy_container(descriptor)?,
                tenant_ingress_container(descriptor),
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
            format!("agent.aa_kbc_params=cc_kbc::{KBS_URL} agent.guest_components_rest_api=all"),
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
            "ghcr.io/enclava-ai/enclava-init@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string()
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

fn mount_with_subpath(name: &str, mount_path: &str, sub_path: &str) -> Value {
    json!({
        "name": name,
        "mountPath": mount_path,
        "subPath": sub_path,
    })
}

fn storage_subdir(path: &str) -> String {
    path.trim_start_matches('/').replace('/', "-")
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
    let mut volume_mounts = vec![
        mount("startup", "/startup", true),
        mount("unlock-socket", "/run/enclava", false),
        mount("state-mount", "/state", false),
    ];
    for storage_path in oci
        .mounts
        .iter()
        .filter(|mount| mount.source == "state-mount")
        .map(|mount| mount.destination.as_str())
        .filter(|path| *path != "/state")
    {
        volume_mounts.push(mount_with_subpath(
            "state-mount",
            storage_path,
            &storage_subdir(storage_path),
        ));
    }

    let env = with_kubernetes_service_env(
        oci.env
            .iter()
            .map(|env| value_env(&env.name, &env.value))
            .collect(),
    );

    json!({
        "name": "web",
        "image": descriptor.image_ref,
        "command": [ENCLAVA_WAIT_EXEC_PATH],
        "args": oci.args,
        "env": env,
        "ports": oci.ports.iter().map(|port| json!({
            "containerPort": port.container_port,
            "protocol": port.protocol,
        })).collect::<Vec<_>>(),
        "volumeMounts": volume_mounts,
        "securityContext": security_context(10001, 10001, true, false, false, caps(&["ALL"], &[])),
        "resources": ResourcesYaml::from(&oci.resources),
    })
}

fn attestation_proxy_container(descriptor: &DeploymentDescriptor) -> Result<Value> {
    Ok(json!({
        "name": "attestation-proxy",
        "image": image_ref(ATTESTATION_PROXY_IMAGE_REPO, &descriptor.sidecars.attestation_proxy_digest),
        "command": ["/attestation-proxy"],
        "ports": [
            {"containerPort": 8081, "name": "attest-http"},
            {"containerPort": 8443, "name": "attestation"},
        ],
        "env": with_kubernetes_service_env(vec![
            value_env("ATTESTATION_WORKLOAD_CONTAINER", "web"),
            field_env("ATTESTATION_POD_NAME", "metadata.name"),
            field_env("ATTESTATION_POD_NAMESPACE", "metadata.namespace"),
            value_env("ATTESTATION_PROFILE", "coco-sev-snp"),
            value_env("ATTESTATION_RUNTIME_CLASS", "kata-qemu-snp"),
            value_env("ATTESTATION_WORKLOAD_IMAGE", descriptor.image_ref.clone()),
            value_env("ATTESTATION_TLS_PORT", "8443"),
            value_env("TEE_DOMAIN", descriptor.tee_domain.clone()),
            value_env("STORAGE_OWNERSHIP_MODE", storage_ownership_mode(&descriptor.unlock_mode)?),
            value_env("INSTANCE_ID", format!("{}-{}", descriptor.namespace, descriptor.app_name)),
            value_env("OWNER_CIPHERTEXT_BACKEND", "kbs-resource"),
            value_env("OWNER_SEED_HANDOFF_SLOTS", "app-data"),
            value_env("OWNERSHIP_MOUNT_PATH", "/run/ownership-signal"),
            value_env("KBS_RESOURCE_CACHE_SECONDS", "300"),
            value_env("KBS_RESOURCE_FAILURE_CACHE_SECONDS", "30"),
            value_env("KBS_FETCH_RETRIES", "120"),
            value_env("KBS_FETCH_RETRY_SLEEP_SECONDS", "2"),
            value_env("KBS_FETCH_MAX_SLEEP_SECONDS", "10"),
            value_env("KBS_FETCH_REQUEST_TIMEOUT_SECONDS", "10"),
            value_env("ENCLAVA_INIT_UNLOCK_SOCKET", "/run/enclava/unlock.sock"),
        ]),
        "volumeMounts": [
            mount("ownership-signal", "/run/ownership-signal", false),
            mount("unlock-socket", "/run/enclava", false),
        ],
        "securityContext": security_context(65532, 65532, true, false, false, caps(&["ALL"], &[])),
        "resources": resources("100m", "128Mi", "500m", "256Mi"),
    }))
}

fn tenant_ingress_container(descriptor: &DeploymentDescriptor) -> Value {
    json!({
        "name": "tenant-ingress",
        "image": image_ref(CADDY_INGRESS_IMAGE_REPO, &descriptor.sidecars.caddy_digest),
        "command": [ENCLAVA_WAIT_EXEC_PATH],
        "args": ["caddy", "run", "--config", "/etc/caddy/Caddyfile"],
        "ports": [
            {"containerPort": 443, "name": "https"},
        ],
        "env": with_kubernetes_service_env(vec![
            field_env("POD_NAME", "metadata.name"),
            field_env("POD_NAMESPACE", "metadata.namespace"),
            value_env("CADDY_SEED_PATH", "/run/enclava/seeds/caddy/seed"),
            value_env("VOLUME_MOUNT_POINT", "/tls-state"),
            value_env("XDG_DATA_HOME", "/tls-state/caddy"),
            value_env("XDG_CONFIG_HOME", "/tls-state/caddy/config"),
            value_env("HOME", "/tls-state"),
            value_env("ENCLAVA_CONTAINER_NAME", "tenant-ingress"),
            value_env("ENCLAVA_STARTED_DIR", "/run/enclava/containers"),
            value_env("ENCLAVA_INIT_READY_FILE", "/run/enclava/init-ready"),
        ]),
        "volumeMounts": [
            mount("tenant-ingress-caddyfile", "/etc/caddy", true),
            mount("unlock-socket", "/run/enclava", false),
        ],
        "securityContext": security_context(10002, 10002, false, false, false, caps(&["ALL"], &["NET_BIND_SERVICE"])),
        "resources": resources("100m", "128Mi", "500m", "256Mi"),
    })
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
            value_env("ENCLAVA_INIT_UNLOCK_SOCKET_GID", "65532"),
            value_env("ENCLAVA_INIT_WAIT_FOR_CONTAINERS", "web,tenant-ingress"),
        ]),
        "volumeMounts": [
            mount("state-mount", "/state", false),
            mount("tls-state-mount", "/state/tls-state", false),
            mount("unlock-socket", "/run/enclava", false),
            mount("enclava-init-config", "/etc/enclava-init", true),
        ],
        "volumeDevices": [
            {"name": "state", "devicePath": "/dev/csi0"},
            {"name": "tls-state", "devicePath": "/dev/csi1"},
        ],
        "securityContext": security_context(0, 0, true, true, true, caps(&["ALL"], &["$(privileged_caps)"])),
        "resources": resources("50m", "64Mi", "250m", "128Mi"),
    }))
}

fn cap_volumes(descriptor: &DeploymentDescriptor) -> Vec<Value> {
    vec![
        json!({"name": "logs", "emptyDir": {}}),
        json!({"name": "ownership-signal", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        config_map_volume(
            "tenant-ingress-caddyfile",
            format!("{}-tenant-ingress", descriptor.app_name),
        ),
        config_map_volume("startup", format!("{}-startup", descriptor.app_name)),
        json!({"name": "unlock-socket", "emptyDir": {"medium": "Memory", "sizeLimit": "1Mi"}}),
        json!({"name": "state-mount", "emptyDir": {}}),
        json!({"name": "tls-state-mount", "emptyDir": {}}),
        config_map_volume(
            "enclava-init-config",
            format!("{}-enclava-init", descriptor.app_name),
        ),
    ]
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
    use crate::descriptor::tests::fixed_descriptor;

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
        assert!(!invocation.manifest_yaml.contains("initContainers:"));
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
        assert!(!invocation.manifest_yaml.contains("mountPropagation"));
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
        assert!(invocation
            .manifest_yaml
            .contains("name: ENCLAVA_INIT_UNLOCK_SOCKET"));
        assert!(invocation
            .manifest_yaml
            .contains("value: /run/enclava/unlock.sock"));
        assert!(invocation
            .manifest_yaml
            .contains("name: ENCLAVA_INIT_UNLOCK_SOCKET_GID"));
        assert!(invocation.manifest_yaml.contains("value: '65532'"));
        assert!(invocation
            .manifest_yaml
            .contains("image: ghcr.io/enclava-ai/demo@sha256:aaaa"));
        assert!(invocation
            .manifest_yaml
            .contains("- /usr/local/bin/enclava-wait-exec"));
        assert!(invocation.manifest_yaml.contains("$(privileged_caps)"));
        assert!(invocation.manifest_yaml.contains("readinessProbe:"));
        assert!(invocation.manifest_yaml.contains("--probe-ready"));
        assert!(invocation.manifest_yaml.contains("name: XDG_CONFIG_HOME"));
        assert!(invocation
            .manifest_yaml
            .contains("value: /tls-state/caddy/config"));
        assert!(invocation.manifest_yaml.contains("- name: A"));
        assert!(invocation.manifest_yaml.contains("value: '1'"));
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
