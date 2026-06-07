use anyhow::{anyhow, bail, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::canonical::{ce_v1_bytes, ce_v1_hash};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignerIdentity {
    pub subject: String,
    pub issuer: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnvVar {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Port {
    pub container_port: u32,
    pub protocol: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    pub source: String,
    pub destination: String,
    #[serde(rename = "type")]
    pub mount_type: String,
    #[serde(default)]
    pub options: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Capabilities {
    #[serde(default)]
    pub add: Vec<String>,
    #[serde(default)]
    pub drop: Vec<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SecurityContext {
    pub run_as_user: u32,
    pub run_as_group: u32,
    pub read_only_root_fs: bool,
    pub allow_privilege_escalation: bool,
    pub privileged: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Resources {
    #[serde(default)]
    pub requests: Vec<EnvVar>,
    #[serde(default)]
    pub limits: Vec<EnvVar>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OciRuntimeSpec {
    pub command: Vec<String>,
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<EnvVar>,
    #[serde(default)]
    pub ports: Vec<Port>,
    #[serde(default)]
    pub mounts: Vec<Mount>,
    #[serde(default)]
    pub capabilities: Capabilities,
    #[serde(default)]
    pub security_context: SecurityContext,
    #[serde(default)]
    pub resources: Resources,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sidecars {
    pub attestation_proxy_digest: String,
    pub caddy_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentDescriptor {
    pub schema_version: String,
    pub org_id: Uuid,
    pub org_slug: String,
    pub app_id: Uuid,
    pub app_name: String,
    pub deploy_id: Uuid,
    pub created_at: DateTime<Utc>,
    #[serde(with = "hex_bytes32")]
    pub nonce: [u8; 32],

    pub app_domain: String,
    pub tee_domain: String,
    #[serde(default)]
    pub custom_domains: Vec<String>,

    pub namespace: String,
    pub service_account: String,
    #[serde(with = "hex_bytes32")]
    pub identity_hash: [u8; 32],

    pub image_ref: String,
    pub image_digest: String,
    pub signer_identity: SignerIdentity,
    pub oci_runtime_spec: OciRuntimeSpec,
    pub sidecars: Sidecars,
    #[serde(default)]
    pub api_signing_pubkey: String,

    #[serde(with = "hex_bytes32")]
    pub expected_firmware_measurement: [u8; 32],
    pub expected_runtime_class: String,
    pub kbs_resource_path: String,
    pub unlock_mode: String,

    pub policy_template_id: String,
    #[serde(with = "hex_bytes32")]
    pub policy_template_sha256: [u8; 32],
    pub platform_release_version: String,

    #[serde(with = "hex_bytes32")]
    #[serde(default)]
    pub expected_agent_policy_hash: [u8; 32],
    #[serde(with = "hex_bytes32")]
    pub expected_cc_init_data_hash: [u8; 32],
    #[serde(with = "hex_bytes32")]
    pub expected_kbs_policy_hash: [u8; 32],
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DeploymentDescriptorEnvelope {
    pub descriptor: DeploymentDescriptor,
    #[serde(with = "hex_signature")]
    pub signature: Signature,
    pub signing_key_id: String,
    #[serde(with = "hex_pubkey")]
    pub signing_pubkey: VerifyingKey,
}

pub fn verify_descriptor<'a>(
    envelope: &'a DeploymentDescriptorEnvelope,
    expected_pubkey: &VerifyingKey,
) -> Result<&'a DeploymentDescriptor> {
    if envelope.signing_pubkey.to_bytes() != expected_pubkey.to_bytes() {
        bail!("descriptor signing pubkey does not match verified keyring member");
    }
    let bytes = descriptor_canonical_bytes(&envelope.descriptor);
    expected_pubkey
        .verify(&bytes, &envelope.signature)
        .map_err(|err| anyhow!("descriptor signature verification failed: {err}"))?;
    Ok(&envelope.descriptor)
}

pub fn canonical_signer_bytes(s: &SignerIdentity) -> [u8; 32] {
    ce_v1_hash(&[
        ("subject", s.subject.as_bytes()),
        ("issuer", s.issuer.as_bytes()),
    ])
}

pub fn canonical_sidecar_map_bytes(s: &Sidecars) -> [u8; 32] {
    ce_v1_hash(&[
        ("attestation_proxy", s.attestation_proxy_digest.as_bytes()),
        ("caddy", s.caddy_digest.as_bytes()),
    ])
}

fn canonical_string_list_bytes(items: &[String]) -> [u8; 32] {
    let records: Vec<(String, Vec<u8>)> = items
        .iter()
        .enumerate()
        .map(|(idx, value)| (format!("i{idx}"), value.as_bytes().to_vec()))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, value)| (label.as_str(), value.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_env_bytes(env: &[EnvVar]) -> [u8; 32] {
    let mut sorted: Vec<&EnvVar> = env.iter().collect();
    sorted.sort_by(|a, b| a.name.cmp(&b.name));
    let records: Vec<(String, Vec<u8>)> = sorted
        .iter()
        .map(|entry| (entry.name.clone(), entry.value.as_bytes().to_vec()))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, value)| (label.as_str(), value.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_ports_bytes(ports: &[Port]) -> [u8; 32] {
    let records: Vec<(String, Vec<u8>)> = ports
        .iter()
        .enumerate()
        .map(|(idx, port)| {
            let mut value = Vec::with_capacity(4 + port.protocol.len());
            value.extend_from_slice(&port.container_port.to_be_bytes());
            value.extend_from_slice(port.protocol.as_bytes());
            (format!("p{idx}"), value)
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, value)| (label.as_str(), value.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_mounts_bytes(mounts: &[Mount]) -> [u8; 32] {
    let records: Vec<(String, [u8; 32])> = mounts
        .iter()
        .enumerate()
        .map(|(idx, mount)| {
            (
                format!("m{idx}"),
                ce_v1_hash(&[
                    ("source", mount.source.as_bytes()),
                    ("destination", mount.destination.as_bytes()),
                    ("type", mount.mount_type.as_bytes()),
                    ("options", &canonical_string_list_bytes(&mount.options)),
                ]),
            )
        })
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, value)| (label.as_str(), value.as_slice()))
        .collect();
    ce_v1_hash(&refs)
}

fn canonical_secctx_bytes(security: &SecurityContext) -> [u8; 32] {
    let user = security.run_as_user.to_be_bytes();
    let group = security.run_as_group.to_be_bytes();
    let flags = [
        security.read_only_root_fs as u8,
        security.allow_privilege_escalation as u8,
        security.privileged as u8,
    ];
    ce_v1_hash(&[
        ("run_as_user", &user),
        ("run_as_group", &group),
        ("flags", &flags),
    ])
}

fn canonical_resources_bytes(resources: &Resources) -> [u8; 32] {
    ce_v1_hash(&[
        ("requests", &canonical_env_bytes(&resources.requests)),
        ("limits", &canonical_env_bytes(&resources.limits)),
    ])
}

pub fn canonical_oci_spec_bytes(oci: &OciRuntimeSpec) -> [u8; 32] {
    ce_v1_hash(&[
        ("command", &canonical_string_list_bytes(&oci.command)),
        ("args", &canonical_string_list_bytes(&oci.args)),
        ("env", &canonical_env_bytes(&oci.env)),
        ("ports", &canonical_ports_bytes(&oci.ports)),
        ("mounts", &canonical_mounts_bytes(&oci.mounts)),
        (
            "capabilities_add",
            &canonical_string_list_bytes(&oci.capabilities.add),
        ),
        (
            "capabilities_drop",
            &canonical_string_list_bytes(&oci.capabilities.drop),
        ),
        (
            "security_context",
            &canonical_secctx_bytes(&oci.security_context),
        ),
        ("resources", &canonical_resources_bytes(&oci.resources)),
    ])
}

pub fn descriptor_canonical_bytes(descriptor: &DeploymentDescriptor) -> Vec<u8> {
    let sub = DescriptorSubHashes::new(descriptor);
    let records = descriptor_records(descriptor, b"enclava-deployment-descriptor-v1", true, &sub);
    ce_v1_bytes(&records)
}

pub fn descriptor_core_canonical_bytes(descriptor: &DeploymentDescriptor) -> Vec<u8> {
    let sub = DescriptorSubHashes::new(descriptor);
    let records = descriptor_records(
        descriptor,
        b"enclava-deployment-descriptor-core-v1",
        false,
        &sub,
    );
    ce_v1_bytes(&records)
}

pub fn descriptor_core_hash(descriptor: &DeploymentDescriptor) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(descriptor_core_canonical_bytes(descriptor)).into()
}

fn descriptor_records<'a>(
    descriptor: &'a DeploymentDescriptor,
    purpose: &'a [u8],
    include_chain_anchors: bool,
    sub: &'a DescriptorSubHashes,
) -> Vec<(&'a str, &'a [u8])> {
    let mut records = vec![
        ("purpose", purpose),
        ("schema_version", descriptor.schema_version.as_bytes()),
        ("org_id", descriptor.org_id.as_bytes().as_slice()),
        ("org_slug", descriptor.org_slug.as_bytes()),
        ("app_id", descriptor.app_id.as_bytes().as_slice()),
        ("app_name", descriptor.app_name.as_bytes()),
        ("deploy_id", descriptor.deploy_id.as_bytes().as_slice()),
        ("created_at", sub.created_at.as_bytes()),
        ("nonce", descriptor.nonce.as_slice()),
        ("app_domain", descriptor.app_domain.as_bytes()),
        ("tee_domain", descriptor.tee_domain.as_bytes()),
        ("custom_domains", sub.custom_domains_hash.as_slice()),
        ("namespace", descriptor.namespace.as_bytes()),
        ("service_account", descriptor.service_account.as_bytes()),
        ("identity_hash", descriptor.identity_hash.as_slice()),
        ("image_ref", descriptor.image_ref.as_bytes()),
        ("image_digest", descriptor.image_digest.as_bytes()),
        ("signer_identity", sub.signer_hash.as_slice()),
        ("oci_runtime_spec", sub.oci_hash.as_slice()),
        ("sidecars", sub.sidecar_hash.as_slice()),
        (
            "api_signing_pubkey",
            descriptor.api_signing_pubkey.as_bytes(),
        ),
        (
            "expected_firmware_measurement",
            descriptor.expected_firmware_measurement.as_slice(),
        ),
        (
            "expected_runtime_class",
            descriptor.expected_runtime_class.as_bytes(),
        ),
        ("kbs_resource_path", descriptor.kbs_resource_path.as_bytes()),
        ("unlock_mode", descriptor.unlock_mode.as_bytes()),
        (
            "policy_template_id",
            descriptor.policy_template_id.as_bytes(),
        ),
        (
            "policy_template_sha256",
            descriptor.policy_template_sha256.as_slice(),
        ),
        (
            "platform_release_version",
            descriptor.platform_release_version.as_bytes(),
        ),
    ];
    if include_chain_anchors {
        records.push((
            "expected_agent_policy_hash",
            descriptor.expected_agent_policy_hash.as_slice(),
        ));
        records.push((
            "expected_cc_init_data_hash",
            descriptor.expected_cc_init_data_hash.as_slice(),
        ));
        records.push((
            "expected_kbs_policy_hash",
            descriptor.expected_kbs_policy_hash.as_slice(),
        ));
    }
    records
}

struct DescriptorSubHashes {
    created_at: String,
    custom_domains_hash: [u8; 32],
    signer_hash: [u8; 32],
    oci_hash: [u8; 32],
    sidecar_hash: [u8; 32],
}

impl DescriptorSubHashes {
    fn new(descriptor: &DeploymentDescriptor) -> Self {
        Self {
            created_at: descriptor.created_at.to_rfc3339(),
            custom_domains_hash: canonical_string_list_bytes(&descriptor.custom_domains),
            signer_hash: canonical_signer_bytes(&descriptor.signer_identity),
            oci_hash: canonical_oci_spec_bytes(&descriptor.oci_runtime_spec),
            sidecar_hash: canonical_sidecar_map_bytes(&descriptor.sidecars),
        }
    }
}

pub(crate) mod hex_bytes32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        use serde::de::Error;
        let value = String::deserialize(d)?;
        let bytes = hex::decode(&value).map_err(D::Error::custom)?;
        bytes.try_into().map_err(|_| D::Error::custom("len != 32"))
    }
}

pub(crate) mod hex_pubkey {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(key: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(key.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
        use serde::de::Error;
        let value = String::deserialize(d)?;
        let bytes = hex::decode(&value).map_err(D::Error::custom)?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("len != 32"))?;
        VerifyingKey::from_bytes(&arr).map_err(D::Error::custom)
    }
}

pub(crate) mod hex_signature {
    use ed25519_dalek::Signature;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(sig: &Signature, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(sig.to_bytes()))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Signature, D::Error> {
        use serde::de::Error;
        let value = String::deserialize(d)?;
        let bytes = hex::decode(&value).map_err(D::Error::custom)?;
        let arr: [u8; 64] = bytes
            .try_into()
            .map_err(|_| D::Error::custom("len != 64"))?;
        Ok(Signature::from_bytes(&arr))
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use chrono::TimeZone;

    pub fn fixed_descriptor() -> DeploymentDescriptor {
        DeploymentDescriptor {
            schema_version: "v1".to_string(),
            org_id: Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap(),
            org_slug: "abcd1234".to_string(),
            app_id: Uuid::parse_str("22222222-2222-2222-2222-222222222222").unwrap(),
            app_name: "demo".to_string(),
            deploy_id: Uuid::parse_str("33333333-3333-3333-3333-333333333333").unwrap(),
            created_at: Utc.with_ymd_and_hms(2026, 4, 1, 12, 0, 0).unwrap(),
            nonce: [7; 32],
            app_domain: "demo.abcd1234.enclava.dev".to_string(),
            tee_domain: "demo.abcd1234.tee.enclava.dev".to_string(),
            custom_domains: vec!["app.example.com".to_string()],
            namespace: "cap-abcd1234-demo".to_string(),
            service_account: "cap-demo-sa".to_string(),
            identity_hash: [9; 32],
            image_ref: "ghcr.io/enclava-labs/demo@sha256:aaaa".to_string(),
            image_digest: "sha256:aaaa".to_string(),
            signer_identity: SignerIdentity {
                subject: "https://github.com/x/y/.github/workflows/build.yml".to_string(),
                issuer: "https://token.actions.githubusercontent.com".to_string(),
            },
            oci_runtime_spec: OciRuntimeSpec {
                command: vec!["/app".to_string()],
                args: vec!["--serve".to_string()],
                env: vec![
                    EnvVar {
                        name: "A".to_string(),
                        value: "1".to_string(),
                    },
                    EnvVar {
                        name: "B".to_string(),
                        value: "2".to_string(),
                    },
                ],
                ports: vec![Port {
                    container_port: 3000,
                    protocol: "TCP".to_string(),
                }],
                mounts: vec![],
                capabilities: Capabilities::default(),
                security_context: SecurityContext::default(),
                resources: Resources::default(),
            },
            sidecars: Sidecars {
                attestation_proxy_digest: "sha256:1111".to_string(),
                caddy_digest: "sha256:2222".to_string(),
            },
            api_signing_pubkey: "test-api-signing-pubkey".to_string(),
            expected_firmware_measurement: [3; 32],
            expected_runtime_class: "kata-qemu-snp".to_string(),
            kbs_resource_path: "default/cap-abcd1234-demo-tls-owner".to_string(),
            unlock_mode: "password".to_string(),
            policy_template_id: "kbs-release-policy-v3".to_string(),
            policy_template_sha256: [4; 32],
            platform_release_version: "platform-2026.04".to_string(),
            expected_agent_policy_hash: [7; 32],
            expected_cc_init_data_hash: [5; 32],
            expected_kbs_policy_hash: [6; 32],
        }
    }

    #[test]
    fn descriptor_core_hash_matches_cap_vector() {
        assert_eq!(
            hex::encode(descriptor_core_hash(&fixed_descriptor())),
            "1e1758ef9f3235eba697bb71672e69ca27f353ebffa94e7d186f33ebd39932de"
        );
    }

    #[test]
    fn descriptor_json_carries_image_ref_and_digest() {
        let json = serde_json::to_string(&fixed_descriptor()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();
        let object = value.as_object().unwrap();
        let image_ref_position = json.find("\"image_ref\"").unwrap();
        let image_digest_position = json.find("\"image_digest\"").unwrap();

        assert_eq!(object["image_ref"], "ghcr.io/enclava-labs/demo@sha256:aaaa");
        assert_eq!(object["image_digest"], "sha256:aaaa");
        assert!(
            image_ref_position < image_digest_position,
            "image_ref must serialize before image_digest"
        );
    }

    #[test]
    fn canonical_descriptor_includes_image_ref() {
        let mut a = fixed_descriptor();
        let mut b = a.clone();
        b.image_ref = "registry.example.com/other/demo@sha256:aaaa".to_string();

        assert_ne!(
            descriptor_canonical_bytes(&a),
            descriptor_canonical_bytes(&b)
        );
        assert_ne!(descriptor_core_hash(&a), descriptor_core_hash(&b));

        a.image_ref = b.image_ref.clone();
        assert_eq!(
            descriptor_canonical_bytes(&a),
            descriptor_canonical_bytes(&b)
        );
        assert_eq!(descriptor_core_hash(&a), descriptor_core_hash(&b));
    }

    #[test]
    fn descriptor_core_excludes_forward_chain_hashes() {
        let mut descriptor = fixed_descriptor();
        let before = descriptor_core_hash(&descriptor);
        descriptor.expected_agent_policy_hash = [0xdd; 32];
        descriptor.expected_cc_init_data_hash = [0xff; 32];
        descriptor.expected_kbs_policy_hash = [0xee; 32];
        assert_eq!(before, descriptor_core_hash(&descriptor));
    }

    #[test]
    fn full_descriptor_includes_forward_chain_hashes() {
        let mut a = fixed_descriptor();
        let mut b = a.clone();
        b.expected_agent_policy_hash = [0xdd; 32];
        assert_ne!(
            descriptor_canonical_bytes(&a),
            descriptor_canonical_bytes(&b)
        );
        a.expected_agent_policy_hash = [0xdd; 32];
        assert_eq!(
            descriptor_canonical_bytes(&a),
            descriptor_canonical_bytes(&b)
        );
        b.expected_kbs_policy_hash = [0xee; 32];
        assert_ne!(
            descriptor_canonical_bytes(&a),
            descriptor_canonical_bytes(&b)
        );
        a.expected_kbs_policy_hash = [0xee; 32];
        assert_eq!(
            descriptor_canonical_bytes(&a),
            descriptor_canonical_bytes(&b)
        );
    }

    #[test]
    fn env_order_is_canonicalized() {
        let mut a = fixed_descriptor();
        let mut b = a.clone();
        b.oci_runtime_spec.env.reverse();
        assert_eq!(
            canonical_oci_spec_bytes(&a.oci_runtime_spec),
            canonical_oci_spec_bytes(&b.oci_runtime_spec)
        );
        a.oci_runtime_spec.args.push("--other".to_string());
        assert_ne!(
            canonical_oci_spec_bytes(&a.oci_runtime_spec),
            canonical_oci_spec_bytes(&b.oci_runtime_spec)
        );
    }
}
