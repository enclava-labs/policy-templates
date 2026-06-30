use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand_core::OsRng;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    canonical::{ce_v1_bytes, ce_v1_hash},
    descriptor::{
        descriptor_core_hash, verify_descriptor, Capabilities, DeploymentDescriptor,
        DeploymentDescriptorEnvelope, OciRuntimeSpec,
    },
    genpolicy::GeneratedAgentPolicy,
    keyring::{find_deployer_pubkey, keyring_fingerprint, verify_keyring, OrgKeyringEnvelope},
    TEMPLATE_ID, TEMPLATE_TEXT,
};

const ROOTFUL_SUDO_CAPS: &[&str] = &["CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"];

#[derive(Debug, Clone)]
pub struct SigningKeyMaterial {
    pub key_id: String,
    pub signing_key: SigningKey,
}

#[derive(Debug, Deserialize)]
pub struct SignRequest {
    pub app_id: Uuid,
    pub deploy_id: Uuid,
    pub platform_release_version: String,
    pub customer_descriptor_blob: String,
    pub org_keyring_blob: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedPolicyArtifact {
    pub metadata: PolicyMetadata,
    pub rego_text: String,
    pub rego_sha256: String,
    pub agent_policy_text: String,
    pub agent_policy_sha256: String,
    pub signature: String,
    pub verify_pubkey_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_keyring: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PolicyMetadata {
    pub app_id: String,
    pub deploy_id: String,
    pub descriptor_core_hash: String,
    pub descriptor_signing_pubkey: String,
    pub platform_release_version: String,
    pub policy_template_id: String,
    pub policy_template_sha256: String,
    pub agent_policy_sha256: String,
    pub genpolicy_version_pin: String,
    pub signed_at: String,
    pub key_id: String,
}

#[derive(Debug, Clone)]
pub struct DecodedSigningBlobs {
    pub descriptor_envelope: DeploymentDescriptorEnvelope,
    pub keyring_envelope: OrgKeyringEnvelope,
    pub keyring_envelope_value: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct VerifiedSigningInputs {
    pub descriptor: DeploymentDescriptor,
    pub descriptor_signing_pubkey: VerifyingKey,
    pub descriptor_core_hash: [u8; 32],
    pub org_keyring_fingerprint: [u8; 32],
    pub org_keyring: serde_json::Value,
}

pub fn load_signing_key_material() -> Result<SigningKeyMaterial> {
    match std::env::var("POLICY_SIGNING_KEY_B64") {
        Ok(raw) => {
            if std::env::var("ALLOW_RAW_POLICY_SIGNING_KEY_B64").as_deref() != Ok("1") {
                bail!(
                    "POLICY_SIGNING_KEY_B64 raw-env loading is disabled; use customer-signed artifacts or an external signer, or set ALLOW_RAW_POLICY_SIGNING_KEY_B64=1 only for non-production compatibility"
                );
            }
            let key_id = std::env::var("POLICY_SIGNING_KEY_ID")
                .context("POLICY_SIGNING_KEY_ID is required when POLICY_SIGNING_KEY_B64 is set")?;
            let bytes = B64
                .decode(raw.as_bytes())
                .context("decoding POLICY_SIGNING_KEY_B64")?;
            let seed: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow!("POLICY_SIGNING_KEY_B64 must decode to 32 bytes"))?;
            Ok(SigningKeyMaterial {
                key_id,
                signing_key: SigningKey::from_bytes(&seed),
            })
        }
        Err(_) if std::env::var("ALLOW_EPHEMERAL_SIGNING_KEY").as_deref() == Ok("1") => {
            Ok(SigningKeyMaterial {
                key_id: std::env::var("POLICY_SIGNING_KEY_ID")
                    .unwrap_or_else(|_| "ephemeral-dev".to_string()),
                signing_key: SigningKey::generate(&mut OsRng),
            })
        }
        Err(_) => bail!("POLICY_SIGNING_KEY_B64 is required"),
    }
}

pub fn decode_signing_blobs(req: &SignRequest) -> Result<DecodedSigningBlobs> {
    Ok(DecodedSigningBlobs {
        descriptor_envelope: decode_json_blob(
            "customer_descriptor_blob",
            &req.customer_descriptor_blob,
        )?,
        keyring_envelope: decode_json_blob("org_keyring_blob", &req.org_keyring_blob)?,
        keyring_envelope_value: decode_json_blob("org_keyring_blob", &req.org_keyring_blob)?,
    })
}

pub fn verify_signing_inputs(
    blobs: DecodedSigningBlobs,
    trusted_owner: &VerifyingKey,
) -> Result<VerifiedSigningInputs> {
    if blobs.descriptor_envelope.descriptor.org_id != blobs.keyring_envelope.keyring.org_id {
        bail!("descriptor org_id does not match org keyring org_id");
    }

    let keyring = verify_keyring(&blobs.keyring_envelope, trusted_owner)?;
    let deployer = find_deployer_pubkey(keyring, &blobs.descriptor_envelope.signing_pubkey)?;
    let descriptor = verify_descriptor(&blobs.descriptor_envelope, &deployer)?;
    let descriptor_core_hash = descriptor_core_hash(descriptor);
    Ok(VerifiedSigningInputs {
        descriptor: descriptor.clone(),
        descriptor_signing_pubkey: deployer,
        descriptor_core_hash,
        org_keyring_fingerprint: keyring_fingerprint(keyring),
        org_keyring: blobs.keyring_envelope_value,
    })
}

pub fn sign_verified_policy(
    req: &SignRequest,
    inputs: VerifiedSigningInputs,
    generated_agent_policy: GeneratedAgentPolicy,
    key_material: &SigningKeyMaterial,
    signed_at: DateTime<Utc>,
) -> Result<SignedPolicyArtifact> {
    if req.app_id != inputs.descriptor.app_id {
        bail!("request app_id does not match signed descriptor app_id");
    }
    if req.deploy_id != inputs.descriptor.deploy_id {
        bail!("request deploy_id does not match signed descriptor deploy_id");
    }
    if req.platform_release_version != inputs.descriptor.platform_release_version {
        bail!("request platform_release_version does not match signed descriptor");
    }
    if inputs.descriptor.schema_version != "v1" {
        bail!("unsupported descriptor schema_version");
    }
    if inputs.descriptor.policy_template_id != TEMPLATE_ID {
        bail!("descriptor policy_template_id does not match service template");
    }

    let template_sha256 = template_sha256();
    if inputs.descriptor.policy_template_sha256 != template_sha256 {
        bail!("descriptor policy_template_sha256 does not match service template bytes");
    }

    validate_oci_security_floor(&inputs.descriptor)?;
    let rego_text = render_template(&inputs.descriptor)?;
    let rego_hash: [u8; 32] = Sha256::digest(rego_text.as_bytes()).into();
    if inputs.descriptor.expected_kbs_policy_hash != rego_hash {
        bail!("descriptor expected_kbs_policy_hash does not match rendered policy");
    }
    let agent_policy_hash: [u8; 32] =
        Sha256::digest(generated_agent_policy.policy_text.as_bytes()).into();
    if inputs.descriptor.expected_agent_policy_hash != agent_policy_hash {
        bail!("descriptor expected_agent_policy_hash does not match generated agent policy");
    }

    let metadata = PolicyMetadata {
        app_id: inputs.descriptor.app_id.to_string(),
        deploy_id: inputs.descriptor.deploy_id.to_string(),
        descriptor_core_hash: hex::encode(inputs.descriptor_core_hash),
        descriptor_signing_pubkey: hex::encode(inputs.descriptor_signing_pubkey.to_bytes()),
        platform_release_version: inputs.descriptor.platform_release_version.clone(),
        policy_template_id: TEMPLATE_ID.to_string(),
        policy_template_sha256: hex::encode(template_sha256),
        agent_policy_sha256: hex::encode(agent_policy_hash),
        genpolicy_version_pin: generated_agent_policy.invocation.version_pin.clone(),
        signed_at: signed_at.to_rfc3339(),
        key_id: key_material.key_id.clone(),
    };
    let signing_input = policy_artifact_signing_input(&metadata, &rego_hash)?;
    let signature = key_material.signing_key.sign(&signing_input);

    Ok(SignedPolicyArtifact {
        metadata,
        rego_text,
        rego_sha256: hex::encode(rego_hash),
        agent_policy_text: generated_agent_policy.policy_text,
        agent_policy_sha256: hex::encode(agent_policy_hash),
        signature: hex::encode(signature.to_bytes()),
        verify_pubkey_b64: B64.encode(key_material.signing_key.verifying_key().to_bytes()),
        org_keyring: Some(inputs.org_keyring),
    })
}

pub fn verify_signed_artifact(
    artifact: &SignedPolicyArtifact,
    verify_key: &VerifyingKey,
) -> Result<()> {
    let rego_hash: [u8; 32] = hex::decode(&artifact.rego_sha256)
        .context("decoding rego_sha256")?
        .try_into()
        .map_err(|_| anyhow!("rego_sha256 must be 32 bytes"))?;
    let actual_rego_hash: [u8; 32] = Sha256::digest(artifact.rego_text.as_bytes()).into();
    if rego_hash != actual_rego_hash {
        bail!("rego_sha256 does not match rego_text");
    }
    let agent_policy_hash: [u8; 32] = hex::decode(&artifact.agent_policy_sha256)
        .context("decoding agent_policy_sha256")?
        .try_into()
        .map_err(|_| anyhow!("agent_policy_sha256 must be 32 bytes"))?;
    let actual_agent_policy_hash: [u8; 32] =
        Sha256::digest(artifact.agent_policy_text.as_bytes()).into();
    if agent_policy_hash != actual_agent_policy_hash {
        bail!("agent_policy_sha256 does not match agent_policy_text");
    }
    if artifact.metadata.agent_policy_sha256 != artifact.agent_policy_sha256 {
        bail!("metadata.agent_policy_sha256 does not match artifact");
    }
    let signature_bytes: [u8; 64] = decode_signature(&artifact.signature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    let signing_input = policy_artifact_signing_input(&artifact.metadata, &rego_hash)?;
    verify_key
        .verify(&signing_input, &signature)
        .map_err(|err| anyhow!("policy artifact signature verification failed: {err}"))
}

fn decode_signature(value: &str) -> Result<[u8; 64]> {
    if let Ok(bytes) = hex::decode(value) {
        return bytes
            .try_into()
            .map_err(|bytes: Vec<u8>| anyhow!("signature must be 64 bytes, got {}", bytes.len()));
    }
    B64.decode(value.as_bytes())
        .context("decoding signature as hex or base64")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("signature must be 64 bytes, got {}", bytes.len()))
}

pub fn render_template(descriptor: &DeploymentDescriptor) -> Result<String> {
    let replacements = [
        (
            "{{init_data_hash}}",
            hex::encode(descriptor.expected_cc_init_data_hash),
        ),
        ("{{image_digest}}", descriptor.image_digest.clone()),
        (
            "{{signer_subject}}",
            descriptor.signer_identity.subject.clone(),
        ),
        (
            "{{signer_issuer}}",
            descriptor.signer_identity.issuer.clone(),
        ),
        ("{{namespace}}", descriptor.namespace.clone()),
        ("{{service_account}}", descriptor.service_account.clone()),
        ("{{identity_hash}}", hex::encode(descriptor.identity_hash)),
        (
            "{{kbs_resource_path}}",
            descriptor.kbs_resource_path.clone(),
        ),
    ];

    let mut rendered = TEMPLATE_TEXT.to_string();
    for (needle, value) in replacements {
        validate_rego_string_slot(needle, &value)?;
        rendered = rendered.replace(needle, &value);
    }
    if rendered.contains("{{") {
        bail!("unrendered template slot remains");
    }
    Ok(rendered)
}

pub fn template_sha256() -> [u8; 32] {
    Sha256::digest(TEMPLATE_TEXT.as_bytes()).into()
}

pub fn canonical_policy_metadata_hash(metadata: &PolicyMetadata) -> Result<[u8; 32]> {
    let app_id = Uuid::parse_str(&metadata.app_id)?.into_bytes();
    let deploy_id = Uuid::parse_str(&metadata.deploy_id)?.into_bytes();
    let descriptor_core_hash =
        decode_hex32("descriptor_core_hash", &metadata.descriptor_core_hash)?;
    let descriptor_signing_pubkey = decode_hex32(
        "descriptor_signing_pubkey",
        &metadata.descriptor_signing_pubkey,
    )?;
    let policy_template_sha256 =
        decode_hex32("policy_template_sha256", &metadata.policy_template_sha256)?;
    let agent_policy_sha256 = decode_hex32("agent_policy_sha256", &metadata.agent_policy_sha256)?;

    Ok(ce_v1_hash(&[
        ("app_id", &app_id),
        ("deploy_id", &deploy_id),
        ("descriptor_core_hash", &descriptor_core_hash),
        ("descriptor_signing_pubkey", &descriptor_signing_pubkey),
        (
            "platform_release_version",
            metadata.platform_release_version.as_bytes(),
        ),
        ("policy_template_id", metadata.policy_template_id.as_bytes()),
        ("policy_template_sha256", &policy_template_sha256),
        ("agent_policy_sha256", &agent_policy_sha256),
        (
            "genpolicy_version_pin",
            metadata.genpolicy_version_pin.as_bytes(),
        ),
        ("signed_at", metadata.signed_at.as_bytes()),
        ("key_id", metadata.key_id.as_bytes()),
    ]))
}

pub fn policy_artifact_signing_input(
    metadata: &PolicyMetadata,
    rego_hash: &[u8; 32],
) -> Result<Vec<u8>> {
    let metadata_hash = canonical_policy_metadata_hash(metadata)?;
    Ok(ce_v1_bytes(&[
        ("purpose", b"enclava-policy-artifact-v1"),
        ("metadata", &metadata_hash),
        ("rego_sha256", rego_hash),
    ]))
}

pub fn decode_json_blob<T: DeserializeOwned>(name: &str, blob: &str) -> Result<T> {
    let trimmed = blob.trim();
    if trimmed.is_empty() {
        bail!("{name} is required");
    }
    if let Ok(decoded) = B64.decode(trimmed.as_bytes()) {
        if let Ok(parsed) = serde_json::from_slice(&decoded) {
            return Ok(parsed);
        }
    }
    serde_json::from_str(trimmed).with_context(|| format!("parsing {name} as JSON or base64 JSON"))
}

fn decode_hex32(name: &str, value: &str) -> Result<[u8; 32]> {
    hex::decode(value)
        .with_context(|| format!("decoding {name}"))?
        .try_into()
        .map_err(|_| anyhow!("{name} must be 32 bytes"))
}

fn validate_rego_string_slot(name: &str, value: &str) -> Result<()> {
    if value.is_empty() {
        bail!("template slot is empty: {name}");
    }
    if value
        .bytes()
        .any(|byte| matches!(byte, b'"' | b'\n' | b'\r' | 0))
    {
        bail!("template slot contains invalid Rego string characters: {name}");
    }
    Ok(())
}

fn validate_oci_security_floor(descriptor: &DeploymentDescriptor) -> Result<()> {
    if descriptor.oci_runtime_spec.security_context.privileged {
        bail!("descriptor security_context.privileged must be false");
    }
    if descriptor
        .oci_runtime_spec
        .security_context
        .allow_privilege_escalation
        && !descriptor_uses_rootful_sudo(&descriptor.oci_runtime_spec)
    {
        bail!(
            "descriptor security_context.allow_privilege_escalation requires rootful-sudo profile"
        );
    }
    Ok(())
}

fn descriptor_uses_rootful_sudo(oci: &OciRuntimeSpec) -> bool {
    let sec = &oci.security_context;
    sec.run_as_user == 0
        && sec.run_as_group == 0
        && !sec.read_only_root_fs
        && sec.allow_privilege_escalation
        && !sec.privileged
        && capabilities_match_rootful_sudo(&oci.capabilities)
}

fn capabilities_match_rootful_sudo(caps: &Capabilities) -> bool {
    caps.drop.iter().any(|cap| cap.eq_ignore_ascii_case("ALL"))
        && caps.add.len() == ROOTFUL_SUDO_CAPS.len()
        && ROOTFUL_SUDO_CAPS.iter().all(|required| {
            caps.add
                .iter()
                .any(|cap| cap.eq_ignore_ascii_case(required))
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ed25519_dalek::Signer;
    use std::path::PathBuf;

    use crate::{
        descriptor::{tests::fixed_descriptor, DeploymentDescriptorEnvelope},
        genpolicy::{GeneratedAgentPolicy, GenpolicyInvocation},
        keyring::tests::{fixed_deployer_key, fixed_keyring, fixed_owner_key, sign_keyring},
    };

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 1, 12, 30, 0).unwrap()
    }

    fn fixed_service_key() -> SigningKey {
        SigningKey::from_bytes(&[0x33; 32])
    }

    fn generated_agent_policy() -> GeneratedAgentPolicy {
        GeneratedAgentPolicy {
            policy_text: "package agent_policy\n\ndefault CreateContainerRequest := true\n"
                .to_string(),
            invocation: GenpolicyInvocation {
                binary: PathBuf::from("genpolicy"),
                args: vec!["-y".to_string(), "pod.yaml".to_string()],
                manifest_yaml: "apiVersion: v1\nkind: Pod\n".to_string(),
                version_pin: "kata-containers/genpolicy@3.28.0+test".to_string(),
            },
        }
    }

    fn descriptor_for_service() -> DeploymentDescriptor {
        let mut descriptor = fixed_descriptor();
        descriptor.policy_template_id = TEMPLATE_ID.to_string();
        descriptor.policy_template_sha256 = template_sha256();
        descriptor.expected_agent_policy_hash =
            Sha256::digest(generated_agent_policy().policy_text.as_bytes()).into();
        descriptor.expected_cc_init_data_hash = [0x55; 32];
        descriptor.expected_kbs_policy_hash = Sha256::digest(
            render_template(&descriptor)
                .expect("template renders")
                .as_bytes(),
        )
        .into();
        descriptor
    }

    fn signed_descriptor_envelope(
        descriptor: DeploymentDescriptor,
    ) -> DeploymentDescriptorEnvelope {
        let deployer = fixed_deployer_key();
        let bytes = crate::descriptor::descriptor_canonical_bytes(&descriptor);
        DeploymentDescriptorEnvelope {
            descriptor,
            signature: deployer.sign(&bytes),
            signing_key_id: "deployer-key-1".to_string(),
            signing_pubkey: deployer.verifying_key(),
        }
    }

    fn verified_inputs() -> VerifiedSigningInputs {
        let owner = fixed_owner_key();
        let deployer = fixed_deployer_key();
        let keyring = sign_keyring(&owner, fixed_keyring(&owner, &deployer));
        let keyring_envelope_value = serde_json::to_value(&keyring).unwrap();
        verify_signing_inputs(
            DecodedSigningBlobs {
                descriptor_envelope: signed_descriptor_envelope(descriptor_for_service()),
                keyring_envelope: keyring,
                keyring_envelope_value,
            },
            &owner.verifying_key(),
        )
        .unwrap()
    }

    fn sign_request_for(descriptor: &DeploymentDescriptor) -> SignRequest {
        SignRequest {
            app_id: descriptor.app_id,
            deploy_id: descriptor.deploy_id,
            platform_release_version: descriptor.platform_release_version.clone(),
            customer_descriptor_blob: String::new(),
            org_keyring_blob: String::new(),
        }
    }

    #[test]
    fn request_blobs_decode_from_base64_json_and_verify() {
        let owner = fixed_owner_key();
        let deployer = fixed_deployer_key();
        let descriptor_envelope = signed_descriptor_envelope(descriptor_for_service());
        let keyring_envelope = sign_keyring(&owner, fixed_keyring(&owner, &deployer));
        let req = SignRequest {
            app_id: descriptor_envelope.descriptor.app_id,
            deploy_id: descriptor_envelope.descriptor.deploy_id,
            platform_release_version: descriptor_envelope
                .descriptor
                .platform_release_version
                .clone(),
            customer_descriptor_blob: B64.encode(serde_json::to_vec(&descriptor_envelope).unwrap()),
            org_keyring_blob: B64.encode(serde_json::to_vec(&keyring_envelope).unwrap()),
        };

        let decoded = decode_signing_blobs(&req).unwrap();
        let verified = verify_signing_inputs(decoded, &owner.verifying_key()).unwrap();
        assert_eq!(verified.descriptor.app_id, req.app_id);
        assert_eq!(
            verified.descriptor_signing_pubkey.to_bytes(),
            deployer.verifying_key().to_bytes()
        );
    }

    #[test]
    fn signed_artifact_verifies() {
        let inputs = verified_inputs();
        let req = sign_request_for(&inputs.descriptor);
        let key_material = SigningKeyMaterial {
            key_id: "policy-test-key-v1".to_string(),
            signing_key: fixed_service_key(),
        };
        let artifact = sign_verified_policy(
            &req,
            inputs,
            generated_agent_policy(),
            &key_material,
            fixed_time(),
        )
        .unwrap();
        verify_signed_artifact(&artifact, &key_material.signing_key.verifying_key()).unwrap();
        assert_eq!(artifact.metadata.key_id, "policy-test-key-v1");
        assert_eq!(artifact.metadata.policy_template_id, TEMPLATE_ID);
        assert_eq!(
            artifact.agent_policy_sha256,
            artifact.metadata.agent_policy_sha256
        );
        assert_eq!(
            artifact.metadata.genpolicy_version_pin,
            "kata-containers/genpolicy@3.28.0+test"
        );
    }

    #[test]
    fn request_app_id_must_match_descriptor() {
        let inputs = verified_inputs();
        let mut req = sign_request_for(&inputs.descriptor);
        req.app_id = Uuid::parse_str("99999999-9999-9999-9999-999999999999").unwrap();
        let key_material = SigningKeyMaterial {
            key_id: "policy-test-key-v1".to_string(),
            signing_key: fixed_service_key(),
        };
        let err = sign_verified_policy(
            &req,
            inputs,
            generated_agent_policy(),
            &key_material,
            fixed_time(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("request app_id"));
    }

    #[test]
    fn descriptor_signature_tampering_rejects() {
        let owner = fixed_owner_key();
        let deployer = fixed_deployer_key();
        let mut descriptor_envelope = signed_descriptor_envelope(descriptor_for_service());
        descriptor_envelope.descriptor.namespace = "cap-mutated".to_string();
        let keyring = sign_keyring(&owner, fixed_keyring(&owner, &deployer));
        let keyring_envelope_value = serde_json::to_value(&keyring).unwrap();
        let err = verify_signing_inputs(
            DecodedSigningBlobs {
                descriptor_envelope,
                keyring_envelope: keyring,
                keyring_envelope_value,
            },
            &owner.verifying_key(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("descriptor signature"));
    }

    #[test]
    fn expected_kbs_policy_hash_must_match_rendered_rego() {
        let mut inputs = verified_inputs();
        inputs.descriptor.expected_kbs_policy_hash = [0xaa; 32];
        let req = sign_request_for(&inputs.descriptor);
        let key_material = SigningKeyMaterial {
            key_id: "policy-test-key-v1".to_string(),
            signing_key: fixed_service_key(),
        };
        let err = sign_verified_policy(
            &req,
            inputs,
            generated_agent_policy(),
            &key_material,
            fixed_time(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("expected_kbs_policy_hash"));
    }

    #[test]
    fn expected_agent_policy_hash_must_match_genpolicy_output() {
        let mut inputs = verified_inputs();
        inputs.descriptor.expected_agent_policy_hash = [0xaa; 32];
        let req = sign_request_for(&inputs.descriptor);
        let key_material = SigningKeyMaterial {
            key_id: "policy-test-key-v1".to_string(),
            signing_key: fixed_service_key(),
        };
        let err = sign_verified_policy(
            &req,
            inputs,
            generated_agent_policy(),
            &key_material,
            fixed_time(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("expected_agent_policy_hash"));
    }

    #[test]
    fn rootful_sudo_security_profile_passes_floor() {
        let mut descriptor = descriptor_for_service();
        descriptor.oci_runtime_spec.security_context.run_as_user = 0;
        descriptor.oci_runtime_spec.security_context.run_as_group = 0;
        descriptor
            .oci_runtime_spec
            .security_context
            .read_only_root_fs = false;
        descriptor
            .oci_runtime_spec
            .security_context
            .allow_privilege_escalation = true;
        descriptor.oci_runtime_spec.security_context.privileged = false;
        descriptor.oci_runtime_spec.capabilities = Capabilities {
            add: ROOTFUL_SUDO_CAPS
                .iter()
                .map(|cap| (*cap).to_string())
                .collect(),
            drop: vec!["ALL".to_string()],
        };

        validate_oci_security_floor(&descriptor).unwrap();
    }

    #[test]
    fn privilege_escalation_requires_rootful_sudo_profile() {
        let mut descriptor = descriptor_for_service();
        descriptor
            .oci_runtime_spec
            .security_context
            .allow_privilege_escalation = true;

        let err = validate_oci_security_floor(&descriptor).unwrap_err();
        assert!(err.to_string().contains("rootful-sudo profile"));
    }

    #[test]
    fn privileged_descriptor_is_rejected() {
        let mut descriptor = descriptor_for_service();
        descriptor.oci_runtime_spec.security_context.privileged = true;

        let err = validate_oci_security_floor(&descriptor).unwrap_err();
        assert!(err.to_string().contains("privileged must be false"));
    }

    #[test]
    fn rego_slots_reject_quotes_and_newlines() {
        let mut descriptor = descriptor_for_service();
        descriptor.namespace = "bad\"namespace".to_string();
        assert!(render_template(&descriptor).is_err());

        descriptor.namespace = "bad\nnamespace".to_string();
        assert!(render_template(&descriptor).is_err());
    }

    #[test]
    fn rendered_policy_keeps_get_attestation_read_path() {
        let descriptor = descriptor_for_service();
        let rendered = render_template(&descriptor).unwrap();

        assert!(rendered.contains("data.plugin == \"resource\""));
        assert!(rendered.contains("data.method == \"GET\""));
        assert!(rendered.contains("attested_workload"));
        assert!(rendered.contains("requested_resource_path_allowed"));
        assert!(
            rendered.contains("expected_resource_path := \"default/cap-abcd1234-demo-tls-owner\"")
        );
        assert!(rendered.contains("rp := data[\"resource-path\"]"));
        assert!(rendered.contains("allowed_resource_paths contains expected_resource_path"));
        assert!(rendered
            .contains("path := owner_seed_sibling_path(\"seed-encrypted\", \"seed-sealed\")"));
        assert!(rendered.contains("endswith(parts[1], \"-owner\")"));
        assert!(rendered.contains("object.get(ev, \"init_data_claims\", {})"));
        assert!(rendered.contains("object.get(idc, \"signer_identity_subject\", \"\")"));
        assert!(rendered.contains("parts := split(value, \"@\")"));
        assert!(!rendered.contains("{{"));
    }

    #[test]
    fn rendered_policy_requires_receipts_for_rekey_and_teardown() {
        let rendered = render_template(&descriptor_for_service()).unwrap();
        let required_clauses = [
            "data.plugin == \"workload-resource\"",
            "data.method == \"PUT\"",
            "data.request.body.operation == \"rekey\"",
            "data.request.body.receipt.signature_valid",
            "data.request.body.receipt.pubkey_hash_matches",
            "data.request.body.receipt.payload.purpose == \"enclava-rekey-v1\"",
            "data.request.body.receipt.payload.resource_path == requested_resource_path",
            "data.request.body.value_hash_matches",
            "data.method == \"DELETE\"",
            "data.request.body.operation == \"teardown\"",
            "data.request.body.receipt.payload.purpose == \"enclava-teardown-v1\"",
        ];

        for clause in required_clauses {
            assert!(
                rendered.contains(clause),
                "missing rendered clause: {clause}"
            );
        }
        assert!(!rendered.contains("{{"));
    }

    #[test]
    fn policy_artifact_vector_matches_fixture() {
        let inputs = verified_inputs();
        let req = sign_request_for(&inputs.descriptor);
        let key_material = SigningKeyMaterial {
            key_id: "policy-test-key-v1".to_string(),
            signing_key: fixed_service_key(),
        };
        let artifact = sign_verified_policy(
            &req,
            inputs,
            generated_agent_policy(),
            &key_material,
            fixed_time(),
        )
        .unwrap();
        let rego_hash: [u8; 32] = hex::decode(&artifact.rego_sha256)
            .unwrap()
            .try_into()
            .unwrap();
        let signing_input = policy_artifact_signing_input(&artifact.metadata, &rego_hash).unwrap();
        let fixture = serde_json::json!({
            "purpose": "enclava-policy-artifact-v1",
            "encoding": "ce-v1-raw-tlv",
            "ed25519_signs": "ce_v1_bytes(records), not ce_v1_hash(records)",
            "service_signing_seed_b64": B64.encode([0x33; 32]),
            "verify_pubkey_b64": artifact.verify_pubkey_b64,
            "metadata": artifact.metadata,
            "rego_sha256": artifact.rego_sha256,
            "agent_policy_sha256": artifact.agent_policy_sha256,
            "canonical_policy_metadata_hash": hex::encode(canonical_policy_metadata_hash(&artifact.metadata).unwrap()),
            "signing_input_hex": hex::encode(signing_input),
            "signature": artifact.signature,
        });
        let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../fixtures/policy-artifact-vector-v1.json");
        if std::env::var("REGENERATE_FIXTURES").is_ok() {
            std::fs::write(
                &path,
                serde_json::to_string_pretty(&fixture).unwrap() + "\n",
            )
            .unwrap();
        }
        let expected: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        assert_eq!(fixture, expected);
    }
}
