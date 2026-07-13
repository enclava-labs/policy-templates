use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, SecondsFormat, Utc};
use ed25519_dalek::{Signer as _, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::{
    canonical::{ce_v1_bytes, ce_v1_hash},
    descriptor::{descriptor_canonical_bytes, DeploymentDescriptor, DeploymentDescriptorEnvelope},
    keyring::{canonical_keyring_bytes, OrgKeyringEnvelope},
    policy::{canonical_policy_metadata_hash, SignedPolicyArtifact, SigningKeyMaterial},
};

pub const AUTHORIZATION_SCHEMA_V1: &str = "enclava-kbs-deployment-authorization-v1";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeploymentAuthorizationV1 {
    pub schema_version: String,
    pub authorization_id: Uuid,
    pub org_id: Uuid,
    pub app_id: Uuid,
    pub descriptor_deploy_id: Uuid,
    pub descriptor_core_hash: String,
    pub expected_init_data_hash: String,
    pub namespace: String,
    pub service_account: String,
    pub tenant_instance_identity_hash: String,
    pub org_owner_version: u64,
    pub org_owner_pubkey_sha256: String,
    pub image_digest: String,
    pub signer_identity: crate::descriptor::SignerIdentity,
    pub receipt_resource_path: String,
    pub authorized_resource_paths: Vec<String>,
    pub rego_sha256: String,
    pub agent_policy_sha256: String,
    pub artifact_bundle_digest: String,
    pub issuer_key_id: String,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub signature_alg: String,
    pub signature: String,
}

pub struct AuthorizationInputs<'a> {
    pub descriptor_envelope: &'a DeploymentDescriptorEnvelope,
    pub keyring_envelope: &'a OrgKeyringEnvelope,
    pub owner_version: u64,
    pub owner_pubkey: &'a [u8; 32],
    pub artifact: &'a SignedPolicyArtifact,
}

pub fn issue_authorization(
    inputs: AuthorizationInputs<'_>,
    key_material: &SigningKeyMaterial,
    issued_at: DateTime<Utc>,
) -> Result<(DeploymentAuthorizationV1, Vec<u8>)> {
    let descriptor = &inputs.descriptor_envelope.descriptor;
    if inputs.keyring_envelope.keyring.version != inputs.owner_version {
        bail!("org keyring version does not match signing-service owner version");
    }
    if inputs.keyring_envelope.signing_pubkey.to_bytes() != *inputs.owner_pubkey {
        bail!("org keyring signer does not match signing-service owner key");
    }
    let descriptor_hash = crate::descriptor::descriptor_core_hash(descriptor);
    let receipt_path = format!("default/policy-receipts/{}", hex::encode(descriptor_hash));
    let mut authorized_paths = authorized_paths(descriptor, &receipt_path)?;
    authorized_paths.sort();
    authorized_paths.dedup();

    let bundle_digest = artifact_bundle_digest(&inputs)?;
    let owner_pubkey_sha256: [u8; 32] = Sha256::digest(inputs.owner_pubkey).into();
    let mut authorization = DeploymentAuthorizationV1 {
        schema_version: AUTHORIZATION_SCHEMA_V1.into(),
        authorization_id: Uuid::new_v4(),
        org_id: descriptor.org_id,
        app_id: descriptor.app_id,
        descriptor_deploy_id: descriptor.deploy_id,
        descriptor_core_hash: hex::encode(descriptor_hash),
        expected_init_data_hash: hex::encode(descriptor.expected_cc_init_data_hash),
        namespace: descriptor.namespace.clone(),
        service_account: descriptor.service_account.clone(),
        tenant_instance_identity_hash: hex::encode(descriptor.identity_hash),
        org_owner_version: inputs.owner_version,
        org_owner_pubkey_sha256: hex::encode(owner_pubkey_sha256),
        image_digest: descriptor.image_digest.clone(),
        signer_identity: descriptor.signer_identity.clone(),
        receipt_resource_path: receipt_path,
        authorized_resource_paths: authorized_paths,
        rego_sha256: inputs.artifact.rego_sha256.clone(),
        agent_policy_sha256: inputs.artifact.agent_policy_sha256.clone(),
        artifact_bundle_digest: hex::encode(bundle_digest),
        issuer_key_id: key_material.key_id.clone(),
        issued_at,
        expires_at: None,
        signature_alg: "ed25519".into(),
        signature: URL_SAFE_NO_PAD.encode([0u8; 64]),
    };
    let signature = key_material
        .signing_key
        .sign(&authorization_signing_bytes(&authorization)?);
    authorization.signature = URL_SAFE_NO_PAD.encode(signature.to_bytes());
    let exact_bytes = serde_json::to_vec(&authorization)?;
    if exact_bytes.len() > 16 * 1024 {
        bail!("deployment authorization exceeds 16 KiB");
    }
    Ok((authorization, exact_bytes))
}

pub fn authorization_signing_bytes(value: &DeploymentAuthorizationV1) -> Result<Vec<u8>> {
    let descriptor_core_hash = decode_hex32("descriptor_core_hash", &value.descriptor_core_hash)?;
    let expected_init_data_hash =
        decode_hex32("expected_init_data_hash", &value.expected_init_data_hash)?;
    let identity_hash = decode_hex32(
        "tenant_instance_identity_hash",
        &value.tenant_instance_identity_hash,
    )?;
    let owner_key_hash = decode_hex32("org_owner_pubkey_sha256", &value.org_owner_pubkey_sha256)?;
    let rego_hash = decode_hex32("rego_sha256", &value.rego_sha256)?;
    let agent_hash = decode_hex32("agent_policy_sha256", &value.agent_policy_sha256)?;
    let bundle_hash = decode_hex32("artifact_bundle_digest", &value.artifact_bundle_digest)?;
    let paths_hash = canonical_paths_hash(&value.authorized_resource_paths);
    let signer_hash = ce_v1_hash(&[
        ("subject", value.signer_identity.subject.as_bytes()),
        ("issuer", value.signer_identity.issuer.as_bytes()),
    ]);
    let owner_version = value.org_owner_version.to_be_bytes();
    let issued_at = timestamp(value.issued_at);
    let expires_at = value.expires_at.map(timestamp).unwrap_or_default();
    Ok(ce_v1_bytes(&[
        ("purpose", AUTHORIZATION_SCHEMA_V1.as_bytes()),
        ("schema_version", value.schema_version.as_bytes()),
        ("authorization_id", value.authorization_id.as_bytes()),
        ("org_id", value.org_id.as_bytes()),
        ("app_id", value.app_id.as_bytes()),
        (
            "descriptor_deploy_id",
            value.descriptor_deploy_id.as_bytes(),
        ),
        ("descriptor_core_hash", &descriptor_core_hash),
        ("expected_init_data_hash", &expected_init_data_hash),
        ("namespace", value.namespace.as_bytes()),
        ("service_account", value.service_account.as_bytes()),
        ("tenant_instance_identity_hash", &identity_hash),
        ("org_owner_version", &owner_version),
        ("org_owner_pubkey_sha256", &owner_key_hash),
        ("image_digest", value.image_digest.as_bytes()),
        ("signer_identity", &signer_hash),
        (
            "receipt_resource_path",
            value.receipt_resource_path.as_bytes(),
        ),
        ("authorized_resource_paths", &paths_hash),
        ("rego_sha256", &rego_hash),
        ("agent_policy_sha256", &agent_hash),
        ("artifact_bundle_digest", &bundle_hash),
        ("issuer_key_id", value.issuer_key_id.as_bytes()),
        ("issued_at", issued_at.as_bytes()),
        ("expires_at", expires_at.as_bytes()),
        ("signature_alg", value.signature_alg.as_bytes()),
    ]))
}

fn artifact_bundle_digest(inputs: &AuthorizationInputs<'_>) -> Result<[u8; 32]> {
    let descriptor_hash: [u8; 32] = Sha256::digest(descriptor_canonical_bytes(
        &inputs.descriptor_envelope.descriptor,
    ))
    .into();
    let keyring_hash: [u8; 32] =
        Sha256::digest(canonical_keyring_bytes(&inputs.keyring_envelope.keyring)).into();
    let metadata_hash = canonical_policy_metadata_hash(&inputs.artifact.metadata)?;
    let rego_hash: [u8; 32] = Sha256::digest(inputs.artifact.rego_text.as_bytes()).into();
    let agent_hash: [u8; 32] = Sha256::digest(inputs.artifact.agent_policy_text.as_bytes()).into();
    let policy_signature = decode_signature(&inputs.artifact.signature)?;
    let policy_pubkey: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(inputs.artifact.verify_pubkey_b64.as_bytes())
        .context("decoding policy verify key")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("policy verify key is {} bytes", bytes.len()))?;

    Ok(ce_v1_hash(&[
        ("purpose", b"enclava-workload-artifact-bundle-v1"),
        ("descriptor", &descriptor_hash),
        (
            "descriptor_signature",
            &inputs.descriptor_envelope.signature.to_bytes(),
        ),
        (
            "descriptor_signing_key_id",
            inputs.descriptor_envelope.signing_key_id.as_bytes(),
        ),
        ("org_keyring", &keyring_hash),
        (
            "org_keyring_signature",
            &inputs.keyring_envelope.signature.to_bytes(),
        ),
        (
            "org_keyring_signing_pubkey",
            &inputs.keyring_envelope.signing_pubkey.to_bytes(),
        ),
        ("policy_metadata", &metadata_hash),
        ("rego_sha256", &rego_hash),
        ("agent_policy_sha256", &agent_hash),
        ("policy_signature", &policy_signature),
        ("policy_verify_pubkey", &policy_pubkey),
    ]))
}

fn authorized_paths(descriptor: &DeploymentDescriptor, receipt: &str) -> Result<Vec<String>> {
    let segments: Vec<&str> = descriptor.kbs_resource_path.split('/').collect();
    if segments.len() != 3
        || segments[0] != "default"
        || !segments[1].ends_with("-owner")
        || segments[2] != "seed-encrypted"
        || !is_resource_path(&descriptor.kbs_resource_path)
    {
        bail!("descriptor KBS path is not a canonical owner seed-encrypted path");
    }
    Ok(vec![
        descriptor.kbs_resource_path.clone(),
        format!("{}/{}/seed-sealed", segments[0], segments[1]),
        receipt.to_string(),
    ])
}

fn is_resource_path(value: &str) -> bool {
    !value.starts_with('/')
        && !value.contains('%')
        && !value.contains('\\')
        && value.is_ascii()
        && value.split('/').count() == 3
        && value.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && !segment.starts_with('.')
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn canonical_paths_hash(paths: &[String]) -> [u8; 32] {
    let records: Vec<(String, &[u8])> = paths
        .iter()
        .enumerate()
        .map(|(index, path)| (format!("path-{index}"), path.as_bytes()))
        .collect();
    let refs: Vec<(&str, &[u8])> = records
        .iter()
        .map(|(label, path)| (label.as_str(), *path))
        .collect();
    ce_v1_hash(&refs)
}

fn timestamp(value: DateTime<Utc>) -> String {
    value.to_rfc3339_opts(SecondsFormat::AutoSi, true)
}

fn decode_hex32(name: &str, value: &str) -> Result<[u8; 32]> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("{name} must be 64 lowercase hexadecimal characters");
    }
    hex::decode(value)?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("{name} is {} bytes", bytes.len()))
}

fn decode_signature(value: &str) -> Result<[u8; 64]> {
    hex::decode(value)?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("policy signature is {} bytes", bytes.len()))
}

pub fn verify_issued_authorization(
    value: &DeploymentAuthorizationV1,
    key: &SigningKey,
) -> Result<()> {
    use ed25519_dalek::{Signature, Verifier as _};
    let signature: [u8; 64] = URL_SAFE_NO_PAD
        .decode(value.signature.as_bytes())?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("authorization signature is {} bytes", bytes.len()))?;
    key.verifying_key()
        .verify(
            &authorization_signing_bytes(value)?,
            &Signature::from_bytes(&signature),
        )
        .context("verifying issued authorization")
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone as _;

    #[test]
    fn authorization_signing_vector_matches_cap_and_init_contract() {
        let descriptor_hash = [0x11; 32];
        let value = DeploymentAuthorizationV1 {
            schema_version: AUTHORIZATION_SCHEMA_V1.into(),
            authorization_id: Uuid::from_u128(1),
            org_id: Uuid::from_u128(2),
            app_id: Uuid::from_u128(3),
            descriptor_deploy_id: Uuid::from_u128(4),
            descriptor_core_hash: hex::encode(descriptor_hash),
            expected_init_data_hash: "22".repeat(32),
            namespace: "cust-1234-app".into(),
            service_account: "workload".into(),
            tenant_instance_identity_hash: "33".repeat(32),
            org_owner_version: 7,
            org_owner_pubkey_sha256: "44".repeat(32),
            image_digest: format!("sha256:{}", "55".repeat(32)),
            signer_identity: crate::descriptor::SignerIdentity {
                subject: "subject".into(),
                issuer: "issuer".into(),
            },
            receipt_resource_path: format!(
                "default/policy-receipts/{}",
                hex::encode(descriptor_hash)
            ),
            authorized_resource_paths: vec![
                "default/acme-owner/seed-encrypted".into(),
                "default/acme-owner/seed-sealed".into(),
                format!("default/policy-receipts/{}", hex::encode(descriptor_hash)),
            ],
            rego_sha256: "66".repeat(32),
            agent_policy_sha256: "77".repeat(32),
            artifact_bundle_digest: "88".repeat(32),
            issuer_key_id: "platform-authorization-1".into(),
            issued_at: Utc.with_ymd_and_hms(2026, 7, 10, 1, 2, 3).unwrap(),
            expires_at: None,
            signature_alg: "ed25519".into(),
            signature: URL_SAFE_NO_PAD.encode([0u8; 64]),
        };
        assert_eq!(
            hex::encode(Sha256::digest(authorization_signing_bytes(&value).unwrap())),
            "8d723c0a2f9a19d6dbe37f11d8dd1707acb1623fb1c8f1c13d9d9920bbb28036"
        );
    }
}
