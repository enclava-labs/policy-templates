use std::{env, net::SocketAddr, path::PathBuf, sync::Arc};

use anyhow::{anyhow, Context, Result};
use axum::{
    extract::{Path, Request, State},
    http::{header, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use enclava_policy_signing_service::{
    canonical::ce_v1_bytes,
    genpolicy::GenpolicyConfig,
    owner_store::{BootstrapOutcome, OwnerStore},
    policy::{
        decode_signing_blobs, load_signing_key_material, sign_verified_policy,
        verify_signing_inputs, SignRequest, SignedPolicyArtifact, SigningKeyMaterial,
    },
    policy::{template_sha256, verify_signed_artifact},
    TEMPLATE_ID,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

// Axum 0.7 uses `:name` for dynamic path segments (`{name}` is Axum 0.8 syntax).
const OWNER_STATUS_ROUTE: &str = "/orgs/:org_id/owner";

#[derive(Clone)]
struct AppState {
    key_material: Option<Arc<SigningKeyMaterial>>,
    owner_store: Option<Arc<OwnerStore>>,
    genpolicy: GenpolicyConfig,
    template_sha256: String,
    auth: Arc<ServiceAuth>,
}

#[derive(Clone)]
struct ServiceAuth {
    token_hashes: Vec<[u8; 32]>,
}

#[derive(Debug, Deserialize)]
struct BootstrapOrgRequest {
    org_id: Uuid,
    #[serde(default)]
    owner_pubkey_b64: Option<String>,
    #[serde(default)]
    owner_pubkey_hex: Option<String>,
}

#[derive(Debug, Serialize)]
struct BootstrapOrgResponse {
    org_id: Uuid,
    state: &'static str,
    owner_pubkey_fingerprint: String,
}

#[derive(Debug, Deserialize)]
struct RotateOwnerRequest {
    org_id: Uuid,
    replacement_owner_pubkey_b64: String,
    signed_at: DateTime<Utc>,
    reason: String,
    signing_pubkey_b64: String,
    signature_b64: String,
}

#[derive(Debug, Serialize)]
struct RotateOwnerResponse {
    org_id: Uuid,
    version: u64,
    owner_pubkey_fingerprint: String,
    rotated_at: String,
}

#[derive(Debug, Serialize)]
struct OwnerStatusResponse {
    org_id: Uuid,
    state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    version: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    owner_pubkey_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_changed_at: Option<String>,
}

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: &'static str,
    policy_template_id: &'static str,
    policy_template_sha256: String,
    platform_policy_signing_enabled: bool,
    genpolicy_version_pin: String,
}

#[derive(Debug, Deserialize)]
struct AgentPolicyRequest {
    descriptor: enclava_policy_signing_service::descriptor::DeploymentDescriptor,
    #[serde(default)]
    log_encryption: Option<enclava_policy_signing_service::descriptor::LogEncryptionConfig>,
}

#[derive(Debug, Serialize)]
struct AgentPolicyResponse {
    agent_policy_text: String,
    agent_policy_sha256: String,
    genpolicy_version_pin: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    log_encryption: Option<enclava_policy_signing_service::descriptor::LogEncryptionConfig>,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let platform_policy_signing_enabled = env_flag("ENABLE_PLATFORM_POLICY_SIGNING");
    let key_material = if platform_policy_signing_enabled {
        Some(Arc::new(load_signing_key_material()?))
    } else {
        None
    };
    let legacy_owner_api_enabled = legacy_owner_api_enabled(platform_policy_signing_enabled);
    let owner_store = if legacy_owner_api_enabled {
        let owner_db_path =
            env::var("OWNER_DB_PATH").unwrap_or_else(|_| "owner-state.sqlite3".into());
        Some(Arc::new(OwnerStore::open(PathBuf::from(owner_db_path))?))
    } else {
        None
    };
    let genpolicy = GenpolicyConfig::from_env();
    genpolicy.require_pinned_version()?;
    let auth = ServiceAuth::from_env()?;
    let state = AppState {
        key_material,
        owner_store,
        genpolicy,
        template_sha256: hex::encode(template_sha256()),
        auth: Arc::new(auth),
    };

    let mut protected_routes = Router::new().route("/agent-policy", post(generate_agent_policy));
    if legacy_owner_api_enabled {
        protected_routes = protected_routes
            .route("/sign", post(sign_policy))
            .route("/bootstrap-org", post(bootstrap_org))
            .route("/rotate-owner", post(rotate_owner))
            .route(OWNER_STATUS_ROUTE, get(owner_status));
    } else {
        tracing::info!(
            "legacy platform signing and owner bootstrap routes are disabled; serving /agent-policy only"
        );
    }
    let protected_routes = protected_routes
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_service_auth,
        ))
        .with_state(state.clone());

    let app = Router::new()
        .route("/healthz", get(healthz))
        .merge(protected_routes)
        .with_state(state);

    let addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "0.0.0.0:8080".to_string())
        .parse()
        .context("invalid BIND_ADDR")?;
    let listener = tokio::net::TcpListener::bind(addr).await?;
    tracing::info!(%addr, "policy signing service listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

async fn healthz(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok",
        policy_template_id: TEMPLATE_ID,
        policy_template_sha256: state.template_sha256,
        platform_policy_signing_enabled: state.key_material.is_some(),
        genpolicy_version_pin: state.genpolicy.version_pin,
    })
}

async fn require_service_auth(State(state): State<AppState>, req: Request, next: Next) -> Response {
    if state.auth.authorizes(&req) {
        return next.run(req).await;
    }
    (
        StatusCode::UNAUTHORIZED,
        [(header::WWW_AUTHENTICATE, "Bearer")],
        "signing-service bearer token required",
    )
        .into_response()
}

async fn generate_agent_policy(
    State(state): State<AppState>,
    Json(req): Json<AgentPolicyRequest>,
) -> Result<Json<AgentPolicyResponse>, AppError> {
    if req.descriptor.schema_version != "v1" {
        return Err(AppError(anyhow!("unsupported descriptor schema_version")));
    }
    let generated = state
        .genpolicy
        .run_with_log_encryption(&req.descriptor, req.log_encryption.as_ref())?;
    let agent_policy_sha256 = hex::encode(Sha256::digest(generated.policy_text.as_bytes()));
    Ok(Json(AgentPolicyResponse {
        agent_policy_text: generated.policy_text,
        agent_policy_sha256,
        genpolicy_version_pin: generated.invocation.version_pin,
        log_encryption: req.log_encryption,
    }))
}

async fn sign_policy(
    State(state): State<AppState>,
    Json(req): Json<SignRequest>,
) -> Result<Json<SignedPolicyArtifact>, AppError> {
    let key_material = state.key_material.as_ref().ok_or_else(|| {
        anyhow!(
            "platform policy signing is disabled; submit a customer-signed policy artifact instead"
        )
    })?;
    let blobs = decode_signing_blobs(&req)?;
    if blobs.descriptor_envelope.descriptor.org_id != blobs.keyring_envelope.keyring.org_id {
        return Err(AppError(anyhow!(
            "descriptor org_id does not match org keyring org_id"
        )));
    }
    let owner = state
        .owner_store
        .as_ref()
        .ok_or_else(|| anyhow!("legacy owner API is disabled"))?
        .require_owner(blobs.descriptor_envelope.descriptor.org_id)?;
    let inputs = verify_signing_inputs(blobs, &owner.owner_pubkey)?;
    let generated_agent_policy = state
        .genpolicy
        .run_with_log_encryption(&inputs.descriptor, req.log_encryption.as_ref())?;
    tracing::info!(
        genpolicy_version = %generated_agent_policy.invocation.version_pin,
        manifest_bytes = generated_agent_policy.invocation.manifest_yaml.len(),
        policy_bytes = generated_agent_policy.policy_text.len(),
        "generated Kata agent policy from verified deployment descriptor"
    );
    let artifact = sign_verified_policy(
        &req,
        inputs,
        generated_agent_policy,
        key_material,
        Utc::now(),
    )?;
    let verify_key = key_material.signing_key.verifying_key();
    verify_signed_artifact(&artifact, &verify_key)?;
    Ok(Json(artifact))
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false)
}

fn legacy_owner_api_enabled(platform_policy_signing_enabled: bool) -> bool {
    platform_policy_signing_enabled && env_flag("SIGNING_SERVICE_ENABLE_LEGACY_OWNER_API")
}

impl ServiceAuth {
    fn from_env() -> Result<Self> {
        let mut tokens = Vec::new();
        if let Ok(token) = env::var("SIGNING_SERVICE_BEARER_TOKEN") {
            push_tokens(&mut tokens, &token);
        }
        if let Ok(token_list) = env::var("SIGNING_SERVICE_BEARER_TOKENS") {
            push_tokens(&mut tokens, &token_list);
        }

        if tokens.is_empty() {
            if env_flag("SIGNING_SERVICE_ALLOW_UNAUTHENTICATED") {
                return Ok(Self {
                    token_hashes: Vec::new(),
                });
            }
            anyhow::bail!(
                "SIGNING_SERVICE_BEARER_TOKEN or SIGNING_SERVICE_BEARER_TOKENS is required; set SIGNING_SERVICE_ALLOW_UNAUTHENTICATED=1 only for local development"
            );
        }

        Ok(Self {
            token_hashes: tokens
                .into_iter()
                .map(|token| Sha256::digest(token.as_bytes()).into())
                .collect(),
        })
    }

    fn authorizes(&self, req: &Request) -> bool {
        if self.token_hashes.is_empty() {
            return true;
        }
        let Some(token) = bearer_token(req) else {
            return false;
        };
        let candidate: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        self.token_hashes
            .iter()
            .any(|trusted| constant_time_eq(trusted, &candidate))
    }
}

fn push_tokens(tokens: &mut Vec<String>, raw: &str) {
    tokens.extend(
        raw.split(|c: char| c == ',' || c.is_ascii_whitespace())
            .map(str::trim)
            .filter(|token| !token.is_empty())
            .map(ToString::to_string),
    );
}

fn bearer_token(req: &Request) -> Option<&str> {
    let raw = req.headers().get(header::AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ")
        .or_else(|| raw.strip_prefix("bearer "))
        .map(str::trim)
        .filter(|token| !token.is_empty())
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right.iter()) {
        diff |= a ^ b;
    }
    diff == 0
}

async fn bootstrap_org(
    State(state): State<AppState>,
    Json(req): Json<BootstrapOrgRequest>,
) -> Result<Json<BootstrapOrgResponse>, AppError> {
    let owner_pubkey = match (&req.owner_pubkey_b64, &req.owner_pubkey_hex) {
        (Some(raw), None) => decode_pubkey_b64("owner_pubkey_b64", raw)?,
        (None, Some(raw)) => decode_pubkey_hex("owner_pubkey_hex", raw)?,
        (Some(_), Some(_)) => {
            return Err(AppError(anyhow!(
                "provide only one of owner_pubkey_b64 or owner_pubkey_hex"
            )));
        }
        (None, None) => {
            return Err(AppError(anyhow!(
                "owner_pubkey_b64 or owner_pubkey_hex is required"
            )));
        }
    };
    let outcome = state
        .owner_store
        .as_ref()
        .ok_or_else(|| anyhow!("legacy owner API is disabled"))?
        .bootstrap_owner(req.org_id, owner_pubkey, Utc::now())?;
    let state_label = match outcome {
        BootstrapOutcome::Created => "bootstrapped",
        BootstrapOutcome::AlreadyExists => "already-bootstrapped",
    };
    Ok(Json(BootstrapOrgResponse {
        org_id: req.org_id,
        state: state_label,
        owner_pubkey_fingerprint: hex::encode(owner_pubkey.to_bytes()),
    }))
}

async fn owner_status(
    State(state): State<AppState>,
    Path(org_id): Path<Uuid>,
) -> Result<Json<OwnerStatusResponse>, AppError> {
    let store = state
        .owner_store
        .as_ref()
        .ok_or_else(|| anyhow!("legacy owner API is disabled"))?;
    Ok(Json(owner_status_response(store, org_id)?))
}

fn owner_status_response(store: &OwnerStore, org_id: Uuid) -> Result<OwnerStatusResponse> {
    let Some(owner) = store.get_owner(org_id)? else {
        return Ok(OwnerStatusResponse {
            org_id,
            state: "not_configured",
            version: None,
            owner_pubkey_hex: None,
            last_changed_at: None,
        });
    };
    Ok(OwnerStatusResponse {
        org_id,
        state: "ready",
        version: Some(owner.version),
        owner_pubkey_hex: Some(hex::encode(owner.owner_pubkey.to_bytes())),
        last_changed_at: Some(
            owner
                .rotated_at
                .unwrap_or(owner.bootstrapped_at)
                .to_rfc3339(),
        ),
    })
}

async fn rotate_owner(
    State(state): State<AppState>,
    Json(req): Json<RotateOwnerRequest>,
) -> Result<Json<RotateOwnerResponse>, AppError> {
    if req.reason.trim().is_empty() {
        return Err(AppError(anyhow!("rotation reason is required")));
    }
    let owner_store = state
        .owner_store
        .as_ref()
        .ok_or_else(|| anyhow!("legacy owner API is disabled"))?;
    let current = owner_store.require_owner(req.org_id)?;
    let signing_pubkey = decode_pubkey_b64("signing_pubkey_b64", &req.signing_pubkey_b64)?;
    let replacement = decode_pubkey_b64(
        "replacement_owner_pubkey_b64",
        &req.replacement_owner_pubkey_b64,
    )?;
    if !rotation_authority_is_current_or_replay(
        &current.owner_pubkey,
        &signing_pubkey,
        &replacement,
    ) {
        return Err(AppError(anyhow!(
            "rotation directive must be signed by the current owner"
        )));
    }
    let signature = decode_signature_b64("signature_b64", &req.signature_b64)?;
    let directive = recovery_directive_bytes(
        req.org_id,
        &signing_pubkey,
        &replacement,
        req.signed_at,
        &req.reason,
    );
    signing_pubkey
        .verify(&directive, &signature)
        .map_err(|err| anyhow!("owner rotation signature verification failed: {err}"))?;

    let rotated =
        owner_store.rotate_owner(req.org_id, current.owner_pubkey, replacement, Utc::now())?;
    Ok(Json(RotateOwnerResponse {
        org_id: req.org_id,
        version: rotated.version,
        owner_pubkey_fingerprint: hex::encode(rotated.owner_pubkey.to_bytes()),
        rotated_at: rotated.rotated_at.unwrap_or_else(Utc::now).to_rfc3339(),
    }))
}

fn rotation_authority_is_current_or_replay(
    current: &VerifyingKey,
    signer: &VerifyingKey,
    replacement: &VerifyingKey,
) -> bool {
    signer.to_bytes() == current.to_bytes() || replacement.to_bytes() == current.to_bytes()
}

fn recovery_directive_bytes(
    org_id: Uuid,
    revoked_pubkey: &VerifyingKey,
    replacement_pubkey: &VerifyingKey,
    signed_at: DateTime<Utc>,
    reason: &str,
) -> Vec<u8> {
    let revoked = revoked_pubkey.to_bytes();
    let replacement = replacement_pubkey.to_bytes();
    let signed_at = signed_at.to_rfc3339();
    ce_v1_bytes(&[
        ("purpose", b"enclava-recovery-v1"),
        ("org_id", org_id.as_bytes().as_slice()),
        ("revoked_pubkey", &revoked),
        ("replacement_pubkey", &replacement),
        ("signed_at", signed_at.as_bytes()),
        ("reason", reason.as_bytes()),
    ])
}

fn decode_pubkey_b64(name: &str, raw: &str) -> Result<VerifyingKey> {
    let bytes = B64
        .decode(raw.as_bytes())
        .with_context(|| format!("decoding {name}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|err| anyhow!("{name} is not a valid Ed25519 key: {err}"))
}

fn decode_pubkey_hex(name: &str, raw: &str) -> Result<VerifyingKey> {
    let bytes = hex::decode(raw).with_context(|| format!("decoding {name}"))?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to 32 bytes"))?;
    VerifyingKey::from_bytes(&arr)
        .map_err(|err| anyhow!("{name} is not a valid Ed25519 key: {err}"))
}

fn decode_signature_b64(name: &str, raw: &str) -> Result<Signature> {
    let bytes = B64
        .decode(raw.as_bytes())
        .with_context(|| format!("decoding {name}"))?;
    let arr: [u8; 64] = bytes
        .try_into()
        .map_err(|_| anyhow!("{name} must decode to 64 bytes"))?;
    Ok(Signature::from_bytes(&arr))
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

struct AppError(anyhow::Error);

impl<E> From<E> for AppError
where
    E: Into<anyhow::Error>,
{
    fn from(err: E) -> Self {
        Self(err.into())
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, self.0.to_string()).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn recovery_directive_signature_round_trips() {
        let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let current = SigningKey::from_bytes(&[0x11; 32]);
        let replacement = SigningKey::from_bytes(&[0x22; 32]).verifying_key();
        let signed_at = DateTime::parse_from_rfc3339("2026-04-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        let bytes = recovery_directive_bytes(
            org_id,
            &current.verifying_key(),
            &replacement,
            signed_at,
            "routine owner rotation",
        );
        let signature = current.sign(&bytes);
        current.verifying_key().verify(&bytes, &signature).unwrap();
    }

    #[test]
    fn owner_status_distinguishes_absent_and_ready_without_private_material() {
        let dir = tempfile::tempdir().unwrap();
        let store = OwnerStore::open(dir.path().join("owners.sqlite3")).unwrap();
        let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let absent = owner_status_response(&store, org_id).unwrap();
        assert_eq!(absent.state, "not_configured");
        assert_eq!(absent.version, None);
        assert_eq!(absent.owner_pubkey_hex, None);

        let owner = SigningKey::from_bytes(&[0x11; 32]).verifying_key();
        let now = DateTime::parse_from_rfc3339("2026-04-01T12:00:00Z")
            .unwrap()
            .with_timezone(&Utc);
        store.bootstrap_owner(org_id, owner, now).unwrap();
        let ready = owner_status_response(&store, org_id).unwrap();
        assert_eq!(ready.state, "ready");
        assert_eq!(ready.version, Some(1));
        let expected_fingerprint = hex::encode(owner.to_bytes());
        assert_eq!(
            ready.owner_pubkey_hex.as_deref(),
            Some(expected_fingerprint.as_str())
        );
        assert_eq!(
            ready.last_changed_at.as_deref(),
            Some("2026-04-01T12:00:00+00:00")
        );
    }

    #[test]
    fn owner_status_route_uses_axum_seven_dynamic_segment_syntax() {
        assert_eq!(OWNER_STATUS_ROUTE, "/orgs/:org_id/owner");
    }

    #[test]
    fn owner_rotation_accepts_only_current_authority_or_exact_replacement_replay() {
        let current = SigningKey::from_bytes(&[0x11; 32]).verifying_key();
        let replacement = SigningKey::from_bytes(&[0x22; 32]).verifying_key();
        let stranger = SigningKey::from_bytes(&[0x33; 32]).verifying_key();

        assert!(rotation_authority_is_current_or_replay(
            &current,
            &current,
            &replacement
        ));
        assert!(rotation_authority_is_current_or_replay(
            &replacement,
            &current,
            &replacement
        ));
        assert!(rotation_authority_is_current_or_replay(
            &replacement,
            &stranger,
            &replacement
        ));
        assert!(!rotation_authority_is_current_or_replay(
            &current,
            &stranger,
            &replacement
        ));
    }

    #[test]
    fn bearer_auth_accepts_only_configured_tokens() {
        let auth = ServiceAuth {
            token_hashes: vec![Sha256::digest(b"correct-token").into()],
        };
        let ok = Request::builder()
            .header(header::AUTHORIZATION, "Bearer correct-token")
            .body(Body::empty())
            .unwrap();
        let wrong = Request::builder()
            .header(header::AUTHORIZATION, "Bearer wrong-token")
            .body(Body::empty())
            .unwrap();
        let missing = Request::builder().body(Body::empty()).unwrap();

        assert!(auth.authorizes(&ok));
        assert!(!auth.authorizes(&wrong));
        assert!(!auth.authorizes(&missing));
    }

    #[test]
    fn bearer_auth_disabled_only_when_token_list_is_empty() {
        let auth = ServiceAuth {
            token_hashes: Vec::new(),
        };
        let req = Request::builder().body(Body::empty()).unwrap();
        assert!(auth.authorizes(&req));
    }

    #[test]
    fn legacy_owner_api_is_disabled_by_default_even_with_platform_key_material() {
        std::env::remove_var("SIGNING_SERVICE_ENABLE_LEGACY_OWNER_API");

        assert!(!legacy_owner_api_enabled(true));
        assert!(!legacy_owner_api_enabled(false));
    }
}
