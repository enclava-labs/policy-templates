use std::{env, path::PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::SigningKey;
use enclava_policy_signing_service::{
    genpolicy::GenpolicyConfig,
    policy::{
        decode_signing_blobs, sign_verified_policy, verify_signed_artifact, verify_signing_inputs,
        SignRequest, SigningKeyMaterial,
    },
};

fn main() -> Result<()> {
    // The genpolicy invocation is async; the CLI binary drives a minimal
    // single-threaded runtime for it (same blocking UX for the operator).
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("building the policy-artifact runtime")?;
    let args = Args::parse(env::args().skip(1).collect())?;
    let request: SignRequest = serde_json::from_slice(
        &std::fs::read(&args.request)
            .with_context(|| format!("reading {}", args.request.display()))?,
    )
    .context("parsing sign request JSON")?;
    let owner_pubkey = decode_pubkey_hex(&args.owner_pubkey_hex)?;
    let signing_key = SigningKey::from_bytes(&decode_seed_hex(&args.signing_seed_hex)?);
    let key_material = SigningKeyMaterial {
        key_id: args.key_id,
        signing_key,
    };

    let blobs = decode_signing_blobs(&request)?;
    let inputs = verify_signing_inputs(blobs, &owner_pubkey)?;
    if inputs.descriptor_signing_pubkey.to_bytes()
        != key_material.signing_key.verifying_key().to_bytes()
    {
        bail!("artifact signing key must match descriptor_signing_pubkey");
    }

    // Drive the generation with Ctrl-C routed through the subprocess
    // cleanup path (Devin T2): on SIGINT the generation future is
    // dropped, which drops the Child (kill_on_drop) AND fires the
    // process-group guard's Drop — the child and its helpers are
    // TERMed before the CLI exits with an interrupted status.
    let generation = async { GenpolicyConfig::from_env().run(&inputs.descriptor).await };
    let generated_agent_policy = runtime.block_on(async {
        tokio::select! {
            result = generation => result,
            _ = tokio::signal::ctrl_c() => {
                // Give the dropped-future cleanup a beat to TERM the group.
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                bail!("interrupted: genpolicy terminated (process group TERMed)");
            }
        }
    })?;
    let signed_at = args
        .signed_at
        .map(|value| DateTime::parse_from_rfc3339(&value).map(|dt| dt.with_timezone(&Utc)))
        .transpose()
        .context("parsing --signed-at")?
        .unwrap_or_else(Utc::now);
    let artifact = sign_verified_policy(
        &request,
        inputs,
        generated_agent_policy,
        &key_material,
        signed_at,
    )?;
    verify_signed_artifact(&artifact, &key_material.signing_key.verifying_key())?;
    let out = serde_json::to_vec_pretty(&artifact)?;
    if let Some(path) = args.out {
        std::fs::write(&path, out).with_context(|| format!("writing {}", path.display()))?;
    } else {
        println!("{}", String::from_utf8(out)?);
    }
    Ok(())
}

#[derive(Debug)]
struct Args {
    request: PathBuf,
    owner_pubkey_hex: String,
    signing_seed_hex: String,
    key_id: String,
    signed_at: Option<String>,
    out: Option<PathBuf>,
}

impl Args {
    fn parse(raw: Vec<String>) -> Result<Self> {
        let mut request = None;
        let mut owner_pubkey_hex = None;
        let mut signing_seed_hex = None;
        let mut key_id = None;
        let mut signed_at = None;
        let mut out = None;

        let mut iter = raw.into_iter();
        while let Some(flag) = iter.next() {
            let mut value = || {
                iter.next()
                    .ok_or_else(|| anyhow!("{flag} requires a value"))
            };
            match flag.as_str() {
                "--request" => request = Some(PathBuf::from(value()?)),
                "--owner-pubkey-hex" => owner_pubkey_hex = Some(value()?),
                "--signing-seed-hex" => signing_seed_hex = Some(value()?),
                "--key-id" => key_id = Some(value()?),
                "--signed-at" => signed_at = Some(value()?),
                "--out" => out = Some(PathBuf::from(value()?)),
                "--help" | "-h" => {
                    println!(
                        "usage: policy-artifact --request sign-request.json --owner-pubkey-hex <hex> --signing-seed-hex <hex> --key-id <id> [--signed-at <rfc3339>] [--out artifact.json]"
                    );
                    std::process::exit(0);
                }
                other => bail!("unknown argument: {other}"),
            }
        }

        Ok(Self {
            request: request.ok_or_else(|| anyhow!("--request is required"))?,
            owner_pubkey_hex: owner_pubkey_hex
                .or_else(|| env::var("ENCLAVA_OWNER_PUBKEY_HEX").ok())
                .ok_or_else(|| anyhow!("--owner-pubkey-hex is required"))?,
            signing_seed_hex: signing_seed_hex
                .or_else(|| env::var("ENCLAVA_POLICY_ARTIFACT_SIGNING_SEED_HEX").ok())
                .ok_or_else(|| anyhow!("--signing-seed-hex is required"))?,
            key_id: key_id
                .or_else(|| env::var("ENCLAVA_POLICY_ARTIFACT_KEY_ID").ok())
                .ok_or_else(|| anyhow!("--key-id is required"))?,
            signed_at,
            out,
        })
    }
}

fn decode_seed_hex(value: &str) -> Result<[u8; 32]> {
    hex::decode(value.trim())
        .context("decoding signing seed hex")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("signing seed must be 32 bytes, got {}", bytes.len()))
}

fn decode_pubkey_hex(value: &str) -> Result<ed25519_dalek::VerifyingKey> {
    let raw: [u8; 32] = hex::decode(value.trim())
        .context("decoding owner pubkey hex")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("owner pubkey must be 32 bytes, got {}", bytes.len()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&raw).context("parsing owner pubkey")
}
