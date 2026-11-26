use std::{env, path::PathBuf};

use anyhow::{anyhow, bail, Context as _, Result};
use ed25519_dalek::{Signer as _, SigningKey};
use enclava_policy_signing_service::canonical::ce_v1_bytes;
use serde::Serialize;
use sha2::{Digest as _, Sha256};

const SCHEMA: &str = "enclava-kbs-static-resource-policy-v1";

#[derive(Serialize)]
struct StaticPolicyArtifact {
    schema_version: &'static str,
    policy_epoch: u64,
    rego_text: String,
    rego_sha256: String,
    issuer_key_id: String,
    signature_alg: &'static str,
    signature: String,
}

fn main() -> Result<()> {
    let args = Args::parse(env::args().skip(1).collect())?;
    let rego_text = std::fs::read_to_string(&args.rego)
        .with_context(|| format!("reading {}", args.rego.display()))?;
    if rego_text.is_empty() {
        bail!("static policy Rego is empty");
    }
    let rego_sha256: [u8; 32] = Sha256::digest(rego_text.as_bytes()).into();
    let signing_key = SigningKey::from_bytes(&decode_seed_hex(&args.signing_seed_hex)?);
    let epoch = args.policy_epoch.to_be_bytes();
    let signature_alg = "ed25519";
    let signing_bytes = ce_v1_bytes(&[
        ("purpose", SCHEMA.as_bytes()),
        ("schema_version", SCHEMA.as_bytes()),
        ("policy_epoch", &epoch),
        ("rego_sha256", &rego_sha256),
        ("issuer_key_id", args.key_id.as_bytes()),
        ("signature_alg", signature_alg.as_bytes()),
    ]);
    let artifact = StaticPolicyArtifact {
        schema_version: SCHEMA,
        policy_epoch: args.policy_epoch,
        rego_text,
        rego_sha256: hex::encode(rego_sha256),
        issuer_key_id: args.key_id,
        signature_alg,
        signature: hex::encode(signing_key.sign(&signing_bytes).to_bytes()),
    };
    let bytes = serde_json::to_vec_pretty(&artifact)?;
    let artifact_sha256 = hex::encode(Sha256::digest(&bytes));
    eprintln!("static_resource_policy_sha256={artifact_sha256}");
    eprintln!("static_policy_issuer_key_id={}", artifact.issuer_key_id);
    if let Some(path) = args.out {
        std::fs::write(&path, bytes).with_context(|| format!("writing {}", path.display()))?;
    } else {
        println!("{}", String::from_utf8(bytes)?);
    }
    Ok(())
}

struct Args {
    rego: PathBuf,
    policy_epoch: u64,
    signing_seed_hex: String,
    key_id: String,
    out: Option<PathBuf>,
}

impl Args {
    fn parse(raw: Vec<String>) -> Result<Self> {
        let mut rego = None;
        let mut policy_epoch = None;
        let mut signing_seed_hex = None;
        let mut key_id = None;
        let mut out = None;
        let mut iter = raw.into_iter();
        while let Some(flag) = iter.next() {
            let mut value = || {
                iter.next()
                    .ok_or_else(|| anyhow!("{flag} requires a value"))
            };
            match flag.as_str() {
                "--rego" => rego = Some(PathBuf::from(value()?)),
                "--policy-epoch" => {
                    policy_epoch = Some(value()?.parse::<u64>().context("parsing policy epoch")?)
                }
                "--signing-seed-hex" => signing_seed_hex = Some(value()?),
                "--key-id" => key_id = Some(value()?),
                "--out" => out = Some(PathBuf::from(value()?)),
                other => bail!("unknown argument: {other}"),
            }
        }
        let policy_epoch = policy_epoch.ok_or_else(|| anyhow!("--policy-epoch is required"))?;
        if policy_epoch == 0 {
            bail!("policy epoch must be greater than zero");
        }
        Ok(Self {
            rego: rego.ok_or_else(|| anyhow!("--rego is required"))?,
            policy_epoch,
            signing_seed_hex: signing_seed_hex
                .or_else(|| env::var("ENCLAVA_STATIC_POLICY_SIGNING_SEED_HEX").ok())
                .ok_or_else(|| anyhow!("--signing-seed-hex is required"))?,
            key_id: key_id
                .or_else(|| env::var("ENCLAVA_STATIC_POLICY_KEY_ID").ok())
                .ok_or_else(|| anyhow!("--key-id is required"))?,
            out,
        })
    }
}

fn decode_seed_hex(value: &str) -> Result<[u8; 32]> {
    hex::decode(value.trim())
        .context("decoding signing seed")?
        .try_into()
        .map_err(|bytes: Vec<u8>| anyhow!("signing seed is {} bytes", bytes.len()))
}
