use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::VerifyingKey;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use uuid::Uuid;

const SQLITE_BUSY_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Clone)]
pub struct OwnerStore {
    path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootstrapOutcome {
    Created,
    AlreadyExists,
}

#[derive(Debug, Clone)]
pub struct OwnerRecord {
    pub org_id: Uuid,
    pub owner_pubkey: VerifyingKey,
    pub version: u64,
    pub bootstrapped_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

impl OwnerStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .with_context(|| format!("creating owner DB directory {}", parent.display()))?;
            }
        }
        let store = Self { path };
        store.initialize()?;
        Ok(store)
    }

    fn connect(&self) -> Result<Connection> {
        let conn = Connection::open(&self.path)
            .with_context(|| format!("opening owner DB {}", self.path.display()))?;
        conn.busy_timeout(SQLITE_BUSY_TIMEOUT)?;
        Ok(conn)
    }

    fn initialize(&self) -> Result<()> {
        let conn = self.connect()?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS owners (
                org_id TEXT PRIMARY KEY NOT NULL,
                owner_pubkey BLOB NOT NULL CHECK(length(owner_pubkey) = 32),
                version INTEGER NOT NULL,
                bootstrapped_at TEXT NOT NULL,
                rotated_at TEXT
            );

            CREATE TABLE IF NOT EXISTS owner_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                org_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                event_type TEXT NOT NULL,
                owner_pubkey BLOB NOT NULL CHECK(length(owner_pubkey) = 32),
                occurred_at TEXT NOT NULL
            );
            "#,
        )?;
        Ok(())
    }

    pub fn bootstrap_owner(
        &self,
        org_id: Uuid,
        owner_pubkey: VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<BootstrapOutcome> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<Vec<u8>> = tx
            .query_row(
                "SELECT owner_pubkey FROM owners WHERE org_id = ?1",
                params![org_id.to_string()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(existing) = existing {
            if existing == owner_pubkey.to_bytes().as_slice() {
                return Ok(BootstrapOutcome::AlreadyExists);
            }
            bail!("org already bootstrapped with a different owner pubkey");
        }

        let now = now.to_rfc3339();
        tx.execute(
            "INSERT INTO owners (org_id, owner_pubkey, version, bootstrapped_at) VALUES (?1, ?2, ?3, ?4)",
            params![org_id.to_string(), owner_pubkey.to_bytes().as_slice(), 1_i64, now],
        )?;
        tx.execute(
            "INSERT INTO owner_events (org_id, version, event_type, owner_pubkey, occurred_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                org_id.to_string(),
                1_i64,
                "bootstrap",
                owner_pubkey.to_bytes().as_slice(),
                now
            ],
        )?;
        tx.commit()?;
        Ok(BootstrapOutcome::Created)
    }

    pub fn get_owner(&self, org_id: Uuid) -> Result<Option<OwnerRecord>> {
        let conn = self.connect()?;
        conn.query_row(
            "SELECT org_id, owner_pubkey, version, bootstrapped_at, rotated_at FROM owners WHERE org_id = ?1",
            params![org_id.to_string()],
            |row| {
                let org_id: String = row.get(0)?;
                let owner_pubkey: Vec<u8> = row.get(1)?;
                let version: i64 = row.get(2)?;
                let bootstrapped_at: String = row.get(3)?;
                let rotated_at: Option<String> = row.get(4)?;
                Ok((org_id, owner_pubkey, version, bootstrapped_at, rotated_at))
            },
        )
        .optional()?
        .map(|(org_id, owner_pubkey, version, bootstrapped_at, rotated_at)| {
            let owner_pubkey = verifying_key_from_vec(owner_pubkey)?;
            Ok(OwnerRecord {
                org_id: Uuid::parse_str(&org_id)?,
                owner_pubkey,
                version: u64::try_from(version).map_err(|_| anyhow!("negative owner version"))?,
                bootstrapped_at: DateTime::parse_from_rfc3339(&bootstrapped_at)?.with_timezone(&Utc),
                rotated_at: rotated_at
                    .map(|raw| DateTime::parse_from_rfc3339(&raw).map(|dt| dt.with_timezone(&Utc)))
                    .transpose()?,
            })
        })
        .transpose()
    }

    pub fn require_owner(&self, org_id: Uuid) -> Result<OwnerRecord> {
        self.get_owner(org_id)?
            .ok_or_else(|| anyhow!("org is not bootstrapped in signing-service owner DB"))
    }

    pub fn rotate_owner(
        &self,
        org_id: Uuid,
        expected_current: VerifyingKey,
        replacement: VerifyingKey,
        now: DateTime<Utc>,
    ) -> Result<OwnerRecord> {
        let mut conn = self.connect()?;
        let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let existing: Option<(Vec<u8>, i64, String)> = tx
            .query_row(
                "SELECT owner_pubkey, version, bootstrapped_at FROM owners WHERE org_id = ?1",
                params![org_id.to_string()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .optional()?;
        let Some((current_bytes, version, bootstrapped_at)) = existing else {
            bail!("org is not bootstrapped in signing-service owner DB");
        };
        if current_bytes != expected_current.to_bytes().as_slice() {
            bail!("rotation signer is not the current owner");
        }
        if replacement.to_bytes() == expected_current.to_bytes() {
            bail!("replacement owner pubkey must differ from current owner pubkey");
        }
        let new_version = version + 1;
        let now_raw = now.to_rfc3339();
        tx.execute(
            "UPDATE owners SET owner_pubkey = ?2, version = ?3, rotated_at = ?4 WHERE org_id = ?1",
            params![
                org_id.to_string(),
                replacement.to_bytes().as_slice(),
                new_version,
                now_raw
            ],
        )?;
        tx.execute(
            "INSERT INTO owner_events (org_id, version, event_type, owner_pubkey, occurred_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                org_id.to_string(),
                new_version,
                "rotation",
                replacement.to_bytes().as_slice(),
                now_raw
            ],
        )?;
        tx.commit()?;
        Ok(OwnerRecord {
            org_id,
            owner_pubkey: replacement,
            version: u64::try_from(new_version).map_err(|_| anyhow!("negative owner version"))?,
            bootstrapped_at: DateTime::parse_from_rfc3339(&bootstrapped_at)?.with_timezone(&Utc),
            rotated_at: Some(now),
        })
    }
}

fn verifying_key_from_vec(bytes: Vec<u8>) -> Result<VerifyingKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("stored owner pubkey must be 32 bytes"))?;
    VerifyingKey::from_bytes(&arr).map_err(|err| anyhow!("stored owner pubkey invalid: {err}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ed25519_dalek::SigningKey;

    fn fixed_time() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 4, 1, 12, 0, 0).unwrap()
    }

    #[test]
    fn bootstrap_persists_and_reopens() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owners.sqlite3");
        let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let owner = SigningKey::from_bytes(&[0x11; 32]).verifying_key();

        let store = OwnerStore::open(&path).unwrap();
        assert_eq!(
            store.bootstrap_owner(org_id, owner, fixed_time()).unwrap(),
            BootstrapOutcome::Created
        );
        drop(store);

        let reopened = OwnerStore::open(&path).unwrap();
        let record = reopened.require_owner(org_id).unwrap();
        assert_eq!(record.owner_pubkey.to_bytes(), owner.to_bytes());
        assert_eq!(record.version, 1);
    }

    #[test]
    fn bootstrap_refuses_different_owner_for_existing_org() {
        let dir = tempfile::tempdir().unwrap();
        let store = OwnerStore::open(dir.path().join("owners.sqlite3")).unwrap();
        let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let owner = SigningKey::from_bytes(&[0x11; 32]).verifying_key();
        let other = SigningKey::from_bytes(&[0x22; 32]).verifying_key();

        store.bootstrap_owner(org_id, owner, fixed_time()).unwrap();
        let err = store
            .bootstrap_owner(org_id, other, fixed_time())
            .unwrap_err();
        assert!(err.to_string().contains("different owner"));
    }

    #[test]
    fn bootstrap_waits_for_transient_sqlite_writer_lock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("owners.sqlite3");
        let store = OwnerStore::open(&path).unwrap();
        let lock_conn = Connection::open(&path).unwrap();
        lock_conn.execute_batch("BEGIN IMMEDIATE").unwrap();

        let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let owner = SigningKey::from_bytes(&[0x11; 32]).verifying_key();
        let store_for_thread = store.clone();
        let handle = std::thread::spawn(move || {
            store_for_thread.bootstrap_owner(org_id, owner, fixed_time())
        });

        std::thread::sleep(Duration::from_millis(100));
        lock_conn.execute_batch("COMMIT").unwrap();

        assert_eq!(handle.join().unwrap().unwrap(), BootstrapOutcome::Created);
    }

    #[test]
    fn rotate_owner_updates_version() {
        let dir = tempfile::tempdir().unwrap();
        let store = OwnerStore::open(dir.path().join("owners.sqlite3")).unwrap();
        let org_id = Uuid::parse_str("11111111-1111-1111-1111-111111111111").unwrap();
        let owner = SigningKey::from_bytes(&[0x11; 32]).verifying_key();
        let replacement = SigningKey::from_bytes(&[0x22; 32]).verifying_key();

        store.bootstrap_owner(org_id, owner, fixed_time()).unwrap();
        let record = store
            .rotate_owner(org_id, owner, replacement, fixed_time())
            .unwrap();
        assert_eq!(record.owner_pubkey.to_bytes(), replacement.to_bytes());
        assert_eq!(record.version, 2);
        assert_eq!(
            store.require_owner(org_id).unwrap().owner_pubkey.to_bytes(),
            replacement.to_bytes()
        );
    }
}
