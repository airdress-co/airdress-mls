//! Sealed file-backed MLS state storage.
//!
//! Implements `mls-rs`'s `GroupStateStorage` and `KeyPackageStorage`
//! over one sealed file per item:
//!
//! - groups: `<state_dir>/groups/<hex group id>`
//! - key package private halves: `<state_dir>/key_packages/<hex id>`
//! - key package public messages: `<state_dir>/key_packages_public/<hex id>`
//!
//! Each file is ChaCha20-Poly1305 over the serialized state under the
//! host-supplied 32-byte state key, with a random 96-bit nonce per
//! write (stored as the file's first 12 bytes) and AAD binding a
//! domain label plus the item id — the same primitive and envelope
//! shape as the operator's chat encryption at rest, deliberately, so
//! there is one reviewed AEAD pattern in the codebase. Writes are
//! write-temp + fsync + rename for crash atomicity.
//!
//! An AEAD failure on open REFUSES the item with a clean error — it
//! never silently re-keys or discards state. `mls-rs-provider-sqlite`
//! was rejected for this job: rusqlite plus a bundled C SQLite across
//! four Android ABIs, two iOS targets and desktop buys indexing we do
//! not need at ~50 groups, where a sealed file per group is auditable
//! in an afternoon.
//!
//! ## Bounded epoch retention is a security property (SPEC-061 FR-21)
//!
//! [`SealedGroupStore`] retains at most
//! [`DEFAULT_MAX_EPOCH_RETENTION`] past-epoch records per group,
//! trimming the oldest on every write. This is **not** housekeeping.
//! `mls-rs`'s own `InMemoryGroupStateStorage` trims to the same bound
//! and this store did not, which was harmless only for as long as no
//! group ever advanced an epoch. Once Commits ship, an untrimmed
//! store keeps every departed epoch's secret tree on disk forever, so
//! anyone who later obtains the sealed file and the state key can
//! decrypt every message ever sent in the group — inter-epoch forward
//! secrecy destroyed at the storage layer regardless of what the
//! protocol does correctly (SPEC-061 NFR-4).
//!
//! Trimming happens on the write path, inside the same re-seal. A
//! background compaction pass would leave a window in which the
//! records still exist, and that window is exactly the moment after
//! an epoch advance — which is when an attacker holding the disk is
//! most interested.
//!
//! **What this does not do** (SPEC-061 NFR-5): the sealed write
//! replaces a file by rename, so the superseded ciphertext's bytes may
//! survive on the filesystem at the filesystem's discretion. Bounded
//! retention is a true statement about the *record*. "The old epoch
//! secrets are gone from the disk" is not a true statement and must
//! not be made. The same caveat already applies to the group state
//! file and is recorded in SPEC-054 §"Delivered".

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{AeadCore, ChaCha20Poly1305};
use mls_rs_core::key_package::KeyPackageData;
use mls_rs_core::mls_rs_codec::{MlsDecode, MlsEncode};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 12;
const GROUP_AAD_LABEL: &[u8] = b"airdress-mls-group-state-v1";
const KEY_PACKAGE_AAD_LABEL: &[u8] = b"airdress-mls-key-package-v1";
const KEY_PACKAGE_PUBLIC_AAD_LABEL: &[u8] = b"airdress-mls-key-package-public-v1";

/// A stored item's id paired with its bytes.
pub type StoredItem = (Vec<u8>, Vec<u8>);

/// Error type shared by both storage implementations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StorageError(pub String);

impl core::fmt::Display for StorageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "mls state storage: {}", self.0)
    }
}

impl std::error::Error for StorageError {}

impl mls_rs_core::error::IntoAnyError for StorageError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(Box::new(self))
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// The shared sealed-file primitive both stores are built on.
#[derive(Clone)]
pub struct SealedStore {
    root: Arc<PathBuf>,
    cipher: Arc<ChaCha20Poly1305>,
}

impl core::fmt::Debug for SealedStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SealedStore")
            .field("root", &self.root)
            .finish_non_exhaustive()
    }
}

impl SealedStore {
    /// Open (creating directories as needed) the sealed store rooted
    /// at `state_dir`, sealing with `state_key`.
    pub fn open(state_dir: &str, state_key: &[u8; 32]) -> Result<Self, StorageError> {
        let root = PathBuf::from(state_dir);
        for sub in ["groups", "key_packages", "key_packages_public"] {
            std::fs::create_dir_all(root.join(sub))
                .map_err(|e| StorageError(format!("create {sub} dir: {e}")))?;
        }
        Ok(Self {
            root: Arc::new(root),
            cipher: Arc::new(ChaCha20Poly1305::new(state_key.into())),
        })
    }

    fn path(&self, sub: &str, id: &[u8]) -> PathBuf {
        self.root.join(sub).join(hex(id))
    }

    fn aad(label: &[u8], id: &[u8]) -> Vec<u8> {
        let mut aad = Vec::with_capacity(label.len() + id.len());
        aad.extend_from_slice(label);
        aad.extend_from_slice(id);
        aad
    }

    /// Seal `plaintext` and atomically write it to `<sub>/<hex id>`.
    fn seal_write(
        &self,
        sub: &str,
        label: &[u8],
        id: &[u8],
        plaintext: &[u8],
    ) -> Result<(), StorageError> {
        let nonce = ChaCha20Poly1305::generate_nonce(&mut chacha20poly1305::aead::OsRng);
        let ciphertext = self
            .cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &Self::aad(label, id),
                },
            )
            .map_err(|_| StorageError("seal failed".to_owned()))?;

        let final_path = self.path(sub, id);
        let tmp_path =
            final_path.with_extension(format!("tmp-{}-{}", std::process::id(), next_tmp_ordinal()));

        let mut file = std::fs::File::create(&tmp_path)
            .map_err(|e| StorageError(format!("create temp file: {e}")))?;
        file.write_all(&nonce)
            .and_then(|()| file.write_all(&ciphertext))
            .and_then(|()| file.sync_all())
            .map_err(|e| StorageError(format!("write temp file: {e}")))?;
        drop(file);
        std::fs::rename(&tmp_path, &final_path)
            .map_err(|e| StorageError(format!("rename into place: {e}")))?;
        // Best-effort directory fsync so the rename itself is durable.
        if let Ok(dir) = std::fs::File::open(final_path.parent().unwrap_or(Path::new("."))) {
            let _ = dir.sync_all();
        }
        Ok(())
    }

    /// Read and unseal `<sub>/<hex id>`. `Ok(None)` when absent; an
    /// AEAD failure (tampering, wrong key, copied file) is an error
    /// that refuses the item — never a silent re-key.
    fn open_read(
        &self,
        sub: &str,
        label: &[u8],
        id: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        let path = self.path(sub, id);
        let sealed = match std::fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(StorageError(format!("read sealed file: {e}"))),
        };
        if sealed.len() < NONCE_LEN {
            return Err(StorageError("sealed file truncated".to_owned()));
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_LEN);
        let plaintext = self
            .cipher
            .decrypt(
                nonce.into(),
                Payload {
                    msg: ciphertext,
                    aad: &Self::aad(label, id),
                },
            )
            .map_err(|_| {
                StorageError(
                    "unseal failed: state file is corrupt or sealed under another key".to_owned(),
                )
            })?;
        Ok(Some(Zeroizing::new(plaintext)))
    }

    fn delete(&self, sub: &str, id: &[u8]) -> Result<(), StorageError> {
        match std::fs::remove_file(self.path(sub, id)) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(StorageError(format!("delete sealed file: {e}"))),
        }
    }

    fn list_ids(&self, sub: &str) -> Result<Vec<Vec<u8>>, StorageError> {
        let mut ids = Vec::new();
        let entries = std::fs::read_dir(self.root.join(sub))
            .map_err(|e| StorageError(format!("list {sub}: {e}")))?;
        for entry in entries {
            let entry = entry.map_err(|e| StorageError(format!("list {sub}: {e}")))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            // Skip leftover temp files from interrupted writes.
            if let Some(id) = parse_hex(name) {
                ids.push(id);
            }
        }
        Ok(ids)
    }
}

static TMP_ORDINAL: AtomicU64 = AtomicU64::new(0);

fn next_tmp_ordinal() -> u64 {
    TMP_ORDINAL.fetch_add(1, Ordering::Relaxed)
}

fn parse_hex(name: &str) -> Option<Vec<u8>> {
    if name.is_empty() || !name.len().is_multiple_of(2) {
        return None;
    }
    (0..name.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(name.get(i..i + 2)?, 16).ok())
        .collect()
}

// ---------------------------------------------------------------------------
// Group state
// ---------------------------------------------------------------------------

/// Plaintext record layout (before sealing), version 1:
/// `u8 version || u32 LE state_len || state || u32 LE epoch_count ||
/// (u64 LE epoch_id || u32 LE len || data)*`
const GROUP_RECORD_VERSION: u8 = 1;

struct GroupRecord {
    state: Vec<u8>,
    epochs: Vec<(u64, Vec<u8>)>,
}

impl GroupRecord {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(GROUP_RECORD_VERSION);
        out.extend_from_slice(&u32::try_from(self.state.len()).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&self.state);
        out.extend_from_slice(&u32::try_from(self.epochs.len()).unwrap_or(0).to_le_bytes());
        for (id, data) in &self.epochs {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_le_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        let err = || StorageError("group record truncated".to_owned());
        let mut cursor = bytes;
        let take = |cursor: &mut &[u8], n: usize| -> Result<Vec<u8>, StorageError> {
            if cursor.len() < n {
                return Err(err());
            }
            let (head, rest) = cursor.split_at(n);
            *cursor = rest;
            Ok(head.to_vec())
        };
        let version = take(&mut cursor, 1)?[0];
        if version != GROUP_RECORD_VERSION {
            return Err(StorageError(format!(
                "unsupported group record version {version}"
            )));
        }
        let state_len = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().map_err(|_| err())?);
        let state = take(&mut cursor, state_len as usize)?;
        let count = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().map_err(|_| err())?);
        let mut epochs = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let id = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().map_err(|_| err())?);
            let len = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().map_err(|_| err())?);
            epochs.push((id, take(&mut cursor, len as usize)?));
        }
        Ok(Self { state, epochs })
    }
}

/// How many past-epoch records a group retains on disk by default.
///
/// Matches `mls-rs`'s own `DEFAULT_EPOCH_RETENTION_LIMIT` (3) in
/// `InMemoryGroupStateStorage`, deliberately: this store stands in for
/// that one, and a different number here would mean forward secrecy
/// depended on which provider a binary happened to build with.
pub const DEFAULT_MAX_EPOCH_RETENTION: usize = 3;

/// Sealed file-per-group implementation of `GroupStateStorage`.
///
/// Retains at most `max_epoch_retention` past-epoch records per group;
/// see the module docs for why that bound is a security property and
/// what it does not achieve.
#[derive(Clone, Debug)]
pub struct SealedGroupStore {
    store: SealedStore,
    max_epoch_retention: usize,
}

impl SealedGroupStore {
    /// A group store over `store` with the default epoch bound.
    ///
    /// Both engines (the FFI client engine and the operator's
    /// in-process agent engine) construct through here, so neither can
    /// drift from the other — SPEC-061 FR-23 is satisfied by there
    /// being one default rather than by two call sites agreeing.
    #[must_use]
    pub const fn new(store: SealedStore) -> Self {
        Self {
            store,
            max_epoch_retention: DEFAULT_MAX_EPOCH_RETENTION,
        }
    }

    /// A group store with an explicit epoch bound (SPEC-061 FR-23).
    #[must_use]
    pub const fn with_max_epoch_retention(store: SealedStore, max_epoch_retention: usize) -> Self {
        Self {
            store,
            max_epoch_retention,
        }
    }

    /// The configured retention bound.
    #[must_use]
    pub const fn max_epoch_retention(&self) -> usize {
        self.max_epoch_retention
    }

    /// The epoch ids currently retained for `group_id`, ascending.
    ///
    /// Exists so callers can tell "this epoch was deliberately
    /// trimmed" from "this message is bad" (SPEC-061 FR-22) without
    /// reaching into the record encoding.
    pub fn retained_epoch_ids(&self, group_id: &[u8]) -> Result<Vec<u64>, StorageError> {
        let Some(record) = self.load(group_id)? else {
            return Ok(Vec::new());
        };
        let mut ids: Vec<u64> = record.epochs.iter().map(|(id, _)| *id).collect();
        ids.sort_unstable();
        Ok(ids)
    }

    /// The oldest epoch id still retained for `group_id`, if any.
    pub fn oldest_retained_epoch(&self, group_id: &[u8]) -> Result<Option<u64>, StorageError> {
        Ok(self
            .load(group_id)?
            .and_then(|r| r.epochs.iter().map(|(id, _)| *id).min()))
    }

    fn load(&self, group_id: &[u8]) -> Result<Option<GroupRecord>, StorageError> {
        self.store
            .open_read("groups", GROUP_AAD_LABEL, group_id)?
            .map(|plain| GroupRecord::decode(&plain))
            .transpose()
    }
}

impl mls_rs_core::group::GroupStateStorage for SealedGroupStore {
    type Error = StorageError;

    fn state(&self, group_id: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self.load(group_id)?.map(|r| Zeroizing::new(r.state)))
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self.load(group_id)?.and_then(|r| {
            r.epochs
                .into_iter()
                .find(|(id, _)| *id == epoch_id)
                .map(|(_, data)| Zeroizing::new(data))
        }))
    }

    fn write(
        &mut self,
        state: mls_rs_core::group::GroupState,
        epoch_inserts: Vec<mls_rs_core::group::EpochRecord>,
        epoch_updates: Vec<mls_rs_core::group::EpochRecord>,
    ) -> Result<(), Self::Error> {
        let mut record = self.load(&state.id)?.unwrap_or(GroupRecord {
            state: Vec::new(),
            epochs: Vec::new(),
        });
        record.state = state.data.to_vec();
        for insert in epoch_inserts {
            record.epochs.push((insert.id, insert.data.to_vec()));
        }
        for update in epoch_updates {
            if let Some(slot) = record.epochs.iter_mut().find(|(id, _)| *id == update.id) {
                slot.1 = update.data.to_vec();
            }
        }
        // SPEC-061 FR-21 / NFR-4. Trim in the same re-seal that wrote
        // the new epoch, so there is no window in which the departed
        // epoch's secrets are on disk unbounded. The record encoding
        // is unchanged: this removes entries, it does not change how
        // they are written.
        if record.epochs.len() > self.max_epoch_retention {
            record.epochs.sort_unstable_by_key(|(id, _)| *id);
            let excess = record.epochs.len() - self.max_epoch_retention;
            record.epochs.drain(..excess);
        }
        let plaintext = Zeroizing::new(record.encode());
        self.store
            .seal_write("groups", GROUP_AAD_LABEL, &state.id, &plaintext)
    }

    fn max_epoch_id(&self, group_id: &[u8]) -> Result<Option<u64>, Self::Error> {
        Ok(self
            .load(group_id)?
            .and_then(|r| r.epochs.iter().map(|(id, _)| *id).max()))
    }
}

// ---------------------------------------------------------------------------
// Key packages
// ---------------------------------------------------------------------------

/// Sealed file-per-package implementation of `KeyPackageStorage`.
///
/// The private half (`KeyPackageData`) lives under `key_packages/`;
/// the publishable public `MlsMessage` bytes live alongside under
/// `key_packages_public/` so the host can (re)publish the pool after
/// a restart. Both are deleted together on consumption — a consumed
/// package must never be reused (RFC 9420 §12.4).
#[derive(Clone, Debug)]
pub struct SealedKeyPackageStore(pub SealedStore);

impl SealedKeyPackageStore {
    /// Persist the publishable public message for `id`.
    pub fn insert_public(&self, id: &[u8], message: &[u8]) -> Result<(), StorageError> {
        self.0.seal_write(
            "key_packages_public",
            KEY_PACKAGE_PUBLIC_AAD_LABEL,
            id,
            message,
        )
    }

    /// All stored publishable public messages (unconsumed pool).
    pub fn stored_public_messages(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        Ok(self
            .stored_public_with_ids()?
            .into_iter()
            .map(|(_, msg)| msg)
            .collect())
    }

    /// All stored publishable public messages, each paired with its
    /// storage id. The id is stable across restarts, so a host that
    /// publishes packages under it can tell which of the stored
    /// packages have already been handed out.
    pub fn stored_public_with_ids(&self) -> Result<Vec<StoredItem>, StorageError> {
        let mut out = Vec::new();
        for id in self.0.list_ids("key_packages_public")? {
            if let Some(msg) =
                self.0
                    .open_read("key_packages_public", KEY_PACKAGE_PUBLIC_AAD_LABEL, &id)?
            {
                out.push((id, msg.to_vec()));
            }
        }
        Ok(out)
    }

    /// Number of unconsumed private halves in the pool.
    pub fn pool_count(&self) -> Result<usize, StorageError> {
        Ok(self.pool_ids()?.len())
    }

    /// Ids of the unconsumed private halves in the pool.
    pub fn pool_ids(&self) -> Result<Vec<Vec<u8>>, StorageError> {
        self.0.list_ids("key_packages")
    }
}

impl mls_rs_core::key_package::KeyPackageStorage for SealedKeyPackageStore {
    type Error = StorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        self.0.delete("key_packages", id)?;
        self.0.delete("key_packages_public", id)
    }

    fn insert(&mut self, id: Vec<u8>, pkg: KeyPackageData) -> Result<(), Self::Error> {
        let plaintext = Zeroizing::new(
            pkg.mls_encode_to_vec()
                .map_err(|e| StorageError(format!("encode key package: {e}")))?,
        );
        self.0
            .seal_write("key_packages", KEY_PACKAGE_AAD_LABEL, &id, &plaintext)
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, Self::Error> {
        self.0
            .open_read("key_packages", KEY_PACKAGE_AAD_LABEL, id)?
            .map(|plain| {
                KeyPackageData::mls_decode(&mut plain.as_slice())
                    .map_err(|e| StorageError(format!("decode key package: {e}")))
            })
            .transpose()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_round_trip_and_corruption_refusal() {
        let dir = tempfile::tempdir().unwrap();
        let store = SealedStore::open(dir.path().to_str().unwrap(), &[5u8; 32]).unwrap();
        store
            .seal_write("groups", GROUP_AAD_LABEL, &[0xab, 0xcd], b"payload")
            .unwrap();
        let back = store
            .open_read("groups", GROUP_AAD_LABEL, &[0xab, 0xcd])
            .unwrap()
            .unwrap();
        assert_eq!(&back[..], b"payload");

        // Absent file: None, not an error.
        assert!(
            store
                .open_read("groups", GROUP_AAD_LABEL, &[0x00])
                .unwrap()
                .is_none()
        );

        // Flip one ciphertext byte: clean refusal.
        let path = store.path("groups", &[0xab, 0xcd]);
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, bytes).unwrap();
        let err = store
            .open_read("groups", GROUP_AAD_LABEL, &[0xab, 0xcd])
            .expect_err("corrupt file must refuse");
        assert!(err.0.contains("unseal failed"), "unexpected error: {err}");
    }

    #[test]
    fn wrong_key_refuses() {
        let dir = tempfile::tempdir().unwrap();
        let store = SealedStore::open(dir.path().to_str().unwrap(), &[5u8; 32]).unwrap();
        store
            .seal_write("groups", GROUP_AAD_LABEL, &[1], b"secret")
            .unwrap();
        let other = SealedStore::open(dir.path().to_str().unwrap(), &[6u8; 32]).unwrap();
        assert!(other.open_read("groups", GROUP_AAD_LABEL, &[1]).is_err());
    }

    #[test]
    fn aad_binds_the_item_id() {
        let dir = tempfile::tempdir().unwrap();
        let store = SealedStore::open(dir.path().to_str().unwrap(), &[5u8; 32]).unwrap();
        store
            .seal_write("groups", GROUP_AAD_LABEL, &[1], b"for group 1")
            .unwrap();
        // Copy group 1's sealed file over group 2's slot.
        std::fs::copy(store.path("groups", &[1]), store.path("groups", &[2])).unwrap();
        assert!(store.open_read("groups", GROUP_AAD_LABEL, &[2]).is_err());
    }

    #[test]
    fn group_record_round_trip() {
        let record = GroupRecord {
            state: vec![1, 2, 3],
            epochs: vec![(7, vec![9, 9]), (8, vec![])],
        };
        let back = GroupRecord::decode(&record.encode()).unwrap();
        assert_eq!(back.state, record.state);
        assert_eq!(back.epochs, record.epochs);
        assert!(GroupRecord::decode(&[]).is_err());
        assert!(GroupRecord::decode(&[2]).is_err());
    }

    /// SPEC-061 FR-21/FR-22/FR-23 at the store level, without an MLS
    /// group in the way: writes drive the record past the bound and
    /// only the highest epoch ids survive, across a reopen.
    #[test]
    fn epoch_retention_is_bounded_and_keeps_the_newest() {
        use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};

        let dir = tempfile::tempdir().unwrap();
        let group_id = vec![0xaa, 0xbb];
        let open = || {
            SealedGroupStore::with_max_epoch_retention(
                SealedStore::open(dir.path().to_str().unwrap(), &[5u8; 32]).unwrap(),
                3,
            )
        };

        let mut store = open();
        for epoch in 0..20u64 {
            store
                .write(
                    GroupState {
                        id: group_id.clone(),
                        data: Zeroizing::new(vec![u8::try_from(epoch % 256).unwrap()]),
                    },
                    vec![EpochRecord {
                        id: epoch,
                        data: Zeroizing::new(vec![u8::try_from(epoch % 256).unwrap(); 4]),
                    }],
                    Vec::new(),
                )
                .unwrap();
        }

        assert_eq!(
            store.retained_epoch_ids(&group_id).unwrap(),
            vec![17, 18, 19]
        );
        assert_eq!(store.max_epoch_id(&group_id).unwrap(), Some(19));
        assert_eq!(store.oldest_retained_epoch(&group_id).unwrap(), Some(17));
        // Trimmed epochs are unreachable, not merely uncounted.
        assert!(store.epoch(&group_id, 0).unwrap().is_none());
        assert!(store.epoch(&group_id, 16).unwrap().is_none());
        assert!(store.epoch(&group_id, 17).unwrap().is_some());

        // All of it survives a reopen: the trim is in the record, not
        // in some in-memory view of it.
        let reopened = open();
        assert_eq!(
            reopened.retained_epoch_ids(&group_id).unwrap(),
            vec![17, 18, 19]
        );
        assert!(reopened.epoch(&group_id, 0).unwrap().is_none());
        assert_eq!(reopened.max_epoch_id(&group_id).unwrap(), Some(19));

        // An update to a trimmed epoch is a no-op, not a resurrection.
        let mut reopened = reopened;
        reopened
            .write(
                GroupState {
                    id: group_id.clone(),
                    data: Zeroizing::new(vec![99]),
                },
                Vec::new(),
                vec![EpochRecord {
                    id: 0,
                    data: Zeroizing::new(vec![0xff; 4]),
                }],
            )
            .unwrap();
        assert_eq!(
            reopened.retained_epoch_ids(&group_id).unwrap(),
            vec![17, 18, 19]
        );
    }

    #[test]
    fn default_retention_matches_mls_rs() {
        let dir = tempfile::tempdir().unwrap();
        let store = SealedGroupStore::new(
            SealedStore::open(dir.path().to_str().unwrap(), &[5u8; 32]).unwrap(),
        );
        assert_eq!(store.max_epoch_retention(), DEFAULT_MAX_EPOCH_RETENTION);
        assert_eq!(DEFAULT_MAX_EPOCH_RETENTION, 3);
    }
}
