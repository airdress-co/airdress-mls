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
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

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
        // Writing into a String cannot fail.
        write!(out, "{b:02x}").expect("formatting into a String is infallible");
    }
    out
}

/// The shared sealed-file primitive both stores are built on.
#[derive(Clone)]
pub struct SealedStore {
    root: Arc<Path>,
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
            // A write interrupted by a crash leaves its temp file, and
            // each one holds a whole sealed item; nothing ever reads one.
            remove_interrupted_writes(&root.join(sub), None)
                .map_err(|e| StorageError(format!("clean {sub} dir: {e}")))?;
        }
        Ok(Self {
            root: Arc::from(root),
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
    #[expect(
        clippy::map_err_ignore,
        reason = "an AEAD failure is opaque by design, and a short read's error is the slice; the closed message says what happened"
    )]
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

        write_file_atomically(&self.path(sub, id), &[&nonce, &ciphertext])
            .map_err(|e| StorageError(format!("write sealed file: {e}")))
    }

    /// Read and unseal `<sub>/<hex id>`. `Ok(None)` when absent; an
    /// AEAD failure (tampering, wrong key, copied file) is an error
    /// that refuses the item — never a silent re-key.
    #[expect(
        clippy::map_err_ignore,
        reason = "an AEAD failure is opaque by design, and a short read's error is the slice; the closed message says what happened"
    )]
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

/// What a temp file's name carries after the target's name.
const TMP_MARKER: &str = ".tmp-";

/// Write `parts`, concatenated, to `path` so that a crash leaves either
/// the old file or the new one, never half of either.
///
/// The bytes go to a temp file beside `path` (`<name>.tmp-<pid>-<n>`,
/// mode 0600 on Unix), which is fsynced and renamed into place; then the
/// directory is fsynced so the rename itself is durable. On any error
/// the temp file is removed, so a failed write leaves nothing behind.
/// A temp file left by a process that died mid-write is removed by
/// [`remove_interrupted_writes`].
///
/// # Errors
///
/// Creating, writing, syncing or renaming the temp file failed.
pub fn write_file_atomically(path: &Path, parts: &[&[u8]]) -> std::io::Result<()> {
    let name = path
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| std::io::Error::other("target path has no UTF-8 file name"))?;
    let tmp_path = path.with_file_name(format!(
        "{name}{TMP_MARKER}{}-{}",
        std::process::id(),
        next_tmp_ordinal()
    ));
    // Not ours to remove if creating it fails.
    let mut file = create_private(&tmp_path)?;
    let written = (|| {
        for part in parts {
            file.write_all(part)?;
        }
        file.sync_all()?;
        drop(file);
        std::fs::rename(&tmp_path, path)
    })();
    if let Err(e) = written {
        // Best effort: the error being returned is the one that matters,
        // and a temp file that cannot be removed now is removed at the
        // next open.
        std::fs::remove_file(&tmp_path).ok();
        return Err(e);
    }
    // Best-effort directory fsync so the rename itself is durable; a
    // filesystem without directory fsync is not an error here.
    if let Ok(dir) = std::fs::File::open(path.parent().unwrap_or_else(|| Path::new("."))) {
        dir.sync_all().ok();
    }
    Ok(())
}

/// Remove the temp files [`write_file_atomically`] leaves in `dir` when
/// a process dies mid-write: every `*.tmp-*` file, or with `file_name`
/// only those of that one target (`<file_name>.tmp-*`). Returns how many
/// were removed. Run it when a store opens, before anything writes.
///
/// # Errors
///
/// `dir` cannot be listed, or a temp file in it cannot be removed.
pub fn remove_interrupted_writes(dir: &Path, file_name: Option<&str>) -> std::io::Result<usize> {
    let entries = match std::fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut removed = 0;
    for entry in entries {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let is_temp = match file_name {
            Some(target) => name
                .strip_prefix(target)
                .is_some_and(|rest| rest.starts_with(TMP_MARKER)),
            None => name.contains(TMP_MARKER),
        };
        if is_temp && entry.file_type()?.is_file() {
            match std::fs::remove_file(entry.path()) {
                Ok(()) => removed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(removed)
}

#[cfg(unix)]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
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

///
/// Both halves are group secrets — the state holds the current epoch's
/// key schedule and each epoch record a past one's — so the decoded
/// record wipes itself when dropped (rust guide R-TYP-8), and so does
/// each epoch entry trimmed out of it.
#[derive(Zeroize, ZeroizeOnDrop)]
struct GroupRecord {
    state: Vec<u8>,
    epochs: Vec<EpochEntry>,
}

/// One past epoch's record: its id and its secret bytes.
#[derive(Debug, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
struct EpochEntry {
    id: u64,
    data: Vec<u8>,
}

impl GroupRecord {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.push(GROUP_RECORD_VERSION);
        out.extend_from_slice(&u32::try_from(self.state.len()).unwrap_or(0).to_le_bytes());
        out.extend_from_slice(&self.state);
        out.extend_from_slice(&u32::try_from(self.epochs.len()).unwrap_or(0).to_le_bytes());
        for EpochEntry { id, data } in &self.epochs {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&u32::try_from(data.len()).unwrap_or(0).to_le_bytes());
            out.extend_from_slice(data);
        }
        out
    }

    #[expect(
        clippy::map_err_ignore,
        reason = "try_into on a length-checked slice cannot fail, and its error is the slice; the closed message says what happened"
    )]
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
        // The count is read from the record, so it only bounds the loop:
        // every entry takes at least 12 bytes, and reserving for more than
        // the bytes left could hold is an allocation the input chose (the
        // group-record fuzz target found a 110 GB one).
        let mut epochs = Vec::with_capacity((count as usize).min(cursor.len() / 12));
        for _ in 0..count {
            let id = u64::from_le_bytes(take(&mut cursor, 8)?.try_into().map_err(|_| err())?);
            let len = u32::from_le_bytes(take(&mut cursor, 4)?.try_into().map_err(|_| err())?);
            epochs.push(EpochEntry {
                id,
                data: take(&mut cursor, len as usize)?,
            });
        }
        // `encode` never writes past the last epoch, so bytes after it
        // are not a record this code wrote (found by the fuzz target).
        if !cursor.is_empty() {
            return Err(StorageError("group record has trailing bytes".to_owned()));
        }
        Ok(Self { state, epochs })
    }
}

/// The group-record decoder's fuzz entry (`fuzz/`): whatever decodes
/// re-encodes to exactly the input.
#[cfg(fuzzing)]
pub(crate) fn fuzz_group_record(bytes: &[u8]) {
    if let Ok(record) = GroupRecord::decode(bytes) {
        assert_eq!(
            record.encode(),
            bytes,
            "a decoded record re-encodes to its input"
        );
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
        let mut ids: Vec<u64> = record.epochs.iter().map(|e| e.id).collect();
        ids.sort_unstable();
        Ok(ids)
    }

    /// The oldest epoch id still retained for `group_id`, if any.
    pub fn oldest_retained_epoch(&self, group_id: &[u8]) -> Result<Option<u64>, StorageError> {
        Ok(self
            .load(group_id)?
            .and_then(|r| r.epochs.iter().map(|e| e.id).min()))
    }

    /// Delete `group_id`'s record: its state and every past epoch.
    ///
    /// What joining a group does first. `write` merges into the record
    /// it finds, which is right for a member moving through epochs and
    /// wrong for a join: a device removed and later added back to the
    /// same group id would otherwise keep the epochs of its earlier
    /// membership, both on disk and in `max_epoch_id`, where `mls-rs`
    /// reads the next epoch it expects to insert.
    pub(crate) fn delete_group(&self, group_id: &[u8]) -> Result<(), StorageError> {
        self.store.delete("groups", group_id)
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
        Ok(self
            .load(group_id)?
            .map(|mut r| Zeroizing::new(std::mem::take(&mut r.state))))
    }

    fn epoch(
        &self,
        group_id: &[u8],
        epoch_id: u64,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        Ok(self.load(group_id)?.and_then(|mut r| {
            r.epochs
                .iter_mut()
                .find(|e| e.id == epoch_id)
                .map(|e| Zeroizing::new(std::mem::take(&mut e.data)))
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
        record.state.zeroize();
        record.state = state.data.to_vec();
        for insert in epoch_inserts {
            record.epochs.push(EpochEntry {
                id: insert.id,
                data: insert.data.to_vec(),
            });
        }
        for update in epoch_updates {
            if let Some(slot) = record.epochs.iter_mut().find(|e| e.id == update.id) {
                slot.data.zeroize();
                slot.data = update.data.to_vec();
            }
        }
        // SPEC-061 FR-21 / NFR-4. Trim in the same re-seal that wrote
        // the new epoch, so there is no window in which the departed
        // epoch's secrets are on disk unbounded. The record encoding
        // is unchanged: this removes entries, it does not change how
        // they are written.
        if record.epochs.len() > self.max_epoch_retention {
            record.epochs.sort_unstable_by_key(|e| e.id);
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
            .and_then(|r| r.epochs.iter().map(|e| e.id).max()))
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
    ///
    /// Only packages whose private half is still stored are returned: a
    /// public half without one belongs to a package already consumed.
    pub fn stored_public_with_ids(&self) -> Result<Vec<StoredItem>, StorageError> {
        let mut out = Vec::new();
        let private: std::collections::HashSet<Vec<u8>> =
            self.0.list_ids("key_packages")?.into_iter().collect();
        for id in self.0.list_ids("key_packages_public")? {
            if !private.contains(&id) {
                continue;
            }
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

    /// The public half goes first. A crash between the two deletes then
    /// leaves a private half nobody is offered, rather than a public
    /// half the host would publish again for a package already used.
    fn delete(&mut self, id: &[u8]) -> Result<(), Self::Error> {
        self.0.delete("key_packages_public", id)?;
        self.0.delete("key_packages", id)
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

    fn names_in(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn a_failed_write_leaves_no_temp_file() {
        let dir = tempfile::tempdir().unwrap();
        let store = SealedStore::open(dir.path().to_str().unwrap(), &[5u8; 32]).unwrap();
        // A directory where the item belongs: the rename into place fails
        // after the temp file was written in full.
        std::fs::create_dir(store.path("groups", &[0xab])).unwrap();
        store
            .seal_write("groups", GROUP_AAD_LABEL, &[0xab], b"payload")
            .expect_err("the rename onto a directory fails");
        assert_eq!(names_in(&dir.path().join("groups")), vec!["ab".to_owned()]);
    }

    #[test]
    fn open_removes_temp_files_left_by_interrupted_writes() {
        let dir = tempfile::tempdir().unwrap();
        let store = SealedStore::open(dir.path().to_str().unwrap(), &[5u8; 32]).unwrap();
        store
            .seal_write("groups", GROUP_AAD_LABEL, &[0xab], b"payload")
            .unwrap();
        for sub in ["groups", "key_packages", "key_packages_public"] {
            std::fs::write(dir.path().join(sub).join("cd.tmp-4242-7"), b"sealed").unwrap();
        }
        let reopened = SealedStore::open(dir.path().to_str().unwrap(), &[5u8; 32]).unwrap();
        assert_eq!(names_in(&dir.path().join("groups")), vec!["ab".to_owned()]);
        assert!(names_in(&dir.path().join("key_packages")).is_empty());
        assert!(names_in(&dir.path().join("key_packages_public")).is_empty());
        assert_eq!(
            &reopened
                .open_read("groups", GROUP_AAD_LABEL, &[0xab])
                .unwrap()
                .unwrap()[..],
            b"payload"
        );
    }

    #[test]
    fn only_the_named_targets_temp_files_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        for name in ["pins.sealed.tmp-1-0", "other.sealed.tmp-1-0", "pins.sealed"] {
            std::fs::write(dir.path().join(name), b"x").unwrap();
        }
        assert_eq!(
            remove_interrupted_writes(dir.path(), Some("pins.sealed")).unwrap(),
            1
        );
        assert_eq!(
            names_in(dir.path()),
            vec!["other.sealed.tmp-1-0".to_owned(), "pins.sealed".to_owned()]
        );
    }

    #[test]
    fn a_consumed_key_package_loses_its_public_half_first() {
        use mls_rs_core::key_package::KeyPackageStorage as _;
        let dir = tempfile::tempdir().unwrap();
        let sealed = SealedStore::open(dir.path().to_str().unwrap(), &[5u8; 32]).unwrap();
        let mut store = SealedKeyPackageStore(sealed.clone());
        sealed
            .seal_write("key_packages", KEY_PACKAGE_AAD_LABEL, &[0x01], b"private")
            .unwrap();
        // The public half cannot be deleted (a directory stands in its
        // place), so the delete stops after its first step.
        std::fs::create_dir(sealed.path("key_packages_public", &[0x01])).unwrap();
        std::fs::write(sealed.path("key_packages_public", &[0x01]).join("x"), b"x").unwrap();
        store
            .delete(&[0x01])
            .expect_err("the public half is not deletable");
        assert_eq!(
            store.pool_ids().unwrap(),
            vec![vec![0x01]],
            "the private half stays until the public half is gone"
        );
    }

    #[test]
    fn a_public_half_without_its_private_half_is_not_offered() {
        let dir = tempfile::tempdir().unwrap();
        let sealed = SealedStore::open(dir.path().to_str().unwrap(), &[5u8; 32]).unwrap();
        let store = SealedKeyPackageStore(sealed.clone());
        for id in [[0x01u8], [0x02]] {
            sealed
                .seal_write("key_packages", KEY_PACKAGE_AAD_LABEL, &id, b"private")
                .unwrap();
            store.insert_public(&id, &[id[0]; 4]).unwrap();
        }
        // What an interrupted delete of 0x01 left behind.
        sealed.delete("key_packages", &[0x01]).unwrap();
        assert_eq!(
            store.stored_public_with_ids().unwrap(),
            vec![(vec![0x02], vec![0x02; 4])]
        );
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
            epochs: vec![
                EpochEntry {
                    id: 7,
                    data: vec![9, 9],
                },
                EpochEntry {
                    id: 8,
                    data: vec![],
                },
            ],
        };
        let back = GroupRecord::decode(&record.encode()).unwrap();
        assert_eq!(back.state, record.state);
        assert_eq!(back.epochs, record.epochs);
        assert!(GroupRecord::decode(&[]).is_err());
        // A huge epoch count with nothing behind it is truncated, not an
        // attempt to allocate for it.
        let mut lying = vec![GROUP_RECORD_VERSION, 0, 0, 0, 0];
        lying.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(GroupRecord::decode(&lying).is_err());
        let mut trailing = record.encode();
        trailing.push(0);
        assert!(GroupRecord::decode(&trailing).is_err());
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
