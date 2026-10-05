//! One small sealed JSON file: ChaCha20-Poly1305 under a host key,
//! written to a temporary file and renamed into place.
//!
//! The layout is `nonce (12) ‖ ciphertext`, and the AEAD's associated
//! data names what the file is, so a directory file renamed over a pin
//! file fails to open rather than parsing as the wrong thing.

use std::io::Write as _;
use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

const NONCE_LEN: usize = 12;

/// A sealed file at one path, under one key, for one purpose.
pub(crate) struct SealedFile {
    path: PathBuf,
    key: [u8; 32],
    label: &'static [u8],
}

impl SealedFile {
    pub(crate) fn new(path: PathBuf, key: &[u8; 32], label: &'static [u8]) -> Self {
        Self {
            path,
            key: *key,
            label,
        }
    }

    /// The plaintext, or `None` when the file does not exist yet.
    ///
    /// A file that exists and does not open is an error, never an empty
    /// value: starting over from nothing would forget every group.
    pub(crate) fn read(&self) -> Result<Option<Vec<u8>>, String> {
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", self.path.display())),
        };
        if bytes.len() < NONCE_LEN {
            return Err(format!("{} is truncated", self.path.display()));
        }
        let (nonce, body) = bytes.split_at(NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: body,
                    aad: self.label,
                },
            )
            .map(Some)
            .map_err(|_| {
                format!(
                    "{} does not open under this key: refusing to start over from nothing",
                    self.path.display()
                )
            })
    }

    /// Seal and write, atomically: a crash leaves the old file or the
    /// new one, never half of either.
    pub(crate) fn write(&self, plaintext: &[u8]) -> Result<(), String> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key));
        let body = cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: plaintext,
                    aad: self.label,
                },
            )
            .map_err(|_| "sealing failed".to_owned())?;
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        std::fs::create_dir_all(dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        let tmp = self.path.with_extension("partial");
        {
            let mut f = open_private(&tmp)?;
            f.write_all(&nonce)
                .and_then(|()| f.write_all(&body))
                .and_then(|()| f.sync_all())
                .map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
        }
        std::fs::rename(&tmp, &self.path)
            .map_err(|e| format!("cannot replace {}: {e}", self.path.display()))
    }
}

#[cfg(unix)]
fn open_private(path: &Path) -> Result<std::fs::File, String> {
    use std::os::unix::fs::OpenOptionsExt as _;
    std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("cannot create {}: {e}", path.display()))
}

#[cfg(not(unix))]
fn open_private(path: &Path) -> Result<std::fs::File, String> {
    std::fs::File::create(path).map_err(|e| format!("cannot create {}: {e}", path.display()))
}
