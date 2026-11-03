//! One small sealed JSON file: ChaCha20-Poly1305 under a host key,
//! written to a temporary file and renamed into place, with the same
//! helper and the same fsyncs as the engine's own sealed store.
//!
//! The layout is `nonce (12) ‖ ciphertext`, and the AEAD's associated
//! data names what the file is, so a directory file renamed over a pin
//! file fails to open rather than parsing as the wrong thing.

use std::path::{Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 12;

/// A sealed file at one path, under one key, for one purpose.
///
/// Holds a copy of the host's state key, wiped when the file handle is
/// dropped (rust guide R-TYP-8).
pub(crate) struct SealedFile {
    path: PathBuf,
    key: Zeroizing<[u8; 32]>,
    label: &'static [u8],
}

impl SealedFile {
    pub(crate) fn new(path: PathBuf, key: &[u8; 32], label: &'static [u8]) -> Self {
        Self {
            path,
            key: Zeroizing::new(*key),
            label,
        }
    }

    /// The plaintext, or `None` when the file does not exist yet.
    ///
    /// A file that exists and does not open is an error, never an empty
    /// value: starting over from nothing would forget every group.
    #[expect(
        clippy::map_err_ignore,
        reason = "an AEAD failure is opaque by design; the message says what happened"
    )]
    pub(crate) fn read(&self) -> Result<Option<Vec<u8>>, String> {
        self.remove_interrupted_writes()?;
        let bytes = match std::fs::read(&self.path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(format!("cannot read {}: {e}", self.path.display())),
        };
        if bytes.len() < NONCE_LEN {
            return Err(format!("{} is truncated", self.path.display()));
        }
        let (nonce, body) = bytes.split_at(NONCE_LEN);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.key.as_slice()));
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
    #[expect(
        clippy::map_err_ignore,
        reason = "an AEAD failure is opaque by design; the message says what happened"
    )]
    pub(crate) fn write(&self, plaintext: &[u8]) -> Result<(), String> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRng.fill_bytes(&mut nonce);
        let cipher = ChaCha20Poly1305::new(Key::from_slice(self.key.as_slice()));
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
        airdress_mls::storage::write_file_atomically(&self.path, &[&nonce, &body])
            .map_err(|e| format!("cannot replace {}: {e}", self.path.display()))
    }

    /// Remove what an interrupted write of this file left beside it: the
    /// temp files of [`airdress_mls::storage::write_file_atomically`], and
    /// the single `.partial` file earlier versions wrote. Each is a whole
    /// sealed copy that nothing reads.
    fn remove_interrupted_writes(&self) -> Result<(), String> {
        let dir = self.path.parent().unwrap_or_else(|| Path::new("."));
        let Some(name) = self.path.file_name().and_then(|n| n.to_str()) else {
            return Ok(());
        };
        airdress_mls::storage::remove_interrupted_writes(dir, Some(name))
            .map_err(|e| format!("cannot clean {}: {e}", dir.display()))?;
        match std::fs::remove_file(self.path.with_extension("partial")) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(format!("cannot clean {}: {e}", dir.display())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::SealedFile;

    fn names_in(dir: &std::path::Path) -> Vec<String> {
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
        let path = dir.path().join("pins.sealed");
        // A directory where the file belongs: the rename into place
        // fails after the temp file was written in full.
        std::fs::create_dir(&path).unwrap();
        let file = SealedFile::new(path, &[7u8; 32], b"test");
        file.write(b"{}")
            .expect_err("the rename onto a directory fails");
        assert_eq!(names_in(dir.path()), vec!["pins.sealed".to_owned()]);
    }

    #[test]
    fn opening_removes_what_an_interrupted_write_left() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pins.sealed");
        let file = SealedFile::new(path, &[7u8; 32], b"test");
        file.write(b"{\"a\":1}").unwrap();
        for leftover in [
            "pins.sealed.tmp-4242-0",
            "pins.partial",
            "other.sealed.tmp-1-0",
        ] {
            std::fs::write(dir.path().join(leftover), b"sealed").unwrap();
        }
        assert_eq!(file.read().unwrap().unwrap(), b"{\"a\":1}");
        assert_eq!(
            names_in(dir.path()),
            vec!["other.sealed.tmp-1-0".to_owned(), "pins.sealed".to_owned()],
            "only this file's leftovers are removed"
        );
    }
}
