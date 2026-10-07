//! Which MLS group is which conversation.
//!
//! The scope of a conversation is `conv:{conversation_id}`, as on the
//! phone. A message is filed by the group it decrypted under — MLS
//! authenticates that — and this map turns the group back into the
//! conversation; the operator's own assertion is trusted only for a
//! Welcome, which carries no group id.
//!
//! [`Directory::record`] is first-write-wins: a second group for a
//! conversation that already has one is refused, because two devices
//! founding two groups for one conversation is how a third device goes
//! deaf. [`Directory::record_replacing`] is the deliberate exception, for
//! a rejoin, where the old group is the one that stopped working.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};

use crate::sealed::SealedFile;

const FILE: &str = "directory.sealed";
const LABEL: &[u8] = b"airdress-mls-client directory v1";

/// The scope string for a conversation.
#[must_use]
pub fn scope_of(conversation_id: &str) -> String {
    format!("conv:{conversation_id}")
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct Doc {
    /// scope → base64 group id
    groups: BTreeMap<String, String>,
    /// base64 group id → scope
    scopes: BTreeMap<String, String>,
}

/// The conversation ↔ group map, sealed under the host's state key.
pub struct Directory {
    file: SealedFile,
    doc: Doc,
}

impl core::fmt::Debug for Directory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Sealed content and the key it is sealed under stay out of logs.
        f.debug_struct("Directory").finish_non_exhaustive()
    }
}

impl Directory {
    /// Open (or start) the directory in `dir`.
    ///
    /// # Errors
    ///
    /// The file exists and does not open under `state_key`, or is not a
    /// directory document. Never silently empty.
    pub fn open(dir: &Path, state_key: &[u8; 32]) -> Result<Self, String> {
        let file = SealedFile::new(dir.join(FILE), state_key, LABEL);
        let doc = match file.read()? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("the directory is not readable: {e}"))?,
            None => Doc::default(),
        };
        Ok(Self { file, doc })
    }

    /// The group recorded for a conversation.
    #[must_use]
    pub fn group_for(&self, conversation_id: &str) -> Option<Vec<u8>> {
        self.doc
            .groups
            .get(&scope_of(conversation_id))
            .and_then(|g| STANDARD.decode(g).ok())
    }

    /// The conversation a group belongs to.
    #[must_use]
    pub fn conversation_for(&self, group_id: &[u8]) -> Option<String> {
        self.doc
            .scopes
            .get(&STANDARD.encode(group_id))
            .and_then(|s| s.strip_prefix("conv:"))
            .map(str::to_owned)
    }

    /// Every conversation that has a group.
    #[must_use]
    pub fn conversations(&self) -> Vec<String> {
        self.doc
            .groups
            .keys()
            .filter_map(|s| s.strip_prefix("conv:"))
            .map(str::to_owned)
            .collect()
    }

    /// Record a group for a conversation, first write wins. Returns
    /// whether it was recorded: `false` when the conversation already
    /// has a different group or the group already belongs elsewhere
    /// (recording the same pair again is `true`).
    ///
    /// # Errors
    ///
    /// The sealed file could not be written.
    pub fn record(&mut self, conversation_id: &str, group_id: &[u8]) -> Result<bool, String> {
        let scope = scope_of(conversation_id);
        let gid = STANDARD.encode(group_id);
        match (self.doc.groups.get(&scope), self.doc.scopes.get(&gid)) {
            (Some(g), Some(s)) if *g == gid && *s == scope => return Ok(true),
            (None, None) => {}
            _ => return Ok(false),
        }
        self.doc.groups.insert(scope.clone(), gid.clone());
        self.doc.scopes.insert(gid, scope);
        self.save()?;
        Ok(true)
    }

    /// Record a group for a conversation, replacing whatever it had.
    /// For a rejoin: the old group is forgotten in both directions.
    ///
    /// # Errors
    ///
    /// The sealed file could not be written.
    pub fn record_replacing(
        &mut self,
        conversation_id: &str,
        group_id: &[u8],
    ) -> Result<(), String> {
        let scope = scope_of(conversation_id);
        let gid = STANDARD.encode(group_id);
        if let Some(old) = self.doc.groups.remove(&scope) {
            self.doc.scopes.remove(&old);
        }
        if let Some(old_scope) = self.doc.scopes.remove(&gid) {
            self.doc.groups.remove(&old_scope);
        }
        self.doc.groups.insert(scope.clone(), gid.clone());
        self.doc.scopes.insert(gid, scope);
        self.save()
    }

    /// Forget a conversation's group (this device was removed from it).
    ///
    /// # Errors
    ///
    /// The sealed file could not be written.
    pub fn forget(&mut self, conversation_id: &str) -> Result<(), String> {
        if let Some(old) = self.doc.groups.remove(&scope_of(conversation_id)) {
            self.doc.scopes.remove(&old);
            self.save()?;
        }
        Ok(())
    }

    fn save(&self) -> Result<(), String> {
        let bytes = serde_json::to_vec(&self.doc).map_err(|e| e.to_string())?;
        self.file.write(&bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_write_wins_and_survives_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let key = [7u8; 32];
        let mut d = Directory::open(dir.path(), &key).unwrap();
        assert!(d.record("c1", b"g1").unwrap());
        assert!(
            d.record("c1", b"g1").unwrap(),
            "the same pair again is fine"
        );
        assert!(!d.record("c1", b"g2").unwrap(), "a second group is refused");
        assert!(
            !d.record("c2", b"g1").unwrap(),
            "a group belongs to one conversation"
        );
        let d = Directory::open(dir.path(), &key).unwrap();
        assert_eq!(d.group_for("c1").unwrap(), b"g1");
        assert_eq!(d.conversation_for(b"g1").unwrap(), "c1");
        assert_eq!(d.conversations(), vec!["c1".to_owned()]);
    }

    #[test]
    fn replacing_forgets_the_old_group_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Directory::open(dir.path(), &[1u8; 32]).unwrap();
        d.record("c1", b"old").unwrap();
        d.record_replacing("c1", b"new").unwrap();
        assert_eq!(d.group_for("c1").unwrap(), b"new");
        assert!(d.conversation_for(b"old").is_none());
        d.forget("c1").unwrap();
        assert!(d.group_for("c1").is_none());
    }

    #[test]
    fn a_wrong_key_is_an_error_not_an_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Directory::open(dir.path(), &[1u8; 32]).unwrap();
        d.record("c1", b"g").unwrap();
        assert!(Directory::open(dir.path(), &[2u8; 32]).is_err());
    }
}
