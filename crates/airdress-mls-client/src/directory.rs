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
//!
//! Every change is written before it takes effect: the next document is
//! built, sealed to disk, and only then becomes the one in memory, so a
//! failed write changes nothing and the envelope behind it can be
//! replayed against the state it first met.

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

/// How many envelopes [`Directory::defer`] keeps a count for. Past it the
/// oldest count is dropped: an envelope the operator stopped replaying
/// leaves its count behind, and the list must not grow without limit.
const MAX_DEFERRED: usize = 256;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Deferred {
    envelope_id: String,
    attempts: u32,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Doc {
    /// scope → base64 group id
    groups: BTreeMap<String, String>,
    /// base64 group id → scope
    scopes: BTreeMap<String, String>,
    /// base64 group id → scope, for a group a rejoin superseded: its late
    /// application messages still belong to the conversation it was, but
    /// it is no longer the conversation's group.
    #[serde(default)]
    retired: BTreeMap<String, String>,
    /// Envelopes left for a replay because their group was not joined
    /// yet, with how often, oldest first.
    #[serde(default)]
    deferred: Vec<Deferred>,
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

    /// The conversation a message in `group_id` belongs to: the group's
    /// current conversation, or the one it belonged to before a rejoin
    /// superseded it. Never the envelope's word.
    pub fn conversation_of_message(&self, group_id: &[u8]) -> Option<String> {
        let gid = STANDARD.encode(group_id);
        self.doc
            .scopes
            .get(&gid)
            .or_else(|| self.doc.retired.get(&gid))
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
        let mut next = self.doc.clone();
        next.groups.insert(scope.clone(), gid.clone());
        next.scopes.insert(gid, scope);
        self.commit(next)?;
        Ok(true)
    }

    /// Record a group for a conversation, replacing whatever it had.
    /// For a rejoin: the old group stops being the conversation's group,
    /// and its late messages are still attributed to the conversation
    /// ([`Self::conversation_of_message`]). Returns `false`, and changes
    /// nothing, when the group is another conversation's.
    ///
    /// # Errors
    ///
    /// The sealed file could not be written.
    pub fn record_replacing(
        &mut self,
        conversation_id: &str,
        group_id: &[u8],
    ) -> Result<bool, String> {
        let scope = scope_of(conversation_id);
        let gid = STANDARD.encode(group_id);
        // One group speaks for one conversation: never take another's.
        if self.doc.scopes.get(&gid).is_some_and(|s| *s != scope) {
            return Ok(false);
        }
        let mut next = self.doc.clone();
        if let Some(old) = next.groups.remove(&scope) {
            next.scopes.remove(&old);
            if old != gid {
                next.retired.insert(old, scope.clone());
            }
        }
        next.retired.remove(&gid);
        next.groups.insert(scope.clone(), gid.clone());
        next.scopes.insert(gid, scope);
        self.commit(next)?;
        Ok(true)
    }

    /// Forget a conversation's group (this device was removed from it).
    ///
    /// # Errors
    ///
    /// The sealed file could not be written.
    pub fn forget(&mut self, conversation_id: &str) -> Result<(), String> {
        let scope = scope_of(conversation_id);
        let mut next = self.doc.clone();
        next.retired.retain(|_, s| *s != scope);
        let had = next.groups.remove(&scope);
        if let Some(old) = &had {
            next.scopes.remove(old);
        }
        if had.is_some() || next.retired.len() != self.doc.retired.len() {
            self.commit(next)?;
        }
        Ok(())
    }

    /// Count one more delivery of an envelope left for a replay, and
    /// return the count including this one.
    ///
    /// # Errors
    ///
    /// The sealed file could not be written; nothing was counted.
    pub(crate) fn defer(&mut self, envelope_id: &str) -> Result<u32, String> {
        let mut next = self.doc.clone();
        let attempts = if let Some(d) = next
            .deferred
            .iter_mut()
            .find(|d| d.envelope_id == envelope_id)
        {
            d.attempts = d.attempts.saturating_add(1);
            d.attempts
        } else {
            next.deferred.push(Deferred {
                envelope_id: envelope_id.to_owned(),
                attempts: 1,
            });
            if next.deferred.len() > MAX_DEFERRED {
                next.deferred.remove(0);
            }
            1
        };
        self.commit(next)?;
        Ok(attempts)
    }

    /// Drop the count of an envelope that is no longer left for a
    /// replay. Writes only when there was one. Returns whether no count
    /// remains; a count that could not be dropped is harmless, and is
    /// pruned with the oldest ([`MAX_DEFERRED`]).
    pub(crate) fn settle(&mut self, envelope_id: &str) -> bool {
        if !self
            .doc
            .deferred
            .iter()
            .any(|d| d.envelope_id == envelope_id)
        {
            return true;
        }
        let mut next = self.doc.clone();
        next.deferred.retain(|d| d.envelope_id != envelope_id);
        self.commit(next).is_ok()
    }

    /// Write `next`, then make it the document: a failed write leaves
    /// memory as it was, in step with the disk.
    fn commit(&mut self, next: Doc) -> Result<(), String> {
        let bytes = serde_json::to_vec(&next).map_err(|e| e.to_string())?;
        self.file.write(&bytes)?;
        self.doc = next;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Make every write to `path` fail until the guard is dropped: a
    /// directory stands where the file is renamed to. The file that was
    /// there, if any, is put back afterwards.
    struct Unwritable {
        path: std::path::PathBuf,
        aside: std::path::PathBuf,
    }

    impl Unwritable {
        fn at(path: std::path::PathBuf) -> Self {
            let aside = path.with_extension("aside");
            if path.exists() {
                std::fs::rename(&path, &aside).unwrap();
            }
            std::fs::create_dir(&path).unwrap();
            std::fs::write(path.join("occupied"), b"").unwrap();
            Self { path, aside }
        }
    }

    impl Drop for Unwritable {
        fn drop(&mut self) {
            std::fs::remove_dir_all(&self.path).unwrap();
            if self.aside.exists() {
                std::fs::rename(&self.aside, &self.path).unwrap();
            }
        }
    }

    #[test]
    fn a_failed_save_leaves_the_directory_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let key = [5u8; 32];
        let mut d = Directory::open(dir.path(), &key).unwrap();
        d.record("c1", b"g1").unwrap();
        {
            let _blocked = Unwritable::at(dir.path().join(FILE));
            assert!(d.record("c2", b"g2").is_err());
            assert!(d.group_for("c2").is_none());
            assert!(d.conversation_for(b"g2").is_none());
            assert!(d.record_replacing("c1", b"g3").is_err());
            assert_eq!(d.group_for("c1").unwrap(), b"g1");
            assert!(d.conversation_of_message(b"g3").is_none());
            assert!(d.forget("c1").is_err());
            assert_eq!(d.group_for("c1").unwrap(), b"g1");
            assert!(d.defer("e1").is_err());
        }
        // Memory and disk agree, and the same changes go through once
        // the disk takes them.
        let reopened = Directory::open(dir.path(), &key).unwrap();
        assert_eq!(reopened.conversations(), d.conversations());
        assert_eq!(d.defer("e1").unwrap(), 1, "the failed count was not kept");
        assert!(d.record("c2", b"g2").unwrap());
        d.forget("c1").unwrap();
        let reopened = Directory::open(dir.path(), &key).unwrap();
        assert_eq!(reopened.conversations(), vec!["c2".to_owned()]);
    }

    #[test]
    fn deferral_counts_are_bounded_and_settled() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Directory::open(dir.path(), &[6u8; 32]).unwrap();
        assert_eq!(d.defer("e1").unwrap(), 1);
        assert_eq!(d.defer("e1").unwrap(), 2);
        let mut d = Directory::open(dir.path(), &[6u8; 32]).unwrap();
        assert_eq!(d.defer("e1").unwrap(), 3, "counts survive a reopen");
        assert!(d.settle("e1"));
        assert_eq!(d.defer("e1").unwrap(), 1);
        for i in 0..MAX_DEFERRED {
            d.defer(&format!("x{i}")).unwrap();
        }
        assert_eq!(d.doc.deferred.len(), MAX_DEFERRED);
        assert_eq!(d.defer("e1").unwrap(), 1, "the oldest count was dropped");
    }

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
        assert!(d.record_replacing("c1", b"new").unwrap());
        assert_eq!(d.group_for("c1").unwrap(), b"new");
        assert!(d.conversation_for(b"old").is_none());
        // The superseded group's late messages still belong to c1, and to
        // nothing else; it survives a reopen.
        let mut d = Directory::open(dir.path(), &[1u8; 32]).unwrap();
        assert_eq!(d.conversation_of_message(b"old").as_deref(), Some("c1"));
        assert_eq!(d.conversation_of_message(b"new").as_deref(), Some("c1"));
        d.forget("c1").unwrap();
        assert!(d.group_for("c1").is_none());
        assert!(d.conversation_of_message(b"old").is_none());
        assert!(d.conversation_of_message(b"new").is_none());
    }

    #[test]
    fn replacing_never_takes_another_conversations_group() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Directory::open(dir.path(), &[1u8; 32]).unwrap();
        d.record("c1", b"g1").unwrap();
        d.record("c2", b"g2").unwrap();
        assert!(!d.record_replacing("c1", b"g2").unwrap());
        assert_eq!(d.group_for("c1").unwrap(), b"g1");
        assert_eq!(d.group_for("c2").unwrap(), b"g2");
        assert_eq!(d.conversation_of_message(b"g1").as_deref(), Some("c1"));
    }

    #[test]
    fn a_wrong_key_is_an_error_not_an_empty_directory() {
        let dir = tempfile::tempdir().unwrap();
        let mut d = Directory::open(dir.path(), &[1u8; 32]).unwrap();
        d.record("c1", b"g").unwrap();
        assert!(Directory::open(dir.path(), &[2u8; 32]).is_err());
    }
}
