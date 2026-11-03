//! Trust-on-first-use pins of peers' root keys.
//!
//! The first root key seen for an airdress is pinned. A later, different
//! one is recorded as a change and **not** adopted: the pinned key stays
//! the one a credential must chain to, so a substituted root fails closed
//! until a person acknowledges the change ([`PinStore::acknowledge`]) or
//! pins out of band ([`PinStore::pin_out_of_band`]). Same rules as the
//! phone's store, so both refuse the same things.
//!
//! Times are the caller's (RFC 3339 strings): this crate keeps no clock.
//!
//! A change is written before it takes effect, so a failed write leaves
//! the store as it was. A plain match writes nothing: the pin's
//! `last_seen` moves in memory and reaches the disk with the next write
//! that changes something else. The history keeps the newest
//! [`MAX_CHANGES_PER_PIN`] changes recorded against each pinned key.
//!
//! Pins are keyed by **pin subject**
//! ([`airdress_mls::credential::AirdressIdentity::pin_subject`]), which is
//! the bare airdress for an owner's root — so every pin written before
//! `v: 3` credentials existed is already under the right key — and
//! `airdress ‖ 0x1F ‖ person_id` for another person of that airdress.
//! The `airdress` arguments below accept either form.

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::sealed::SealedFile;

const FILE: &str = "root-pins.sealed";
const LABEL: &[u8] = b"airdress-mls-client root pins v1";

/// How many recorded changes are kept per pinned key of an airdress. A
/// new one past it drops the oldest for that key: whoever presents root
/// keys must not be able to grow the store without limit.
pub const MAX_CHANGES_PER_PIN: usize = 16;

/// What observing a root key did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinObservation {
    /// Nothing was pinned; this key now is.
    Pinned,
    /// It is the pinned key.
    Matched,
    /// It is not the pinned key. The pin stands; the change is recorded.
    Changed {
        /// The key that stays pinned.
        pinned: [u8; 32],
        /// The key that was observed.
        observed: [u8; 32],
    },
}

/// One recorded change, for a person to look at.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PinChange {
    /// Whose root.
    pub airdress: String,
    /// The pinned key, base64url.
    pub pinned: String,
    /// The key observed instead, base64url.
    pub observed: String,
    /// When (the caller's time).
    pub at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Pin {
    root: String,
    pinned_at: String,
    last_seen: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Doc {
    pins: BTreeMap<String, Pin>,
    changes: Vec<PinChange>,
}

/// The pin store, sealed under the host's state key.
pub struct PinStore {
    file: SealedFile,
    doc: Doc,
}

fn enc(k: &[u8; 32]) -> String {
    URL_SAFE_NO_PAD.encode(k)
}

fn dec(s: &str) -> Option<[u8; 32]> {
    URL_SAFE_NO_PAD.decode(s).ok()?.try_into().ok()
}

impl core::fmt::Debug for PinStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Sealed content and the key it is sealed under stay out of logs.
        f.debug_struct("PinStore").finish_non_exhaustive()
    }
}

impl PinStore {
    /// Open (or start) the store in `dir`.
    ///
    /// # Errors
    ///
    /// The file exists and does not open, or is not a pin document.
    pub fn open(dir: &Path, state_key: &[u8; 32]) -> Result<Self, String> {
        let file = SealedFile::new(dir.join(FILE), state_key, LABEL);
        let doc = match file.read()? {
            Some(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| format!("the pin store is not readable: {e}"))?,
            None => Doc::default(),
        };
        Ok(Self { file, doc })
    }

    /// The pinned root of an airdress.
    #[must_use]
    pub fn pinned(&self, airdress: &str) -> Option<[u8; 32]> {
        self.doc.pins.get(airdress).and_then(|p| dec(&p.root))
    }

    /// Every change recorded, oldest first: the history, kept as
    /// evidence, including changes accepted or superseded since.
    #[must_use]
    pub fn changes(&self) -> &[PinChange] {
        &self.doc.changes
    }

    /// The changes a person can still act on: recorded against the
    /// airdress's current pin. What a review screen offers to accept.
    #[must_use]
    pub fn pending_changes(&self) -> Vec<&PinChange> {
        self.doc
            .changes
            .iter()
            .filter(|c| {
                self.doc
                    .pins
                    .get(&c.airdress)
                    .is_some_and(|p| p.root == c.pinned)
            })
            .collect()
    }

    /// Observe `root` for `airdress` at `now`.
    ///
    /// A first key is pinned and a new change recorded, each written
    /// before it is answered; a match writes nothing.
    ///
    /// # Errors
    ///
    /// The store could not be written; nothing changed.
    pub fn observe(
        &mut self,
        airdress: &str,
        root: &[u8; 32],
        now: &str,
    ) -> Result<PinObservation, String> {
        let Some(pin) = self.doc.pins.get_mut(airdress) else {
            let mut next = self.doc.clone();
            next.pins.insert(
                airdress.to_owned(),
                Pin {
                    root: enc(root),
                    pinned_at: now.to_owned(),
                    last_seen: now.to_owned(),
                },
            );
            self.commit(next)?;
            return Ok(PinObservation::Pinned);
        };
        let pinned = dec(&pin.root).ok_or("a stored pin is malformed")?;
        if pinned == *root {
            now.clone_into(&mut pin.last_seen);
            return Ok(PinObservation::Matched);
        }
        let current = pin.root.clone();
        let observed = enc(root);
        let already = self
            .doc
            .changes
            .iter()
            .any(|c| c.airdress == airdress && c.pinned == current && c.observed == observed);
        if !already {
            let mut next = self.doc.clone();
            let same_pin = |c: &PinChange| c.airdress == airdress && c.pinned == current;
            if next.changes.iter().filter(|c| same_pin(c)).count() >= MAX_CHANGES_PER_PIN
                && let Some(oldest) = next.changes.iter().position(same_pin)
            {
                next.changes.remove(oldest);
            }
            next.changes.push(PinChange {
                airdress: airdress.to_owned(),
                pinned: current,
                observed,
                at: now.to_owned(),
            });
            self.commit(next)?;
        }
        Ok(PinObservation::Changed {
            pinned,
            observed: *root,
        })
    }

    /// Pin a key a person verified another way, replacing any pin.
    ///
    /// Recorded changes are kept as evidence; none recorded against an
    /// earlier pin can be adopted over this one ([`Self::acknowledge`]).
    /// Written before it takes effect: a failed write changes nothing.
    ///
    /// # Errors
    ///
    /// The store could not be written.
    pub fn pin_out_of_band(
        &mut self,
        airdress: &str,
        root: &[u8; 32],
        now: &str,
    ) -> Result<(), String> {
        let mut next = self.doc.clone();
        next.pins.insert(
            airdress.to_owned(),
            Pin {
                root: enc(root),
                pinned_at: now.to_owned(),
                last_seen: now.to_owned(),
            },
        );
        self.commit(next)
    }

    /// Adopt `observed` for `airdress`: the key a person was shown as a
    /// change and accepted. Adopted only if a change from the current pin
    /// to exactly that key was recorded, so a key that arrived while the
    /// person was looking, or a change a later pin already resolved, is
    /// never what "accept" pins. Returns whether it was adopted.
    ///
    /// # Errors
    ///
    /// The store could not be written.
    pub fn acknowledge(
        &mut self,
        airdress: &str,
        observed: &[u8; 32],
        now: &str,
    ) -> Result<bool, String> {
        let Some(current) = self.doc.pins.get(airdress).map(|p| p.root.clone()) else {
            return Ok(false);
        };
        let wanted = enc(observed);
        let recorded = self
            .doc
            .changes
            .iter()
            .any(|c| c.airdress == airdress && c.pinned == current && c.observed == wanted);
        if !recorded {
            return Ok(false);
        }
        // The accepted change and any other key seen in the meantime stay
        // in the history; neither is pending once the pin has moved.
        self.pin_out_of_band(airdress, observed, now)?;
        Ok(true)
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
    fn a_failed_save_leaves_the_pins_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let key = [4u8; 32];
        let mut s = PinStore::open(dir.path(), &key).unwrap();
        s.observe("b.example", &[9; 32], "t0").unwrap();
        {
            let _blocked = Unwritable::at(dir.path().join(FILE));
            assert!(s.observe("a.example", &[1; 32], "t1").is_err());
            assert_eq!(s.pinned("a.example"), None, "an unsaved pin is no pin");
            assert!(s.observe("b.example", &[8; 32], "t2").is_err());
            assert!(s.changes().is_empty(), "an unsaved change is no change");
        }
        assert_eq!(
            s.observe("a.example", &[1; 32], "t3").unwrap(),
            PinObservation::Pinned
        );
        s.observe("b.example", &[8; 32], "t4").unwrap();
        let s = PinStore::open(dir.path(), &key).unwrap();
        assert_eq!(s.pinned("a.example"), Some([1; 32]));
        assert_eq!(s.changes().len(), 1);
    }

    #[test]
    fn a_plain_match_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = PinStore::open(dir.path(), &[4u8; 32]).unwrap();
        s.observe("a.example", &[1; 32], "t1").unwrap();
        let _blocked = Unwritable::at(dir.path().join(FILE));
        assert_eq!(
            s.observe("a.example", &[1; 32], "t2").unwrap(),
            PinObservation::Matched
        );
        assert_eq!(s.doc.pins["a.example"].last_seen, "t2");
    }

    #[test]
    fn the_history_keeps_the_newest_changes_per_pin() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = PinStore::open(dir.path(), &[4u8; 32]).unwrap();
        s.observe("a.example", &[0; 32], "t").unwrap();
        s.observe("b.example", &[0; 32], "t").unwrap();
        s.observe("b.example", &[200; 32], "t").unwrap();
        let extra = u8::try_from(MAX_CHANGES_PER_PIN).unwrap() + 24;
        for n in 1..=extra {
            s.observe("a.example", &[n; 32], &format!("t{n}")).unwrap();
        }
        let of_a = |s: &PinStore| {
            s.changes()
                .iter()
                .filter(|c| c.airdress == "a.example")
                .count()
        };
        assert_eq!(of_a(&s), MAX_CHANGES_PER_PIN);
        assert_eq!(s.changes().len(), MAX_CHANGES_PER_PIN + 1, "b's stays");
        assert_eq!(s.pending_changes().len(), MAX_CHANGES_PER_PIN + 1);
        // The oldest went; the newest can still be accepted.
        assert!(!s.acknowledge("a.example", &[1; 32], "t").unwrap());
        assert!(s.acknowledge("a.example", &[extra; 32], "t").unwrap());
        let s = PinStore::open(dir.path(), &[4u8; 32]).unwrap();
        assert_eq!(of_a(&s), MAX_CHANGES_PER_PIN);
        assert_eq!(s.pinned("a.example"), Some([extra; 32]));
    }

    #[test]
    fn accepting_one_change_keeps_the_history_and_leaves_nothing_pending() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = PinStore::open(dir.path(), &[3u8; 32]).unwrap();
        s.observe("a.example", &[1; 32], "t1").unwrap();
        s.observe("a.example", &[2; 32], "t2").unwrap();
        s.observe("a.example", &[3; 32], "t3").unwrap();
        assert_eq!(s.pending_changes().len(), 2);
        assert!(s.acknowledge("a.example", &[2; 32], "t4").unwrap());
        assert_eq!(s.pinned("a.example"), Some([2; 32]));
        // Both observations stay as evidence; neither can be accepted now.
        assert_eq!(s.changes().len(), 2);
        assert!(s.pending_changes().is_empty());
        assert!(!s.acknowledge("a.example", &[3; 32], "t5").unwrap());
        assert_eq!(s.pinned("a.example"), Some([2; 32]));
    }

    #[test]
    fn first_use_pins_and_a_change_fails_closed_until_acknowledged() {
        let dir = tempfile::tempdir().unwrap();
        let key = [3u8; 32];
        let mut s = PinStore::open(dir.path(), &key).unwrap();
        assert_eq!(
            s.observe("a.example", &[1; 32], "t1").unwrap(),
            PinObservation::Pinned
        );
        assert_eq!(
            s.observe("a.example", &[1; 32], "t2").unwrap(),
            PinObservation::Matched
        );
        assert_eq!(
            s.observe("a.example", &[2; 32], "t3").unwrap(),
            PinObservation::Changed {
                pinned: [1; 32],
                observed: [2; 32]
            }
        );
        s.observe("a.example", &[2; 32], "t4").unwrap();
        assert_eq!(s.changes().len(), 1, "one change, however often it is seen");
        assert_eq!(s.pinned("a.example"), Some([1; 32]), "the pin stands");

        let mut s = PinStore::open(dir.path(), &key).unwrap();
        assert!(s.acknowledge("a.example", &[2; 32], "t5").unwrap());
        assert_eq!(s.pinned("a.example"), Some([2; 32]));
        assert!(!s.acknowledge("b.example", &[2; 32], "t5").unwrap());
    }
}
