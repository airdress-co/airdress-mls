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

use std::collections::BTreeMap;
use std::path::Path;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};

use crate::sealed::SealedFile;

const FILE: &str = "root-pins.sealed";
const LABEL: &[u8] = b"airdress-mls-client root pins v1";

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

#[derive(Debug, Default, Serialize, Deserialize)]
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

    /// Every change recorded, oldest first.
    #[must_use]
    pub fn changes(&self) -> &[PinChange] {
        &self.doc.changes
    }

    /// Observe `root` for `airdress` at `now`.
    ///
    /// # Errors
    ///
    /// The store could not be written.
    pub fn observe(
        &mut self,
        airdress: &str,
        root: &[u8; 32],
        now: &str,
    ) -> Result<PinObservation, String> {
        let outcome = match self.doc.pins.get_mut(airdress) {
            None => {
                self.doc.pins.insert(
                    airdress.to_owned(),
                    Pin {
                        root: enc(root),
                        pinned_at: now.to_owned(),
                        last_seen: now.to_owned(),
                    },
                );
                PinObservation::Pinned
            }
            Some(pin) => {
                let pinned = dec(&pin.root).ok_or("a stored pin is malformed")?;
                if pinned == *root {
                    pin.last_seen = now.to_owned();
                    PinObservation::Matched
                } else {
                    let already = self.doc.changes.iter().any(|c| {
                        c.airdress == airdress && c.pinned == pin.root && c.observed == enc(root)
                    });
                    if !already {
                        self.doc.changes.push(PinChange {
                            airdress: airdress.to_owned(),
                            pinned: pin.root.clone(),
                            observed: enc(root),
                            at: now.to_owned(),
                        });
                    }
                    PinObservation::Changed {
                        pinned,
                        observed: *root,
                    }
                }
            }
        };
        self.save()?;
        Ok(outcome)
    }

    /// Pin a key a person verified another way, replacing any pin.
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
        self.doc.pins.insert(
            airdress.to_owned(),
            Pin {
                root: enc(root),
                pinned_at: now.to_owned(),
                last_seen: now.to_owned(),
            },
        );
        self.save()
    }

    /// Adopt the most recent observed change for `airdress`, which a
    /// person has looked at and accepted. Returns whether there was one.
    ///
    /// # Errors
    ///
    /// The store could not be written.
    pub fn acknowledge(&mut self, airdress: &str, now: &str) -> Result<bool, String> {
        let Some(latest) = self
            .doc
            .changes
            .iter()
            .rev()
            .find(|c| c.airdress == airdress)
            .cloned()
        else {
            return Ok(false);
        };
        let root = dec(&latest.observed).ok_or("a recorded change is malformed")?;
        self.pin_out_of_band(airdress, &root, now)?;
        Ok(true)
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
        assert!(s.acknowledge("a.example", "t5").unwrap());
        assert_eq!(s.pinned("a.example"), Some([2; 32]));
        assert!(!s.acknowledge("b.example", "t5").unwrap());
    }
}
