//! The envelope pump's decisions, and building what goes back out.
//!
//! [`Client::process`] takes one received envelope and says what it did
//! and whether to acknowledge it. The rule for the acknowledgement is the
//! phone's: acknowledge once the effect is durable (a joined group, a
//! decrypted message the host has stored, an applied commit) or once it
//! is clear that retrying can never succeed; do not acknowledge what
//! might succeed later — the operator replays unacknowledged envelopes
//! on the next connection.
//!
//! The host must store a [`Event::Message`] before it acknowledges it:
//! decryption ratchets the group forward, so the same ciphertext will not
//! decrypt a second time.

use std::path::Path;

use airdress_mls::{EngineError, MlsEngine};

use crate::directory::Directory;
use crate::wire::{
    EnvelopeKind, InboundEnvelope, LanePayload, OutboundEnvelope, commit_group_tag,
    message_group_id,
};

/// One decrypted chat message.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    /// The operator's id for the envelope that carried it.
    pub envelope_id: String,
    /// The conversation it belongs to — by the group it decrypted under.
    pub conversation_id: String,
    /// That group.
    pub group_id: Vec<u8>,
    /// Who sent it (bound into the ciphertext; a re-attributed message
    /// does not decrypt).
    pub from_airdress: String,
    /// `agent`, `sibling`, or `None` for a device's own words.
    pub origin: Option<String>,
    /// The chat blocks, uninterpreted.
    pub blocks: serde_json::Value,
    /// When the operator accepted it, as it said.
    pub received_at: Option<String>,
}

/// What one envelope did.
#[derive(Debug, Clone, PartialEq)]
pub enum Event {
    /// A Welcome: this device is now a member of the group.
    Joined {
        /// The conversation the Welcome was sent for.
        conversation_id: String,
        /// The group joined.
        group_id: Vec<u8>,
    },
    /// An application message, decrypted.
    Message(Message),
    /// A commit changed the group; this device is still in it.
    Membership {
        /// The conversation.
        conversation_id: String,
        /// The group.
        group_id: Vec<u8>,
        /// Its epoch after the commit.
        epoch: u64,
        /// Member identities that joined.
        added: Vec<Vec<u8>>,
        /// Member identities that left.
        removed: Vec<Vec<u8>>,
    },
    /// A commit removed this device. Nothing sent to the group from now
    /// on is readable here; the directory has forgotten the group.
    Removed {
        /// The conversation it was removed from.
        conversation_id: String,
    },
    /// The device is behind a group it should be in and cannot catch up
    /// on its own: the host posts a rejoin request for the conversation.
    RejoinNeeded {
        /// The conversation.
        conversation_id: String,
        /// Why, in one sentence.
        reason: String,
    },
    /// Nothing to do: an older commit, a trimmed epoch, a kind this
    /// device does not handle. Acknowledged.
    Ignored {
        /// Why.
        reason: String,
    },
    /// It failed. `retryable` says whether a later attempt could succeed
    /// (an application for a group whose Welcome has not arrived yet),
    /// which is also why such an envelope is not acknowledged.
    Failed {
        /// Why.
        reason: String,
        /// Whether to leave it for a replay.
        retryable: bool,
    },
}

/// The outcome of [`Client::process`].
#[derive(Debug, Clone, PartialEq)]
pub struct Processed {
    /// Acknowledge the envelope (after storing a message).
    pub ack: bool,
    /// What happened.
    pub event: Event,
}

impl Processed {
    const fn ack(event: Event) -> Self {
        Self { ack: true, event }
    }
}

/// Why something could not be sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SendError {
    /// The conversation has no group on this device yet: establish one
    /// ([`Client::establish`]) or wait for a Welcome.
    NoGroup,
    /// [`Client::establish`] on a conversation that already has a group.
    AlreadyEstablished,
    /// The engine refused.
    Engine(String),
    /// The directory could not be written.
    Storage(String),
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoGroup => f.write_str("this conversation has no group on this device yet"),
            Self::AlreadyEstablished => f.write_str("this conversation already has a group"),
            Self::Engine(e) => write!(f, "the MLS engine refused: {e}"),
            Self::Storage(e) => write!(f, "the directory could not be written: {e}"),
        }
    }
}

impl std::error::Error for SendError {}

/// A commit built and held, waiting for the operator's answer.
///
/// Post `commit` first. On `202`, call [`Client::confirm_commit`] and then
/// post `welcome` if there is one; on `409 epoch_conflict` (or any
/// failure) call [`Client::abort_commit`] and rebuild from a fresh read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreparedCommit {
    /// The `mls_commit` envelope (with `commit_from_epoch` and
    /// `commit_group` set).
    pub commit: OutboundEnvelope,
    /// The `mls_welcome` for added members, if any.
    pub welcome: Option<OutboundEnvelope>,
    /// The epoch the group will be at once confirmed.
    pub epoch_after: u64,
}

/// One device's client: an engine, and the directory beside it.
pub struct Client {
    engine: MlsEngine,
    directory: Directory,
}

impl Client {
    /// Wrap an engine; open the directory in `state_dir` under the same
    /// key the engine's state is sealed with.
    ///
    /// # Errors
    ///
    /// The directory exists and does not open.
    pub fn open(engine: MlsEngine, state_dir: &Path, state_key: &[u8; 32]) -> Result<Self, String> {
        Ok(Self {
            engine,
            directory: Directory::open(state_dir, state_key)?,
        })
    }

    /// The engine, for what this crate does not wrap (root-key lookups,
    /// the cutover, group rosters).
    #[must_use]
    pub const fn engine(&self) -> &MlsEngine {
        &self.engine
    }

    /// See [`Client::engine`].
    pub const fn engine_mut(&mut self) -> &mut MlsEngine {
        &mut self.engine
    }

    /// The conversation ↔ group directory.
    #[must_use]
    pub const fn directory(&self) -> &Directory {
        &self.directory
    }

    /// Fresh key packages to publish (`POST /v1/chat/key-packages`).
    ///
    /// # Errors
    ///
    /// The engine could not generate or store them.
    pub fn key_packages(&self, count: usize) -> Result<Vec<Vec<u8>>, String> {
        self.engine.generate_key_packages(count)
    }

    /// Handle one received envelope.
    pub fn process(&mut self, env: &InboundEnvelope) -> Processed {
        match EnvelopeKind::parse(&env.envelope_kind) {
            Some(EnvelopeKind::Welcome) => self.process_welcome(env),
            Some(EnvelopeKind::Application) => self.process_application(env),
            Some(EnvelopeKind::Commit) => self.process_commit(env),
            // A sibling asking back in is answered by a device that can
            // commit for the owner; an audio burst is not chat. Neither
            // will mean more on a replay.
            Some(EnvelopeKind::RejoinRequest | EnvelopeKind::AudioBurst) => {
                Processed::ack(Event::Ignored {
                    reason: format!("{} is not handled by this client", env.envelope_kind),
                })
            }
            None => Processed::ack(Event::Ignored {
                reason: format!("unknown envelope kind {}", env.envelope_kind),
            }),
        }
    }

    fn process_welcome(&mut self, env: &InboundEnvelope) -> Processed {
        match self.engine.process_welcome(&env.ciphertext) {
            Ok(group_id) => {
                // A Welcome is filed by the conversation it was sent for:
                // it carries no group id to file it by. If the
                // conversation already had a group, this Welcome is the
                // one that re-seats this device (a rejoin answered), and
                // it replaces the old one.
                let result = if self.directory.group_for(&env.conversation_id).is_some() {
                    self.directory
                        .record_replacing(&env.conversation_id, &group_id)
                } else {
                    self.directory
                        .record(&env.conversation_id, &group_id)
                        .map(|_| ())
                };
                match result {
                    Ok(()) => Processed::ack(Event::Joined {
                        conversation_id: env.conversation_id.clone(),
                        group_id,
                    }),
                    Err(e) => Processed {
                        ack: false,
                        event: Event::Failed {
                            reason: e,
                            retryable: true,
                        },
                    },
                }
            }
            // A Welcome this device cannot join (its key package is gone,
            // or it was meant for another leaf) will not become joinable.
            Err(e) => Processed::ack(Event::Failed {
                reason: format!("cannot join from this Welcome: {e}"),
                retryable: false,
            }),
        }
    }

    fn conversation_of(&self, env: &InboundEnvelope, group_id: &[u8]) -> String {
        self.directory
            .conversation_for(group_id)
            .unwrap_or_else(|| env.conversation_id.clone())
    }

    fn process_application(&mut self, env: &InboundEnvelope) -> Processed {
        let Some(group_id) = message_group_id(&env.ciphertext) else {
            return Processed::ack(Event::Failed {
                reason: "the message carries no group id".to_owned(),
                retryable: false,
            });
        };
        if self.engine.group_epoch(&group_id).is_none() {
            // Most likely its Welcome is still on the way; leave it for
            // the replay rather than lose it.
            return Processed {
                ack: false,
                event: Event::Failed {
                    reason: "a message for a group this device has not joined".to_owned(),
                    retryable: true,
                },
            };
        }
        let conversation_id = self.conversation_of(env, &group_id);
        match self
            .engine
            .decrypt(&group_id, &env.ciphertext, &env.from_airdress)
        {
            Ok(plaintext) => match LanePayload::decode(&plaintext) {
                Ok(payload) => Processed::ack(Event::Message(Message {
                    envelope_id: env.envelope_id.clone(),
                    conversation_id,
                    group_id,
                    from_airdress: env.from_airdress.clone(),
                    origin: payload.origin,
                    blocks: payload.blocks,
                    received_at: env.received_at.clone(),
                })),
                Err(e) => Processed::ack(Event::Failed {
                    reason: format!("decrypted, but not a chat payload: {e}"),
                    retryable: false,
                }),
            },
            Err(EngineError::EpochUnavailable { .. }) => Processed::ack(Event::Ignored {
                reason: "this message is older than the keys still on this device".to_owned(),
            }),
            Err(EngineError::Other(e)) => Processed::ack(Event::Failed {
                reason: e,
                retryable: false,
            }),
        }
    }

    fn process_commit(&mut self, env: &InboundEnvelope) -> Processed {
        let Some(group_id) = message_group_id(&env.ciphertext) else {
            return Processed::ack(Event::Failed {
                reason: "the commit carries no group id".to_owned(),
                retryable: false,
            });
        };
        let Some(current) = self.engine.group_epoch(&group_id) else {
            return Processed {
                ack: false,
                event: Event::Failed {
                    reason: "a commit for a group this device has not joined".to_owned(),
                    retryable: true,
                },
            };
        };
        let conversation_id = self.conversation_of(env, &group_id);
        // Built from an epoch this device has passed: a commit that lost
        // the race, or one already applied. Nothing to do.
        if let Some(from) = env.commit_from_epoch
            && u64::try_from(from).is_ok_and(|f| f < current)
        {
            return Processed::ack(Event::Ignored {
                reason: format!("a commit from epoch {from}; the group is at {current}"),
            });
        }
        match self.engine.process_commit(&group_id, &env.ciphertext) {
            Ok(outcome) if outcome.self_removed => {
                if let Err(e) = self.directory.forget(&conversation_id) {
                    return Processed {
                        ack: false,
                        event: Event::Failed {
                            reason: e,
                            retryable: true,
                        },
                    };
                }
                Processed::ack(Event::Removed { conversation_id })
            }
            Ok(outcome) => Processed::ack(Event::Membership {
                conversation_id,
                group_id,
                epoch: outcome.epoch,
                added: outcome.added,
                removed: outcome.removed,
            }),
            Err(EngineError::EpochUnavailable { .. }) => Processed::ack(Event::Ignored {
                reason: "a commit older than the keys still on this device".to_owned(),
            }),
            // A commit this device should be able to apply and cannot:
            // it has fallen behind, and only a re-add brings it back.
            Err(EngineError::Other(e)) => Processed::ack(Event::RejoinNeeded {
                conversation_id,
                reason: e,
            }),
        }
    }

    /// Encrypt `payload` (a chat payload's bytes, e.g. from
    /// [`LanePayload::encode_device`]) into the conversation's group.
    ///
    /// # Errors
    ///
    /// [`SendError::NoGroup`] when the conversation has none on this
    /// device; [`SendError::Engine`] when the engine refuses.
    pub fn encrypt(
        &mut self,
        conversation_id: &str,
        payload: &[u8],
        from_airdress: &str,
    ) -> Result<OutboundEnvelope, SendError> {
        let group_id = self
            .directory
            .group_for(conversation_id)
            .ok_or(SendError::NoGroup)?;
        let ciphertext = self
            .engine
            .encrypt(&group_id, payload, from_airdress)
            .map_err(SendError::Engine)?;
        Ok(OutboundEnvelope::new(
            conversation_id,
            EnvelopeKind::Application,
            ciphertext,
        ))
    }

    /// Found the conversation's group with one peer (its key package),
    /// with `payload` as the first message. Returns the Welcome and then
    /// the application message, to be posted in that order.
    ///
    /// # Errors
    ///
    /// [`SendError::AlreadyEstablished`] if the conversation has a group;
    /// [`SendError::Engine`] or [`SendError::Storage`] otherwise.
    pub fn establish(
        &mut self,
        conversation_id: &str,
        target_airdress: &str,
        peer_key_package: &[u8],
        payload: &[u8],
        from_airdress: &str,
    ) -> Result<Vec<OutboundEnvelope>, SendError> {
        if self.directory.group_for(conversation_id).is_some() {
            return Err(SendError::AlreadyEstablished);
        }
        let outcome = self
            .engine
            .start_group(peer_key_package, payload, from_airdress)
            .map_err(SendError::Engine)?;
        let recorded = self
            .directory
            .record(conversation_id, &outcome.group_id)
            .map_err(SendError::Storage)?;
        if !recorded {
            return Err(SendError::AlreadyEstablished);
        }
        let mut welcome =
            OutboundEnvelope::new(conversation_id, EnvelopeKind::Welcome, outcome.welcome);
        welcome.target_airdress = Some(target_airdress.to_owned());
        let mut first = OutboundEnvelope::new(
            conversation_id,
            EnvelopeKind::Application,
            outcome.first_application,
        );
        first.target_airdress = Some(target_airdress.to_owned());
        Ok(vec![welcome, first])
    }

    /// Build a commit adding these members (their key packages), held
    /// until [`Client::confirm_commit`] or [`Client::abort_commit`].
    ///
    /// # Errors
    ///
    /// No group, or the engine refuses a package or the commit.
    pub fn prepare_add(
        &mut self,
        conversation_id: &str,
        key_packages: &[Vec<u8>],
    ) -> Result<PreparedCommit, SendError> {
        let group_id = self
            .directory
            .group_for(conversation_id)
            .ok_or(SendError::NoGroup)?;
        for kp in key_packages {
            self.engine
                .propose_add(&group_id, kp)
                .map_err(SendError::Engine)?;
        }
        self.prepare(conversation_id, &group_id)
    }

    /// Build a commit removing the members with these identities
    /// (`airdress ‖ 0x1F ‖ device_id`), held like [`Client::prepare_add`].
    ///
    /// # Errors
    ///
    /// No group, an identity that is not a member, or the engine refuses.
    pub fn prepare_remove(
        &mut self,
        conversation_id: &str,
        identities: &[Vec<u8>],
    ) -> Result<PreparedCommit, SendError> {
        let group_id = self
            .directory
            .group_for(conversation_id)
            .ok_or(SendError::NoGroup)?;
        let members = self
            .engine
            .group_members(&group_id)
            .map_err(SendError::Engine)?;
        for identity in identities {
            let member = members
                .iter()
                .find(|m| &m.identity == identity)
                .ok_or_else(|| SendError::Engine("no such member in this group".to_owned()))?;
            self.engine
                .propose_remove(&group_id, member.index)
                .map_err(SendError::Engine)?;
        }
        self.prepare(conversation_id, &group_id)
    }

    fn prepare(
        &mut self,
        conversation_id: &str,
        group_id: &[u8],
    ) -> Result<PreparedCommit, SendError> {
        let from = self
            .engine
            .group_epoch(group_id)
            .ok_or(SendError::NoGroup)?;
        let outcome = self
            .engine
            .commit_pending(group_id)
            .map_err(SendError::Engine)?;
        let mut commit =
            OutboundEnvelope::new(conversation_id, EnvelopeKind::Commit, outcome.commit);
        commit.commit_from_epoch =
            Some(i64::try_from(from).map_err(|e| SendError::Engine(e.to_string()))?);
        commit.commit_group = Some(commit_group_tag(group_id));
        let welcome = outcome
            .welcome
            .map(|w| OutboundEnvelope::new(conversation_id, EnvelopeKind::Welcome, w));
        Ok(PreparedCommit {
            commit,
            welcome,
            epoch_after: outcome.epoch,
        })
    }

    /// The operator accepted the held commit: persist it.
    ///
    /// # Errors
    ///
    /// No group or no held commit.
    pub fn confirm_commit(&mut self, conversation_id: &str) -> Result<u64, SendError> {
        let group_id = self
            .directory
            .group_for(conversation_id)
            .ok_or(SendError::NoGroup)?;
        self.engine
            .confirm_commit(&group_id)
            .map_err(SendError::Engine)
    }

    /// The operator refused the held commit: drop it.
    ///
    /// # Errors
    ///
    /// No group or no held commit.
    pub fn abort_commit(&mut self, conversation_id: &str) -> Result<u64, SendError> {
        let group_id = self
            .directory
            .group_for(conversation_id)
            .ok_or(SendError::NoGroup)?;
        self.engine
            .abort_commit(&group_id)
            .map_err(SendError::Engine)
    }
}
