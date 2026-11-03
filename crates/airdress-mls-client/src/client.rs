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
//!
//! The engine's state and the directory are two files, and the engine
//! writes first. A removal replays cleanly: the engine stays at the
//! epoch it was removed from, so the replayed commit removes it again and
//! the directory forgets then. A join does not: the Welcome's key package
//! is spent. When the directory write after a join fails, the client
//! keeps the join in memory and files it when the Welcome, or a message
//! for that group, comes back. That memory does not survive a restart: a
//! Welcome replayed after one finds its key package spent and asks to
//! rejoin, the existing way back for a Welcome this device cannot use.
//!
//! An application or commit for a group this device has not joined is
//! left for a replay, since its Welcome may still be on the way, but only
//! [`MAX_DEFERRALS`] times, counted in the directory: after that it is
//! acknowledged as failed, so one whose Welcome never comes is not
//! replayed on every connection for good.
//!
//! An envelope whose effect the engine could not write (a full disk, an
//! I/O error: [`EngineError::Storage`]) is left for a replay, whatever
//! its kind: nothing of it was kept, so the same envelope succeeds once
//! storage does. A commit refused because it removes a device this
//! device does not yet hold revoked ([`EngineError::RevocationViewStale`])
//! is left for a replay too, so the host can refresh its revocation
//! state first; after [`MAX_DEFERRALS`] deliveries the device stays
//! behind and asks to rejoin.

use std::path::Path;

use airdress_mls::engine::message_group_id;
use airdress_mls::{EngineError, MlsEngine};
use sha2::{Digest as _, Sha256};

use crate::directory::Directory;
use crate::wire::{
    EnvelopeKind, InboundEnvelope, LanePayload, OutboundEnvelope, ReplyTo, commit_group_tag,
};

/// How many deliveries of an application or commit for a group this
/// device has not joined are left for a replay before it is
/// acknowledged as failed.
pub const MAX_DEFERRALS: u32 = 8;

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
    /// The message's own reference, as its sender minted it; `None` from
    /// an old client. With `from_airdress` and the conversation it is the
    /// key a reply names this message by.
    pub r#ref: Option<String>,
    /// What this message replies to, when it is a reply.
    pub reply_to: Option<ReplyTo>,
    /// When the operator accepted it, as it said.
    pub received_at: Option<String>,
}

/// What one envelope did.
#[derive(Debug, Clone, PartialEq)]
#[allow(
    clippy::large_enum_variant,
    reason = "one Event per envelope, consumed at once; boxing Message would change every consumer's match for no measurable gain"
)]
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

/// The engine could not write its state: nothing of the envelope was
/// kept, so it is left for a replay.
const fn storage_failed(reason: String) -> Processed {
    Processed {
        ack: false,
        event: Event::Failed {
            reason,
            retryable: true,
        },
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
    /// The directory, or the engine's state, could not be written.
    Storage(String),
}

impl core::fmt::Display for SendError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NoGroup => f.write_str("this conversation has no group on this device yet"),
            Self::AlreadyEstablished => f.write_str("this conversation already has a group"),
            Self::Engine(e) => write!(f, "the MLS engine refused: {e}"),
            Self::Storage(e) => write!(f, "this device's state could not be written: {e}"),
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

/// A join the engine made whose directory entry could not be written.
struct UnfiledJoin {
    /// SHA-256 of the Welcome, so its replay is recognised.
    welcome: [u8; 32],
    conversation_id: String,
    group_id: Vec<u8>,
}

/// One device's client: an engine, and the directory beside it.
pub struct Client {
    engine: MlsEngine,
    directory: Directory,
    unfiled_joins: Vec<UnfiledJoin>,
}

impl core::fmt::Debug for Client {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Sealed content and the key it is sealed under stay out of logs.
        f.debug_struct("Client").finish_non_exhaustive()
    }
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
            unfiled_joins: Vec::new(),
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
        let digest: [u8; 32] = Sha256::digest(&env.ciphertext).into();
        // The replay of a Welcome this device joined from and could not
        // file: its key package is spent, so file what the join gave.
        if let Some(unfiled) = self
            .unfiled_joins
            .iter()
            .find(|u| u.welcome == digest && u.conversation_id == env.conversation_id)
        {
            let group_id = unfiled.group_id.clone();
            return self.file_join(env, digest, group_id);
        }
        match self.engine.process_welcome(&env.ciphertext) {
            Ok(group_id) => self.file_join(env, digest, group_id),
            // A Welcome that names a key package this device does not hold,
            // for a conversation it has no group in, means it was never
            // added: the publisher's pool handed out a package this engine
            // cannot open. Waiting changes nothing, so ask to be added
            // again (SPEC-166 166-I.8); before, the Welcome was dropped and
            // the conversation stayed unreadable for good.
            Err(EngineError::Other(e))
                if e == airdress_mls::engine::WELCOME_KEY_PACKAGE_NOT_FOUND
                    && self.directory.group_for(&env.conversation_id).is_none() =>
            {
                Processed::ack(Event::RejoinNeeded {
                    conversation_id: env.conversation_id.clone(),
                    reason: format!("cannot join from this Welcome: {e}"),
                })
            }
            // The join could not be written: its key package is still
            // held, so the same Welcome joins once storage takes it.
            Err(EngineError::Storage(e)) => storage_failed(e),
            // Any other Welcome this device cannot join (malformed, or one
            // for a conversation it already holds) will not become joinable.
            Err(e) => Processed::ack(Event::Failed {
                reason: format!("cannot join from this Welcome: {e}"),
                retryable: false,
            }),
        }
    }

    /// File a group the engine joined from the Welcome in `env`. A failed
    /// write keeps the join in memory for the replay and leaves the
    /// Welcome unacknowledged.
    fn file_join(
        &mut self,
        env: &InboundEnvelope,
        digest: [u8; 32],
        group_id: Vec<u8>,
    ) -> Processed {
        let result = self.file_group(&env.conversation_id, &group_id);
        let event = match result {
            Ok(true) => Event::Joined {
                conversation_id: env.conversation_id.clone(),
                group_id,
            },
            // The group is already another conversation's: filing it
            // under this one too would let one group speak for two.
            Ok(false) => Event::Failed {
                reason: "this Welcome is for a group another conversation holds".to_owned(),
                retryable: false,
            },
            Err(e) => {
                if !self.unfiled_joins.iter().any(|u| u.welcome == digest) {
                    self.unfiled_joins.push(UnfiledJoin {
                        welcome: digest,
                        conversation_id: env.conversation_id.clone(),
                        group_id,
                    });
                }
                return Processed {
                    ack: false,
                    event: Event::Failed {
                        reason: e,
                        retryable: true,
                    },
                };
            }
        };
        self.unfiled_joins.retain(|u| u.welcome != digest);
        Processed::ack(event)
    }

    /// A Welcome is filed by the conversation it was sent for: it carries
    /// no group id to file it by. If the conversation already had a
    /// group, the Welcome is the one that re-seats this device (a rejoin
    /// answered), and it replaces the old one.
    fn file_group(&mut self, conversation_id: &str, group_id: &[u8]) -> Result<bool, String> {
        if self.directory.group_for(conversation_id).is_some() {
            self.directory.record_replacing(conversation_id, group_id)
        } else {
            self.directory.record(conversation_id, group_id)
        }
    }

    /// The conversation of a joined group whose filing failed, filed now.
    /// `Ok(None)` when no such join is held. The entry stays until its
    /// Welcome is replayed, so that replay is answered as joined.
    fn file_unfiled_group(&mut self, group_id: &[u8]) -> Result<Option<String>, String> {
        let Some(conversation_id) = self
            .unfiled_joins
            .iter()
            .find(|u| u.group_id == group_id)
            .map(|u| u.conversation_id.clone())
        else {
            return Ok(None);
        };
        if self.file_group(&conversation_id, group_id)? {
            Ok(Some(conversation_id))
        } else {
            self.unfiled_joins.retain(|u| u.group_id != group_id);
            Ok(None)
        }
    }

    /// Leave an envelope for a group this device has not joined for a
    /// replay, at most [`MAX_DEFERRALS`] times.
    fn defer_unjoined(&mut self, env: &InboundEnvelope, what: &str) -> Processed {
        match self.directory.defer(&env.envelope_id) {
            Ok(attempts) if attempts >= MAX_DEFERRALS => {
                self.directory.settle(&env.envelope_id);
                Processed::ack(Event::Failed {
                    reason: format!(
                        "{what} after {attempts} deliveries; its Welcome never arrived"
                    ),
                    retryable: false,
                })
            }
            // Counted, or not countable now: either way it may yet be
            // joined, so leave it for the replay.
            Ok(_) | Err(_) => Processed {
                ack: false,
                event: Event::Failed {
                    reason: what.to_owned(),
                    retryable: true,
                },
            },
        }
    }

    fn process_application(&mut self, env: &InboundEnvelope) -> Processed {
        let Ok(group_id) = message_group_id(&env.ciphertext) else {
            return Processed::ack(Event::Failed {
                reason: "the message carries no group id".to_owned(),
                retryable: false,
            });
        };
        if self.engine.group_epoch(&group_id).is_none() {
            // Most likely its Welcome is still on the way; leave it for
            // the replay rather than lose it.
            return self.defer_unjoined(env, "a message for a group this device has not joined");
        }
        self.directory.settle(&env.envelope_id);
        // Filed by this device's own record, never the envelope's: the
        // conversation the group is (or was, before a rejoin superseded
        // it). A group no conversation holds has no conversation to show
        // a message in, whatever the envelope says.
        let conversation_id = match self.directory.conversation_of_message(&group_id) {
            Some(c) => c,
            None => match self.file_unfiled_group(&group_id) {
                Ok(Some(c)) => c,
                Ok(None) => {
                    return Processed::ack(Event::Ignored {
                        reason: "a message for a group no conversation holds".to_owned(),
                    });
                }
                Err(e) => {
                    return Processed {
                        ack: false,
                        event: Event::Failed {
                            reason: e,
                            retryable: true,
                        },
                    };
                }
            },
        };
        // Past the cutover the engine refuses a message whose authenticated
        // sending leaf is not of `from_airdress`, so the name below is the
        // sender's own.
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
                    r#ref: payload.r#ref,
                    reply_to: payload.reply_to,
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
            // Decrypted and not kept: the group on disk is where it was,
            // so the same ciphertext decrypts once storage takes it.
            Err(EngineError::Storage(e)) => storage_failed(e),
            Err(e @ (EngineError::RevocationViewStale(_) | EngineError::Other(_))) => {
                Processed::ack(Event::Failed {
                    reason: e.to_string(),
                    retryable: false,
                })
            }
        }
    }

    fn process_commit(&mut self, env: &InboundEnvelope) -> Processed {
        let processed = self.apply_commit(env);
        // An acknowledged commit is no longer left for a replay; a count
        // kept for an unacknowledged one bounds its replays.
        if processed.ack {
            self.directory.settle(&env.envelope_id);
        }
        processed
    }

    fn apply_commit(&mut self, env: &InboundEnvelope) -> Processed {
        let Ok(group_id) = message_group_id(&env.ciphertext) else {
            return Processed::ack(Event::Failed {
                reason: "the commit carries no group id".to_owned(),
                retryable: false,
            });
        };
        let Some(current) = self.engine.group_epoch(&group_id) else {
            return self.defer_unjoined(env, "a commit for a group this device has not joined");
        };
        let conversation_id = match self.directory.conversation_for(&group_id) {
            Some(c) => Some(c),
            None => match self.file_unfiled_group(&group_id) {
                Ok(c) => c,
                Err(e) => {
                    return Processed {
                        ack: false,
                        event: Event::Failed {
                            reason: e,
                            retryable: true,
                        },
                    };
                }
            },
        };
        // A group this device was removed from: its state lingers in the
        // engine, but no commit can apply to it any more, and the one most
        // likely to arrive is the Add bringing this device straight back,
        // whose Welcome follows. Asking to rejoin here would be answered
        // with a second Remove and Add (SPEC-166 166-B.14, measured on
        // VM2).
        let Some(conversation_id) = conversation_id else {
            return Processed::ack(Event::Ignored {
                reason: "a commit for a group this device was removed from".to_owned(),
            });
        };
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
            // Not applied and not kept: the group on disk is at the
            // epoch before, so the same commit applies once storage
            // takes it.
            Err(EngineError::Storage(e)) => storage_failed(e),
            // It removes a device this device holds live. The commit
            // persisted nothing: the host refreshes its revocation state
            // and the replay processes the same commit again. Bounded
            // like an unjoined group's envelope, after which this device
            // stays behind and asks to rejoin.
            Err(EngineError::RevocationViewStale(e)) => {
                self.defer_for_revocation(env, conversation_id, e)
            }
            // A commit this device should be able to apply and cannot:
            // it has fallen behind, and only a re-add brings it back.
            Err(EngineError::Other(e)) => Processed::ack(Event::RejoinNeeded {
                conversation_id,
                reason: e,
            }),
        }
    }

    /// Leave a commit refused for this device's revocation view for a
    /// replay, at most [`MAX_DEFERRALS`] times; after that, ask to rejoin.
    fn defer_for_revocation(
        &mut self,
        env: &InboundEnvelope,
        conversation_id: String,
        reason: String,
    ) -> Processed {
        match self.directory.defer(&env.envelope_id) {
            Ok(attempts) if attempts >= MAX_DEFERRALS => Processed::ack(Event::RejoinNeeded {
                conversation_id,
                reason,
            }),
            Ok(_) | Err(_) => Processed {
                ack: false,
                event: Event::Failed {
                    reason,
                    retryable: true,
                },
            },
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
            if let Err(e) = self.engine.propose_add(&group_id, kp) {
                // All or nothing: what was staged before the refusal must
                // not ride along on the next commit.
                self.engine.discard_staged(&group_id);
                return Err(SendError::Engine(e));
            }
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
            let staged = members
                .iter()
                .find(|m| &m.identity == identity)
                .ok_or_else(|| "no such member in this group".to_owned())
                .and_then(|member| self.engine.propose_remove(&group_id, member.index));
            if let Err(e) = staged {
                // All or nothing, as in `prepare_add`.
                self.engine.discard_staged(&group_id);
                return Err(SendError::Engine(e));
            }
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
    /// No group or no held commit; [`SendError::Storage`] when the new
    /// state could not be written, in which case the commit stays held
    /// and the same call succeeds once storage does.
    pub fn confirm_commit(&mut self, conversation_id: &str) -> Result<u64, SendError> {
        let group_id = self
            .directory
            .group_for(conversation_id)
            .ok_or(SendError::NoGroup)?;
        self.engine.confirm_commit(&group_id).map_err(|e| match e {
            EngineError::Storage(e) => SendError::Storage(e),
            other => SendError::Engine(other.to_string()),
        })
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
