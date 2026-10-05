//! The client half that sits around [`airdress_mls`], written once in Rust.
//!
//! The phone has this logic in Dart; a device that is not the phone — a
//! terminal, a coding assistant's device host — needs the same decisions
//! made the same way, or a message that decrypts on one fails on the
//! other. This crate is those decisions, and nothing that touches a
//! network:
//!
//! * [`wire`] — the operator's envelope shapes (the SSE `envelope` event
//!   and the body of a conversation envelope POST), the lane payload, and
//!   the commit-group tag;
//! * [`directory`] — which MLS group is which conversation, sealed on disk;
//! * [`pins`] — trust-on-first-use pins of peers' root keys, with the record
//!   of every change seen;
//! * [`client`] — what to do with an inbound envelope (join, decrypt, apply
//!   a commit, ask to rejoin) and how to build an outbound one.
//!
//! The host does the HTTP. It hands each received envelope to
//! [`client::Client::process`], acknowledges it when told to, and posts
//! whatever [`client::Client::encrypt`] or [`client::Client::establish`]
//! return. Keeping the I/O out is what lets the same crate serve a blocking
//! CLI, an async daemon and a test with no operator at all.

pub mod client;
pub mod directory;
pub mod pins;
mod sealed;
pub mod vectors;
pub mod wire;

pub use client::{Client, Event, Message, PreparedCommit, Processed, SendError};
pub use directory::Directory;
pub use pins::{PinChange, PinObservation, PinStore};
pub use wire::{EnvelopeKind, InboundEnvelope, LanePayload, OutboundEnvelope, commit_group_tag};
