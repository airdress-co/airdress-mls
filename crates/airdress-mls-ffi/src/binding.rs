//! The application-message AAD binding (SPEC-061 FR-17a, design D-10).
//!
//! Both engines used to pass `Vec::new()` as the additional
//! authenticated data of every application message. That leaves the
//! envelope's routing metadata unauthenticated: an operator can move a
//! peer's ciphertext into another conversation, or re-attribute it to
//! another sender, and the receiving client renders the result under
//! the wrong heading **with a valid signature**. That is worse than a
//! decryption failure, because it looks correct.
//!
//! The binding:
//!
//! ```text
//! AAD = "airdress-spec-061-v2" ‖ 0x1F ‖ group_id ‖ 0x1F ‖ from_airdress (UTF-8)
//! ```
//!
//! ## Why the group id and not the conversation id (design D-10)
//!
//! D-8 bound `conversation_id ‖ from_airdress` and shipped. Both
//! engines then began *comparing* the AAD on receipt rather than
//! merely binding it — MLS transmits `authenticated_data` in the
//! clear, so binding alone catches nothing; the AAD travels with the
//! ciphertext it was moved with. The comparison only works when the
//! two sides compute the same bytes.
//!
//! They could not. A conversation row is minted **per owner**:
//! `EnvelopeStore::ensure_recipient_conversation` is a find-or-create
//! keyed on `(owner_principal_id, target_airdress)`. So for any
//! conversation whose members span two owners — two SPEC-042
//! principals on one operator, two airdresses on one operator (the
//! shape FR-37 makes the target), or two operators — each side holds
//! its own UUID and neither can compute the other's. Past the cutover
//! that lane could not decrypt at all.
//!
//! The group id has no such problem. **It is the group**: delivered by
//! the Welcome, identical for every member, and the same value
//! regardless of which operator or which principal a member sits
//! behind. Agreement is by construction rather than by coincidence of
//! ownership.
//!
//! ## The receiver must compute the AAD before it decrypts
//!
//! That constraint is unchanged from D-8, and the group id satisfies
//! it more directly than the conversation id ever did: RFC 9420 puts
//! `group_id` in `PrivateMessage` **in the clear**, so it is already
//! readable off the framing — the operator's agent reads it today to
//! select the group, and the client engine takes it as the argument
//! that names which group to load. Nothing new goes on the wire and
//! nothing new is disclosed.
//!
//! ## What the security property becomes
//!
//! The re-attribution defence (`from_airdress`) is unchanged. The
//! re-filing defence changes shape: it stops being "the operator
//! cannot change the conversation id it asserts" and becomes "the
//! receiver files by the group it decrypted under, which MLS itself
//! authenticates in `FramedContentTBS`". That is the stronger form —
//! it removes the operator's assertion from the trusted set instead of
//! authenticating it — but it holds only if the receiver actually
//! files by group. `airdress-chat` does, since the companion change to
//! this one.
//!
//! ## Why a new label
//!
//! SPEC-042's AEAD binding uses `airdress-spec-042-v1`; D-8's used
//! `airdress-spec-061-v1`. This construction gets `-v2` so the change
//! is a new version rather than a silent semantic shift of the same
//! bytes under a shared name. Nothing deployed ever sent a `-v1`
//! bound message: the whole binding lives past the `chat.mls_v2_cutover`
//! flag, which is off.
//!
//! ## One construction, called from both engines
//!
//! Both sides must compute byte-identical AAD or nothing decrypts, so
//! the construction lives here once and is called from the client
//! engine (`engine.rs`) and the operator's in-process agent engine
//! (`airdress-operator/src/agent/mls.rs`) alike.

/// Version label, per the SPEC-042 precedent. A change to the
/// construction gets a new label, never new semantics under this one.
///
/// `-v2` is D-10's group-id binding; `-v1` was D-8's conversation-id
/// binding, which no deployed client ever sent.
pub const AAD_LABEL: &[u8] = b"airdress-spec-061-v2";

/// Field separator. `0x1F` (ASCII unit separator) cannot occur in a
/// hostname or in the UTF-8 encoding of one, which is what makes the
/// concatenation unambiguous. Same byte, same reason, as
/// [`crate::credential::IDENTITY_SEPARATOR`].
///
/// A group id **is** arbitrary bytes and may contain `0x1F`, unlike
/// D-8's fixed-width conversation id. The construction is still
/// unambiguous, because it is read from the right: the label is fixed
/// length and `from_airdress` contains no `0x1F`, so the *last*
/// separator always ends the group id. No pair of distinct
/// `(group_id, from_airdress)` values can collide.
pub const AAD_SEPARATOR: u8 = 0x1F;

/// The cleartext fields an application message is bound to.
///
/// Borrowed rather than owned: the caller already has both, and this
/// type exists to make the pair impossible to supply by halves.
///
/// Neither engine asks a caller to construct one. Both build it
/// internally from the group they are about to encrypt into — or the
/// group they just loaded to decrypt — plus the sending airdress the
/// caller names. That is what deletes D-8's "the caller supplied no
/// binding" failure class: there is no longer anything a caller can
/// omit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageBinding<'a> {
    /// The MLS group id, exactly as it appears in the message framing.
    pub group_id: &'a [u8],
    /// The airdress the message is attributed to.
    pub from_airdress: &'a str,
}

impl<'a> MessageBinding<'a> {
    /// Construct a binding from a group id and a sender.
    #[must_use]
    pub const fn new(group_id: &'a [u8], from_airdress: &'a str) -> Self {
        Self {
            group_id,
            from_airdress,
        }
    }

    /// The AAD bytes. Deterministic, allocation-per-call, and cheap
    /// enough that neither engine caches it.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(
            AAD_LABEL.len() + 1 + self.group_id.len() + 1 + self.from_airdress.len(),
        );
        out.extend_from_slice(AAD_LABEL);
        out.push(AAD_SEPARATOR);
        out.extend_from_slice(self.group_id);
        out.push(AAD_SEPARATOR);
        out.extend_from_slice(self.from_airdress.as_bytes());
        out
    }
}

/// The AAD an application message carries, given the engine's cutover
/// state.
///
/// Pre-cutover this is empty, exactly as it has always been — a `v: 1`
/// peer computes an empty AAD and the two must agree or nothing
/// decrypts. Post-cutover it is the D-10 binding.
///
/// **Infallible, unlike D-8's version.** That one returned
/// `Result` because a caller past the cutover could fail to supply a
/// conversation id it had no way to compute, and a silent fallback to
/// an empty AAD would have been indistinguishable on the wire from an
/// unbound message. Under D-10 both components are always in hand at
/// the call site — the engine holds the group, the caller names the
/// sender — so there is nothing left to refuse.
#[must_use]
pub fn aad_for(cutover: bool, group_id: &[u8], from_airdress: &str) -> Vec<u8> {
    if cutover {
        MessageBinding::new(group_id, from_airdress).aad()
    } else {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use super::{AAD_LABEL, MessageBinding, aad_for};

    const GID: &[u8] = &[
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];

    #[test]
    fn aad_is_label_separator_group_separator_sender() {
        let aad = MessageBinding::new(GID, "alice.test").aad();
        let mut expected = AAD_LABEL.to_vec();
        expected.push(0x1F);
        expected.extend_from_slice(GID);
        expected.push(0x1F);
        expected.extend_from_slice(b"alice.test");
        assert_eq!(aad, expected);
    }

    #[test]
    fn the_label_is_v2_because_the_construction_changed() {
        assert_eq!(AAD_LABEL, b"airdress-spec-061-v2");
    }

    #[test]
    fn a_different_group_or_sender_is_a_different_aad() {
        let base = MessageBinding::new(GID, "alice.test").aad();
        let mut other = GID.to_vec();
        other[0] ^= 0xff;
        assert_ne!(base, MessageBinding::new(&other, "alice.test").aad());
        assert_ne!(base, MessageBinding::new(GID, "bob.test").aad());
    }

    /// A group id may contain the separator byte; a hostname cannot.
    /// That asymmetry is what keeps the construction unambiguous over
    /// the values that can occur: read from the right, the **last**
    /// separator always ends the group id.
    ///
    /// The one other pre-image of these bytes needs a `from_airdress`
    /// containing `0x1F`, which no airdress can. And even granting an
    /// attacker one, it buys nothing: the receiver's group id is not
    /// attacker-chosen — it is the group actually loaded — so a match
    /// forces the sender component to be equal too.
    #[test]
    fn a_separator_inside_the_group_id_stays_unambiguous() {
        let tricky: &[u8] = b"aa\x1fzz";
        let aad = MessageBinding::new(tricky, "alice.test").aad();
        let last = aad
            .iter()
            .rposition(|byte| *byte == 0x1F)
            .expect("separator");
        assert_eq!(&aad[last + 1..], b"alice.test");
        assert_eq!(&aad[AAD_LABEL.len() + 1..last], tricky);
    }

    #[test]
    fn pre_cutover_is_empty_and_post_cutover_is_the_binding() {
        assert!(aad_for(false, GID, "alice.test").is_empty());
        assert_eq!(
            aad_for(true, GID, "alice.test"),
            MessageBinding::new(GID, "alice.test").aad()
        );
    }
}
