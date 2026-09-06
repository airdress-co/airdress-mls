//! The application-message AAD binding (SPEC-061 FR-17a, design D-8).
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
//! AAD = "airdress-spec-061-v1" ‖ 0x1F ‖ conversation_id (16 raw bytes)
//!                              ‖ 0x1F ‖ from_airdress (UTF-8)
//! ```
//!
//! ## Why these two components, and no others
//!
//! **The receiver must be able to compute the AAD before it
//! decrypts.** `conversation_id` and `from_airdress` are cleartext
//! columns on the envelope row and are both carried on the SSE event,
//! so the receiver has them in hand at the moment it needs them.
//! Anything derived from the plaintext would be unusable here — it
//! would have to be known before the plaintext existed.
//!
//! ## Why a new label
//!
//! SPEC-042's AEAD binding uses `airdress-spec-042-v1`. This one gets
//! its own label so that a future change to *this* binding is a new
//! version rather than a silent semantic shift of the same bytes under
//! a shared name.
//!
//! ## One construction, called from both engines
//!
//! Both sides must compute byte-identical AAD or nothing decrypts, so
//! the construction lives here once and is called from the client
//! engine (`engine.rs`) and the operator's in-process agent engine
//! (`airdress-operator/src/agent/mls.rs`) alike.

/// Version label, per the SPEC-042 precedent. A change to the
/// construction gets a new label, never new semantics under this one.
pub const AAD_LABEL: &[u8] = b"airdress-spec-061-v1";

/// Field separator. `0x1F` (ASCII unit separator) cannot occur in a
/// hostname or in the UTF-8 encoding of one, which is what makes the
/// concatenation unambiguous. Same byte, same reason, as
/// [`crate::credential::IDENTITY_SEPARATOR`].
pub const AAD_SEPARATOR: u8 = 0x1F;

/// The cleartext envelope fields an application message is bound to.
///
/// Borrowed rather than owned: the caller already has both, and this
/// type exists to make the pair impossible to supply by halves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageBinding<'a> {
    /// The conversation the message belongs to — the 16 raw bytes of
    /// the UUID, not its hyphenated rendering, so two spellings of one
    /// id cannot produce two AADs.
    pub conversation_id: [u8; 16],
    /// The airdress the message is attributed to.
    pub from_airdress: &'a str,
}

impl<'a> MessageBinding<'a> {
    /// Construct a binding from a conversation id and a sender.
    #[must_use]
    pub const fn new(conversation_id: [u8; 16], from_airdress: &'a str) -> Self {
        Self {
            conversation_id,
            from_airdress,
        }
    }

    /// The AAD bytes. Deterministic, allocation-per-call, and cheap
    /// enough that neither engine caches it.
    #[must_use]
    pub fn aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(AAD_LABEL.len() + 1 + 16 + 1 + self.from_airdress.len());
        out.extend_from_slice(AAD_LABEL);
        out.push(AAD_SEPARATOR);
        out.extend_from_slice(&self.conversation_id);
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
/// decrypts. Post-cutover the binding is mandatory: a caller that
/// supplies none is refused rather than silently falling back, because
/// a silent fallback is indistinguishable on the wire from an
/// unbound message and would make the binding attacker-selectable.
///
/// # Errors
///
/// The caller supplied no binding while the engine is past the v2
/// cutover.
pub fn aad_for(cutover: bool, binding: Option<MessageBinding<'_>>) -> Result<Vec<u8>, String> {
    match (cutover, binding) {
        (false, _) => Ok(Vec::new()),
        (true, Some(binding)) => Ok(binding.aad()),
        (true, None) => Err(
            "application messages must carry their conversation binding after the SPEC-061 cutover"
                .to_owned(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::{AAD_LABEL, MessageBinding, aad_for};

    const CONV: [u8; 16] = [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10,
    ];

    #[test]
    fn aad_is_label_separator_conversation_separator_sender() {
        let aad = MessageBinding::new(CONV, "alice.test").aad();
        let mut expected = AAD_LABEL.to_vec();
        expected.push(0x1F);
        expected.extend_from_slice(&CONV);
        expected.push(0x1F);
        expected.extend_from_slice(b"alice.test");
        assert_eq!(aad, expected);
    }

    #[test]
    fn a_different_conversation_or_sender_is_a_different_aad() {
        let base = MessageBinding::new(CONV, "alice.test").aad();
        let mut other_conv = CONV;
        other_conv[0] ^= 0xff;
        assert_ne!(base, MessageBinding::new(other_conv, "alice.test").aad());
        assert_ne!(base, MessageBinding::new(CONV, "bob.test").aad());
    }

    #[test]
    fn pre_cutover_is_empty_and_post_cutover_demands_a_binding() {
        assert!(aad_for(false, None).unwrap().is_empty());
        assert!(
            aad_for(false, Some(MessageBinding::new(CONV, "alice.test")))
                .unwrap()
                .is_empty(),
            "pre-cutover must stay wire-compatible with a v1 peer"
        );
        assert!(aad_for(true, None).is_err());
        assert_eq!(
            aad_for(true, Some(MessageBinding::new(CONV, "alice.test"))).unwrap(),
            MessageBinding::new(CONV, "alice.test").aad()
        );
    }
}
