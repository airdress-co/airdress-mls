//! C-compatible FFI exports for `dart:ffi`.
//!
//! ## Memory contract
//!
//! - `FfiBytes` returned by Rust must be freed by Dart via
//!   `airdress_mls_free_bytes`.
//! - `FfiBytes` passed TO Rust (as arguments) are borrowed — Rust
//!   does not free them.
//! - `handle_id` values are opaque integers. Dart must not fabricate
//!   them; only use values returned by
//!   `airdress_mls_create_engine_from_seed`.

use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use super::engine::{CommitOutcome, MlsEngine};

// ---------------------------------------------------------------------------
// Handle table
// ---------------------------------------------------------------------------

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static ENGINES: std::sync::LazyLock<Mutex<HashMap<u64, MlsEngine>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

// ---------------------------------------------------------------------------
// FFI byte buffer
// ---------------------------------------------------------------------------

/// Byte buffer returned across the FFI boundary.
///
/// `ptr` is heap-allocated by Rust; Dart must call
/// `airdress_mls_free_bytes` to release it. `error` is non-null when
/// the operation failed (and `ptr`/`len` are zero).
#[repr(C)]
pub struct FfiBytes {
    pub ptr: *mut u8,
    pub len: usize,
    pub error: *mut c_char,
}

impl FfiBytes {
    fn ok(data: Vec<u8>) -> Self {
        let mut boxed = data.into_boxed_slice();
        let ptr = boxed.as_mut_ptr();
        let len = boxed.len();
        std::mem::forget(boxed);
        Self {
            ptr,
            len,
            error: std::ptr::null_mut(),
        }
    }

    fn err(msg: String) -> Self {
        let c_str = std::ffi::CString::new(msg).unwrap_or_default();
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            error: c_str.into_raw(),
        }
    }
}

/// Result type for handle-returning operations.
#[repr(C)]
pub struct FfiHandleResult {
    pub handle_id: u64,
    pub public_key_ptr: *mut u8,
    pub public_key_len: usize,
    pub error: *mut c_char,
}

/// Result type for `start_group` which returns three byte arrays.
#[repr(C)]
pub struct FfiStartGroupResult {
    pub group_id_ptr: *mut u8,
    pub group_id_len: usize,
    pub welcome_ptr: *mut u8,
    pub welcome_len: usize,
    pub first_app_ptr: *mut u8,
    pub first_app_len: usize,
    pub error: *mut c_char,
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

fn ffi_handle_err(msg: &str) -> FfiHandleResult {
    let c_str = std::ffi::CString::new(msg).unwrap_or_default();
    FfiHandleResult {
        handle_id: 0,
        public_key_ptr: std::ptr::null_mut(),
        public_key_len: 0,
        error: c_str.into_raw(),
    }
}

/// Borrow a required C string argument, rejecting null and invalid UTF-8.
fn required_str<'a>(ptr: *const c_char, name: &str) -> Result<&'a str, String> {
    if ptr.is_null() {
        return Err(format!("{name} is null"));
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|_| format!("{name} is not valid UTF-8"))
}

/// Borrow a required 32-byte argument, rejecting null and wrong lengths.
fn required_key32(ptr: *const u8, len: usize, name: &str) -> Result<[u8; 32], String> {
    if ptr.is_null() {
        return Err(format!("{name} is null"));
    }
    if len != 32 {
        return Err(format!("{name} must be 32 bytes, got {len}"));
    }
    let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
    slice.try_into().map_err(|_| format!("{name} length error"))
}

/// Create an MLS engine from host-supplied identity material.
///
/// `session_seed` is the device SESSION signing seed (32 bytes) from the
/// host's secure storage — never the airdress root private key, which
/// must not cross this boundary. `root_pubkey` (32 bytes) and
/// `delegation_json` describe the device's identity chain; `state_dir`
/// and `state_key` (32 bytes) locate and seal the on-disk MLS state.
///
/// Returns a handle ID + the session public key.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_create_engine_from_seed(
    airdress: *const c_char,
    session_seed: *const u8,
    session_seed_len: usize,
    root_pubkey: *const u8,
    root_pubkey_len: usize,
    delegation_json: *const c_char,
    state_dir: *const c_char,
    state_key: *const u8,
    state_key_len: usize,
) -> FfiHandleResult {
    let parsed = (|| -> Result<MlsEngine, String> {
        let airdress = required_str(airdress, "airdress")?;
        let seed = required_key32(session_seed, session_seed_len, "session_seed")?;
        let root = required_key32(root_pubkey, root_pubkey_len, "root_pubkey")?;
        let delegation = required_str(delegation_json, "delegation_json")?;
        let state_dir = required_str(state_dir, "state_dir")?;
        let key = required_key32(state_key, state_key_len, "state_key")?;
        MlsEngine::from_seed(airdress, &seed, &root, delegation, state_dir, &key)
    })();

    match parsed {
        Ok(engine) => {
            let pk = engine.public_key().to_vec();
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            ENGINES.lock().expect("poisoned").insert(id, engine);
            let mut pk_box = pk.into_boxed_slice();
            let pk_ptr = pk_box.as_mut_ptr();
            let pk_len = pk_box.len();
            std::mem::forget(pk_box);
            FfiHandleResult {
                handle_id: id,
                public_key_ptr: pk_ptr,
                public_key_len: pk_len,
                error: std::ptr::null_mut(),
            }
        }
        Err(msg) => ffi_handle_err(&msg),
    }
}

/// Host-supplied root-key cache callback.
///
/// Called with the peer's airdress (NUL-terminated UTF-8) and a
/// 32-byte output buffer. The host returns 1 after filling the buffer
/// with the root public key its cache holds for that airdress (24h
/// TTL, populated at first contact), or 0 when it has none — which
/// rejects the peer's leaf. The callback must be thread-safe and must
/// not call back into this library.
pub type AirdressRootKeyLookupFn =
    extern "C" fn(airdress: *const c_char, out_root_public_key: *mut u8) -> i32;

struct CallbackRootKeyLookup(AirdressRootKeyLookupFn);

impl crate::credential::RootKeyLookup for CallbackRootKeyLookup {
    fn root_public_key(&self, airdress: &str) -> Option<[u8; 32]> {
        let c_airdress = std::ffi::CString::new(airdress).ok()?;
        let mut out = [0u8; 32];
        if (self.0)(c_airdress.as_ptr(), out.as_mut_ptr()) == 1 {
            Some(out)
        } else {
            None
        }
    }
}

/// Register the host's root-key cache and switch the engine to strict
/// credential verification (one-way cutover). Returns 0 on success,
/// -1 for an invalid handle.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_set_root_key_lookup(
    handle_id: u64,
    lookup: AirdressRootKeyLookupFn,
) -> i32 {
    let guard = ENGINES.lock().expect("poisoned");
    match guard.get(&handle_id) {
        Some(engine) => {
            engine.set_root_key_lookup(std::sync::Arc::new(CallbackRootKeyLookup(lookup)));
            0
        }
        None => -1,
    }
}

/// Host callback answering "is this device revoked?" (SPEC-061
/// FR-19, check 5).
///
/// Return `1` for an active device, `0` for a revoked one, and
/// anything else — conventionally `-1` — for "cannot answer", which
/// REJECTS the leaf. The callback must be thread-safe and must not
/// call back into this library.
pub type AirdressRevocationLookupFn = extern "C" fn(device_id: *const c_char) -> i32;

struct CallbackRevocationLookup(AirdressRevocationLookupFn);

impl crate::credential::RevocationLookup for CallbackRevocationLookup {
    fn device_status(&self, device_id: &str) -> Option<crate::credential::DeviceStatus> {
        let c_device_id = std::ffi::CString::new(device_id).ok()?;
        match (self.0)(c_device_id.as_ptr()) {
            1 => Some(crate::credential::DeviceStatus::Active),
            0 => Some(crate::credential::DeviceStatus::Revoked),
            // Unknown answers are "cannot answer", not "fine" — the
            // caller gets RevocationUnavailable, which is a reject.
            _ => None,
        }
    }
}

/// Register the host's device-revocation state (SPEC-061 FR-19).
/// Returns 0 on success, -1 for an invalid handle.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_set_revocation_lookup(
    handle_id: u64,
    lookup: AirdressRevocationLookupFn,
) -> i32 {
    let guard = ENGINES.lock().expect("poisoned");
    match guard.get(&handle_id) {
        Some(engine) => {
            engine.set_revocation_lookup(std::sync::Arc::new(CallbackRevocationLookup(lookup)));
            0
        }
        None => -1,
    }
}

/// Enter the SPEC-061 v2 credential cutover (FR-20): `v: 1`
/// identities stop being accepted and the per-device member identity
/// becomes the only form in the tree. One-way within the process, per
/// NFR-15 — there is no symmetric "unset" export, deliberately.
///
/// Returns 0 on success, -1 for an invalid handle.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_set_v2_cutover(handle_id: u64) -> i32 {
    let guard = ENGINES.lock().expect("poisoned");
    match guard.get(&handle_id) {
        Some(engine) => {
            engine.set_v2_cutover();
            0
        }
        None => -1,
    }
}

/// Whether the v2 cutover has been entered on this engine. Returns 1
/// for yes, 0 for no, -1 for an invalid handle.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_is_v2_cutover(handle_id: u64) -> i32 {
    let guard = ENGINES.lock().expect("poisoned");
    match guard.get(&handle_id) {
        Some(engine) => i32::from(engine.is_v2_cutover()),
        None => -1,
    }
}

/// Destroy an MLS engine and free its resources.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_destroy_engine(handle_id: u64) {
    ENGINES.lock().expect("poisoned").remove(&handle_id);
}

/// Generate a serialized KeyPackage.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_generate_key_package(handle_id: u64) -> FfiBytes {
    let guard = ENGINES.lock().expect("poisoned");
    match guard.get(&handle_id) {
        Some(engine) => match engine.generate_key_package() {
            Ok(bytes) => FfiBytes::ok(bytes),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// List of byte buffers returned across the FFI boundary.
///
/// `items` points at `len` consecutive `FfiBytes` (each with a
/// buffer to free); the whole structure is released in one call to
/// `airdress_mls_free_bytes_list`. `error` is non-null on failure
/// (and `items`/`len` are zero).
#[repr(C)]
pub struct FfiBytesList {
    pub items: *mut FfiBytes,
    pub len: usize,
    pub error: *mut c_char,
}

impl FfiBytesList {
    fn ok(buffers: Vec<Vec<u8>>) -> Self {
        let mut items: Box<[FfiBytes]> = buffers.into_iter().map(FfiBytes::ok).collect();
        let ptr = items.as_mut_ptr();
        let len = items.len();
        std::mem::forget(items);
        Self {
            items: ptr,
            len,
            error: std::ptr::null_mut(),
        }
    }

    fn err(msg: String) -> Self {
        let c_str = std::ffi::CString::new(msg).unwrap_or_default();
        Self {
            items: std::ptr::null_mut(),
            len: 0,
            error: c_str.into_raw(),
        }
    }

    /// An empty list carrying no error — what the delta fields of a
    /// failed `FfiCommitResult` hold, so the single free function has
    /// nothing to skip.
    const fn empty() -> Self {
        Self {
            items: std::ptr::null_mut(),
            len: 0,
            error: std::ptr::null_mut(),
        }
    }
}

/// Generate `count` fresh KeyPackages and return their publishable
/// public messages. Private halves are persisted through the sealed
/// state store so they survive restart — a KeyPackage whose private
/// half is lost is a Welcome the client can never join. Packages are
/// single-use; consumption deletes them from the pool.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_generate_key_packages(handle_id: u64, count: usize) -> FfiBytesList {
    let guard = ENGINES.lock().expect("poisoned");
    match guard.get(&handle_id) {
        Some(engine) => match engine.generate_key_packages(count) {
            Ok(buffers) => FfiBytesList::ok(buffers),
            Err(e) => FfiBytesList::err(e),
        },
        None => FfiBytesList::err("invalid handle".into()),
    }
}

/// The publishable public messages of every unconsumed KeyPackage in
/// the pool — for first publish and for re-publish after a restart.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_stored_key_packages(handle_id: u64) -> FfiBytesList {
    let guard = ENGINES.lock().expect("poisoned");
    match guard.get(&handle_id) {
        Some(engine) => match engine.stored_key_packages() {
            Ok(buffers) => FfiBytesList::ok(buffers),
            Err(e) => FfiBytesList::err(e),
        },
        None => FfiBytesList::err("invalid handle".into()),
    }
}

/// Number of unconsumed KeyPackage private halves in the pool.
/// Returns -1 for an invalid handle, -2 on a storage error.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_key_package_pool_count(handle_id: u64) -> i64 {
    let guard = ENGINES.lock().expect("poisoned");
    match guard.get(&handle_id) {
        Some(engine) => match engine.key_package_pool_count() {
            Ok(count) => i64::try_from(count).unwrap_or(i64::MAX),
            Err(_) => -2,
        },
        None => -1,
    }
}

/// Free a byte-buffer list previously returned by
/// `airdress_mls_generate_key_packages` or
/// `airdress_mls_stored_key_packages` (frees each buffer, each
/// per-item error, and the list itself).
///
/// # Safety
///
/// `list` must have been returned by a Rust FFI function in this
/// crate and must not have been freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_free_bytes_list(list: FfiBytesList) {
    if !list.items.is_null() && list.len > 0 {
        let items =
            unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(list.items, list.len)) };
        for item in items {
            unsafe {
                airdress_mls_free_bytes(item.ptr, item.len);
                airdress_mls_free_error(item.error);
            }
        }
    }
    unsafe { airdress_mls_free_error(list.error) };
}

/// Start a group with a peer's KeyPackage, **unbound**.
///
/// The pre-cutover form, kept so a `v: 1` client keeps working
/// unchanged. Past the v2 cutover this export **refuses**: the first
/// application message rides inside the establishment, so with no
/// binding there is no legal AAD for it (FR-17a, design D-8), and a
/// silent fallback to an empty one would be indistinguishable on the
/// wire from an unbound message. Post-cutover callers use
/// [`airdress_mls_start_group_bound`].
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_start_group(
    handle_id: u64,
    peer_kp_ptr: *const u8,
    peer_kp_len: usize,
    first_msg_ptr: *const u8,
    first_msg_len: usize,
) -> FfiStartGroupResult {
    let peer_kp = unsafe { std::slice::from_raw_parts(peer_kp_ptr, peer_kp_len) };
    let first_msg = unsafe { std::slice::from_raw_parts(first_msg_ptr, first_msg_len) };
    start_group_into_ffi(handle_id, peer_kp, first_msg, None)
}

/// The unbound exports' post-cutover refusal (SPEC-061 FR-17a).
///
/// `aad_for` used to raise this, because a caller past the cutover
/// could supply no binding. Under design D-10 the binding is derived
/// from the group and a sender the caller always has, so the engine
/// has nothing left to refuse — which means the refusal has to live
/// where the missing sender actually is: at the unbound entry points.
///
/// It is not a fallback to an unbound message. An unbound send past
/// the cutover would be indistinguishable on the wire from one an
/// attacker stripped, which is the property FR-17a exists to hold.
fn refuse_unbound_past_cutover(handle_id: u64) -> Option<String> {
    let guard = ENGINES.lock().expect("poisoned");
    let engine = guard.get(&handle_id)?;
    engine.is_v2_cutover().then(|| {
        "application messages must carry their sender binding after the v2 credential cutover"
            .to_owned()
    })
}

/// Start a group with a peer's KeyPackage, carrying the SPEC-061
/// FR-17a conversation binding for the first application message.
///
/// ## Why this export exists
///
/// Establishment was the one operation with no bound form. Joining a
/// group (`airdress_mls_process_welcome`) and sending into an
/// established one (`airdress_mls_encrypt_bound`) were both bound, but
/// the group's **first** application message rides inside
/// `start_group` — so past the cutover a client could join and send
/// and could not create. Since nothing else creates the first group of
/// a conversation, no conversation could be established at all. This
/// closes that.
///
/// Argument shape mirrors `airdress_mls_encrypt_bound` /
/// `airdress_mls_decrypt_bound` exactly: one extra argument, the
/// sending airdress as a NUL-terminated UTF-8 string. The group
/// component of the binding is the group this call creates, so the
/// caller does not supply it (design D-10 — it used to be a 16-byte
/// conversation UUID, which two owners could not agree on).
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_start_group_bound(
    handle_id: u64,
    peer_kp_ptr: *const u8,
    peer_kp_len: usize,
    first_msg_ptr: *const u8,
    first_msg_len: usize,
    from_airdress: *const c_char,
) -> FfiStartGroupResult {
    let peer_kp = unsafe { std::slice::from_raw_parts(peer_kp_ptr, peer_kp_len) };
    let first_msg = unsafe { std::slice::from_raw_parts(first_msg_ptr, first_msg_len) };
    let airdress = match required_str(from_airdress, "from_airdress") {
        Ok(a) => a,
        Err(e) => return ffi_start_group_err(&e),
    };
    start_group_into_ffi(handle_id, peer_kp, first_msg, Some(airdress))
}

/// Start a group with **no other member** — the owner's self thread on
/// a single-device owner (SPEC-061 task 7.2).
///
/// ## Why this export exists
///
/// Task 7.2 retires the `self.local` companion credential, so the self
/// thread becomes a conversation whose members are the owner's own
/// devices. An owner with one device has one member, and
/// `airdress_mls_start_group[_bound]` cannot express that: they take a
/// peer `KeyPackage`, and the only one a lone device holds is its own,
/// which under the task 3.3 identity is a duplicate leaf. Without this
/// the retirement would silently take the self thread away from every
/// single-device owner.
///
/// The result's `welcome_len` is **always 0** — nobody was added, so
/// there is nothing to send. Callers must not put those bytes on the
/// wire; they must still free the (empty) buffer through the same
/// `airdress_mls_free_bytes` contract every other buffer uses, so the
/// three-buffer shape is kept rather than special-cased.
///
/// The binding argument mirrors `airdress_mls_start_group_bound`
/// exactly: the sending airdress as a NUL-terminated UTF-8 string.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_start_group_solo(
    handle_id: u64,
    first_msg_ptr: *const u8,
    first_msg_len: usize,
    from_airdress: *const c_char,
) -> FfiStartGroupResult {
    let first_msg = unsafe { std::slice::from_raw_parts(first_msg_ptr, first_msg_len) };
    let airdress = match required_str(from_airdress, "from_airdress") {
        Ok(a) => a,
        Err(e) => return ffi_start_group_err(&e),
    };
    let mut guard = ENGINES.lock().expect("poisoned");
    let engine = match guard.get_mut(&handle_id) {
        Some(e) => e,
        None => return ffi_start_group_err("invalid handle"),
    };
    marshal_start_group(engine.start_group_solo(first_msg, airdress))
}

/// The body both establishment exports share: resolve the handle, run
/// the engine, and marshal the three buffers out. Written once so the
/// bound and unbound forms cannot drift in their memory contract.
fn start_group_into_ffi(
    handle_id: u64,
    peer_kp: &[u8],
    first_msg: &[u8],
    from_airdress: Option<&str>,
) -> FfiStartGroupResult {
    let mut guard = ENGINES.lock().expect("poisoned");
    let engine = match guard.get_mut(&handle_id) {
        Some(e) => e,
        None => return ffi_start_group_err("invalid handle"),
    };
    let from_airdress = match from_airdress {
        Some(a) => a,
        None if engine.is_v2_cutover() => {
            return ffi_start_group_err(
                "application messages must carry their sender binding after the \
                 v2 credential cutover",
            );
        }
        // Pre-cutover the AAD is empty regardless, so the value is
        // never read. Naming it here keeps the unbound export working
        // unchanged rather than giving it a second code path.
        None => "",
    };
    marshal_start_group(engine.start_group(peer_kp, first_msg, from_airdress))
}

/// Hand three owned buffers to the caller under the Rust-allocates /
/// Dart-frees contract. Shared by every establishment export so the
/// memory contract exists in exactly one place.
fn marshal_start_group(
    outcome: Result<crate::engine::StartGroupOutcome, String>,
) -> FfiStartGroupResult {
    match outcome {
        Ok(outcome) => {
            let mut gid = outcome.group_id.into_boxed_slice();
            let mut welcome = outcome.welcome.into_boxed_slice();
            let mut app = outcome.first_application.into_boxed_slice();
            let result = FfiStartGroupResult {
                group_id_ptr: gid.as_mut_ptr(),
                group_id_len: gid.len(),
                welcome_ptr: welcome.as_mut_ptr(),
                welcome_len: welcome.len(),
                first_app_ptr: app.as_mut_ptr(),
                first_app_len: app.len(),
                error: std::ptr::null_mut(),
            };
            std::mem::forget(gid);
            std::mem::forget(welcome);
            std::mem::forget(app);
            result
        }
        Err(e) => ffi_start_group_err(&e),
    }
}

/// Process an inbound Welcome. Returns the group ID.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_process_welcome(
    handle_id: u64,
    welcome_ptr: *const u8,
    welcome_len: usize,
) -> FfiBytes {
    let welcome = unsafe { std::slice::from_raw_parts(welcome_ptr, welcome_len) };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.process_welcome(welcome) {
            Ok(gid) => FfiBytes::ok(gid),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Encrypt plaintext under an existing group.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_encrypt(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
) -> FfiBytes {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let plaintext = unsafe { std::slice::from_raw_parts(plaintext_ptr, plaintext_len) };
    if let Some(refusal) = refuse_unbound_past_cutover(handle_id) {
        return FfiBytes::err(refusal);
    }
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.encrypt(group_id, plaintext, "") {
            Ok(bytes) => FfiBytes::ok(bytes),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Decrypt an inbound application message.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_decrypt(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    message_ptr: *const u8,
    message_len: usize,
) -> FfiBytes {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let message = unsafe { std::slice::from_raw_parts(message_ptr, message_len) };
    if let Some(refusal) = refuse_unbound_past_cutover(handle_id) {
        return FfiBytes::err(refusal);
    }
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.decrypt(group_id, message, "") {
            Ok(bytes) => FfiBytes::ok(bytes),
            // SPEC-061 FR-22: the variant is distinguishable in Rust;
            // across the C boundary it is still one sentence, per the
            // `credential.rs` discipline. Phase 6 gives the client a
            // structured form when it has somewhere to route it.
            Err(e) => FfiBytes::err(e.to_string()),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

// ---------------------------------------------------------------------------
// SPEC-061 Phase 4: proposals, commits, and the bound application path
// ---------------------------------------------------------------------------

/// Result of a commit operation — built (`commit_pending`) or applied
/// (`process_commit`).
///
/// The three-buffer shape `FfiStartGroupResult` already uses, plus the
/// membership delta FR-4 requires. `added`, `removed` and `members`
/// carry member identities (`airdress ‖ 0x1F ‖ device_id` under the v2
/// credential).
///
/// `self_removed` is `1` when THIS device was the leaf the commit
/// evicted. It is the signal that lets a removed device say so rather
/// than presenting a permanent, unexplained decryption failure.
///
/// Free with `airdress_mls_free_commit_result` — one call releases the
/// commit buffer, the welcome buffer, all three lists and the error.
#[repr(C)]
pub struct FfiCommitResult {
    pub commit_ptr: *mut u8,
    pub commit_len: usize,
    pub welcome_ptr: *mut u8,
    pub welcome_len: usize,
    pub epoch: i64,
    pub self_removed: i32,
    pub added: FfiBytesList,
    pub removed: FfiBytesList,
    pub members: FfiBytesList,
    pub error: *mut c_char,
}

fn ffi_commit_err(msg: &str) -> FfiCommitResult {
    let c_str = std::ffi::CString::new(msg).unwrap_or_default();
    FfiCommitResult {
        commit_ptr: std::ptr::null_mut(),
        commit_len: 0,
        welcome_ptr: std::ptr::null_mut(),
        welcome_len: 0,
        epoch: -1,
        self_removed: 0,
        added: FfiBytesList::empty(),
        removed: FfiBytesList::empty(),
        members: FfiBytesList::empty(),
        error: c_str.into_raw(),
    }
}

fn ffi_commit_ok(outcome: CommitOutcome) -> FfiCommitResult {
    let mut commit = outcome.commit.into_boxed_slice();
    let commit_ptr = commit.as_mut_ptr();
    let commit_len = commit.len();
    std::mem::forget(commit);

    let (welcome_ptr, welcome_len) = outcome.welcome.map_or_else(
        || (std::ptr::null_mut(), 0),
        |w| {
            let mut boxed = w.into_boxed_slice();
            let ptr = boxed.as_mut_ptr();
            let len = boxed.len();
            std::mem::forget(boxed);
            (ptr, len)
        },
    );

    FfiCommitResult {
        commit_ptr,
        commit_len,
        welcome_ptr,
        welcome_len,
        epoch: i64::try_from(outcome.epoch).unwrap_or(i64::MAX),
        self_removed: i32::from(outcome.self_removed),
        added: FfiBytesList::ok(outcome.added),
        removed: FfiBytesList::ok(outcome.removed),
        members: FfiBytesList::ok(outcome.members),
        error: std::ptr::null_mut(),
    }
}

/// Encrypt with the SPEC-061 FR-17a binding (design D-10).
///
/// `airdress_mls_encrypt` stays as the unbound form so a pre-cutover
/// client keeps working unchanged; this is the symbol the client moves
/// to at cutover. Pass the sending airdress; the group component of
/// the binding is the `group_id` this call already names.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_encrypt_bound(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    from_airdress: *const c_char,
) -> FfiBytes {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let plaintext = unsafe { std::slice::from_raw_parts(plaintext_ptr, plaintext_len) };
    let airdress = match required_str(from_airdress, "from_airdress") {
        Ok(a) => a,
        Err(e) => return FfiBytes::err(e),
    };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.encrypt(group_id, plaintext, airdress) {
            Ok(bytes) => FfiBytes::ok(bytes),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Decrypt with the SPEC-061 FR-17a binding. The counterpart to
/// `airdress_mls_encrypt_bound`: the sender comes from the envelope's
/// cleartext `from` column and the group from the framing, so the AAD
/// is computable before the decrypt.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_decrypt_bound(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    from_airdress: *const c_char,
) -> FfiBytes {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let message = unsafe { std::slice::from_raw_parts(message_ptr, message_len) };
    let airdress = match required_str(from_airdress, "from_airdress") {
        Ok(a) => a,
        Err(e) => return FfiBytes::err(e),
    };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.decrypt(group_id, message, airdress) {
            Ok(bytes) => FfiBytes::ok(bytes),
            Err(e) => FfiBytes::err(e.to_string()),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// The MLS group id carried in a message's framing, in the clear.
///
/// ## Why the client needs this (design D-10, the second half)
///
/// The FR-17a binding's security property is "the receiver files by
/// the group it decrypted under, which MLS authenticates in
/// `FramedContentTBS`". That is only true if the receiver actually
/// files by group. The client used to file by the operator-asserted
/// `conversation_id` on the SSE event, which puts the operator's
/// assertion back in the trusted set — the exact thing D-10 removes.
///
/// RFC 9420 puts `group_id` in `PrivateMessage` and `PublicMessage` in
/// the clear, so this needs no key material and no engine handle: it
/// is a parse, and it works on an application message and on a commit
/// alike. A Welcome carries no group id (the group's identity is
/// inside the encrypted `GroupInfo`), so this returns an error for
/// one — a Welcome is filed by the conversation it was sent for, which
/// is establishment-time trust and unchanged by D-10.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_message_group_id(
    message_ptr: *const u8,
    message_len: usize,
) -> FfiBytes {
    let message = unsafe { std::slice::from_raw_parts(message_ptr, message_len) };
    match mls_rs::MlsMessage::from_bytes(message) {
        Ok(msg) => match msg.group_id() {
            Some(gid) => FfiBytes::ok(gid.to_vec()),
            None => FfiBytes::err("this message carries no group id in its framing".into()),
        },
        Err(e) => FfiBytes::err(format!("bad message: {e}")),
    }
}

/// Stage an `Add` for the group's next commit (FR-3). Staged by value
/// — the commit built by `airdress_mls_commit_pending` carries it, so
/// no separate proposal message goes on the wire. Returns an empty
/// buffer on success.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_propose_add(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    key_package_ptr: *const u8,
    key_package_len: usize,
) -> FfiBytes {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let kp = unsafe { std::slice::from_raw_parts(key_package_ptr, key_package_len) };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.propose_add(group_id, kp) {
            Ok(()) => FfiBytes::ok(Vec::new()),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Stage a `Remove` of `leaf_index` for the group's next commit
/// (FR-2), by value. Refused when the leaf belongs to another airdress
/// (FR-25). Returns an empty buffer on success.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_propose_remove(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    leaf_index: u32,
) -> FfiBytes {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.propose_remove(group_id, leaf_index) {
            Ok(()) => FfiBytes::ok(Vec::new()),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Propose replacing this device's own leaf key (FR-1). Returns the
/// bare proposal for publication — the one operation that must travel
/// by reference, because RFC 9420 forbids a committer from including
/// its own `Update`.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_propose_update(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> FfiBytes {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.propose_update(group_id) {
            Ok(bytes) => FfiBytes::ok(bytes),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Hold an inbound bare proposal for the next commit (FR-5). Returns
/// an empty buffer on success.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_process_proposal(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    message_ptr: *const u8,
    message_len: usize,
) -> FfiBytes {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let message = unsafe { std::slice::from_raw_parts(message_ptr, message_len) };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.process_proposal(group_id, message) {
            Ok(()) => FfiBytes::ok(Vec::new()),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Commit held proposals WITHOUT persisting (FR-7, phase one of two).
///
/// The caller publishes `commit_ptr` and only then calls
/// `airdress_mls_confirm_commit`. On a `409` or a network failure it
/// calls `airdress_mls_abort_commit`. Persisting before the operator
/// has accepted the commit forks the group.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_commit_pending(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> FfiCommitResult {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.commit_pending(group_id) {
            Ok(outcome) => ffi_commit_ok(outcome),
            Err(e) => ffi_commit_err(&e),
        },
        None => ffi_commit_err("invalid handle"),
    }
}

/// Persist a commit built by `airdress_mls_commit_pending` (phase two).
/// Returns the resulting epoch, `-1` for an invalid handle, `-2` when
/// no commit was awaiting confirmation or the write failed.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_confirm_commit(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> i64 {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => engine
            .confirm_commit(group_id)
            .map_or(-2, |e| i64::try_from(e).unwrap_or(i64::MAX)),
        None => -1,
    }
}

/// Discard a commit built by `airdress_mls_commit_pending`, reloading
/// the group from sealed storage. Returns the epoch the group is back
/// at, `-1` for an invalid handle, `-2` when nothing was pending.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_abort_commit(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> i64 {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => engine
            .abort_commit(group_id)
            .map_or(-2, |e| i64::try_from(e).unwrap_or(i64::MAX)),
        None => -1,
    }
}

/// Apply another member's commit (FR-4): advance the epoch, persist,
/// and report the membership delta. `self_removed` is `1` when this
/// device was the leaf removed.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_process_commit(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    message_ptr: *const u8,
    message_len: usize,
) -> FfiCommitResult {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let message = unsafe { std::slice::from_raw_parts(message_ptr, message_len) };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.process_commit(group_id, message) {
            Ok(outcome) => ffi_commit_ok(outcome),
            Err(e) => ffi_commit_err(&e.to_string()),
        },
        None => ffi_commit_err("invalid handle"),
    }
}

/// The group's current epoch — the value the client declares as
/// `commit_from_epoch`. Returns `-1` for an invalid handle, `-2` when
/// the group is not on disk.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_group_epoch(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> i64 {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let guard = ENGINES.lock().expect("poisoned");
    match guard.get(&handle_id) {
        Some(engine) => engine
            .group_epoch(group_id)
            .map_or(-2, |e| i64::try_from(e).unwrap_or(i64::MAX)),
        None => -1,
    }
}

/// Every member identity in the group, in leaf-index order — for the
/// membership UI and for AC-4.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_group_members(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> FfiBytesList {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let guard = ENGINES.lock().expect("poisoned");
    match guard.get(&handle_id) {
        Some(engine) => match engine.group_members(group_id) {
            Ok(members) => FfiBytesList::ok(members.into_iter().map(|m| m.identity).collect()),
            Err(e) => FfiBytesList::err(e),
        },
        None => FfiBytesList::err("invalid handle".into()),
    }
}

/// Free an `FfiCommitResult` returned by `airdress_mls_commit_pending`
/// or `airdress_mls_process_commit`.
///
/// # Safety
///
/// `result` must have been returned by one of those two functions and
/// must not have been freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_free_commit_result(result: FfiCommitResult) {
    unsafe {
        airdress_mls_free_bytes(result.commit_ptr, result.commit_len);
        airdress_mls_free_bytes(result.welcome_ptr, result.welcome_len);
        airdress_mls_free_bytes_list(result.added);
        airdress_mls_free_bytes_list(result.removed);
        airdress_mls_free_bytes_list(result.members);
        airdress_mls_free_error(result.error);
    }
}

/// Free a byte buffer previously returned by any `airdress_mls_*` function.
///
/// # Safety
///
/// `ptr` must have been returned by a Rust FFI function in this crate and
/// must not have been freed before.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_free_bytes(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
    }
}

/// Free an error string previously returned in an FFI result's `error` field.
///
/// # Safety
///
/// `ptr` must have been returned by a Rust FFI function in this crate.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_free_error(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(unsafe { std::ffi::CString::from_raw(ptr) });
    }
}

fn ffi_start_group_err(msg: &str) -> FfiStartGroupResult {
    let c_str = std::ffi::CString::new(msg).unwrap_or_default();
    FfiStartGroupResult {
        group_id_ptr: std::ptr::null_mut(),
        group_id_len: 0,
        welcome_ptr: std::ptr::null_mut(),
        welcome_len: 0,
        first_app_ptr: std::ptr::null_mut(),
        first_app_len: 0,
        error: c_str.into_raw(),
    }
}

#[cfg(test)]
mod tests {
    //! SPEC-061 FR-17a / design D-8 at the **FFI** boundary.
    //!
    //! The engine has taken a `MessageBinding` since Phase 4; the
    //! exports are where a client can or cannot supply one. Group
    //! establishment was the one operation with no bound export, so
    //! past the cutover a client could join a group and send into an
    //! established one but could not create one — and since nothing
    //! else creates the first group of a conversation, no conversation
    //! could be established at all.

    use std::ffi::{CStr, CString};

    use ed25519_dalek::SigningKey;

    use super::{
        FfiBytes, FfiStartGroupResult, airdress_mls_create_engine_from_seed, airdress_mls_decrypt,
        airdress_mls_decrypt_bound, airdress_mls_destroy_engine, airdress_mls_encrypt_bound,
        airdress_mls_generate_key_package, airdress_mls_message_group_id,
        airdress_mls_process_welcome, airdress_mls_set_v2_cutover, airdress_mls_start_group,
        airdress_mls_start_group_bound, airdress_mls_start_group_solo,
    };

    const ALICE: &str = "alice.test.airdress.co";
    const BOB: &str = "bob.test.airdress.co";

    /// A live engine handle plus the state dir it must outlive.
    struct Handle {
        id: u64,
        _dir: tempfile::TempDir,
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            airdress_mls_destroy_engine(self.id);
        }
    }

    /// Build an engine through the export a host actually calls, and
    /// put it past the v2 cutover when asked.
    fn engine(airdress: &str, seed_byte: u8, device_id: &str, cutover: bool) -> Handle {
        let dir = tempfile::tempdir().expect("state dir");
        let seed = [seed_byte; 32];
        let root = SigningKey::from_bytes(&[seed_byte.wrapping_add(0x40); 32]);
        let session_pub = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let delegation = crate::credential::test_support::signed_delegation_json_v2(
            &root,
            airdress,
            &session_pub,
            device_id,
            "2099-01-01T00:00:00Z",
        );
        let c_airdress = CString::new(airdress).unwrap();
        let c_delegation = CString::new(delegation).unwrap();
        let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
        let root_pub = root.verifying_key().to_bytes();
        let state_key = [0x77u8; 32];
        let result = airdress_mls_create_engine_from_seed(
            c_airdress.as_ptr(),
            seed.as_ptr(),
            seed.len(),
            root_pub.as_ptr(),
            root_pub.len(),
            c_delegation.as_ptr(),
            c_dir.as_ptr(),
            state_key.as_ptr(),
            state_key.len(),
        );
        assert!(
            result.error.is_null(),
            "create_engine_from_seed: {}",
            unsafe { CStr::from_ptr(result.error) }.to_string_lossy()
        );
        unsafe { super::airdress_mls_free_bytes(result.public_key_ptr, result.public_key_len) };
        if cutover {
            assert_eq!(airdress_mls_set_v2_cutover(result.handle_id), 0);
        }
        Handle {
            id: result.handle_id,
            _dir: dir,
        }
    }

    /// Consume an `FfiBytes`, freeing whichever half it carries.
    fn take_bytes(result: FfiBytes) -> Result<Vec<u8>, String> {
        if result.error.is_null() {
            let bytes = unsafe { std::slice::from_raw_parts(result.ptr, result.len) }.to_vec();
            unsafe { super::airdress_mls_free_bytes(result.ptr, result.len) };
            Ok(bytes)
        } else {
            let msg = unsafe { CStr::from_ptr(result.error) }
                .to_string_lossy()
                .into_owned();
            unsafe { super::airdress_mls_free_error(result.error) };
            Err(msg)
        }
    }

    /// The three buffers of a start-group outcome, or the refusal.
    #[derive(Debug)]
    struct Started {
        group_id: Vec<u8>,
        welcome: Vec<u8>,
        first_application: Vec<u8>,
    }

    fn take_start(result: FfiStartGroupResult) -> Result<Started, String> {
        if !result.error.is_null() {
            let msg = unsafe { CStr::from_ptr(result.error) }
                .to_string_lossy()
                .into_owned();
            unsafe { super::airdress_mls_free_error(result.error) };
            return Err(msg);
        }
        let started = Started {
            group_id: unsafe {
                std::slice::from_raw_parts(result.group_id_ptr, result.group_id_len)
            }
            .to_vec(),
            welcome: unsafe { std::slice::from_raw_parts(result.welcome_ptr, result.welcome_len) }
                .to_vec(),
            first_application: unsafe {
                std::slice::from_raw_parts(result.first_app_ptr, result.first_app_len)
            }
            .to_vec(),
        };
        unsafe {
            super::airdress_mls_free_bytes(result.group_id_ptr, result.group_id_len);
            super::airdress_mls_free_bytes(result.welcome_ptr, result.welcome_len);
            super::airdress_mls_free_bytes(result.first_app_ptr, result.first_app_len);
        }
        Ok(started)
    }

    fn key_package(handle: &Handle) -> Vec<u8> {
        take_bytes(airdress_mls_generate_key_package(handle.id)).expect("key package")
    }

    /// **SPEC-061 FR-17a / D-10 — the cutover blocker.**
    ///
    /// Past the cutover a client must be able to CREATE a group. Join
    /// and send were already bound; establishment was not, and since
    /// nothing else creates the first group of a conversation, no
    /// conversation could be established at all.
    ///
    /// Fails before the bound establishment export existed — the only
    /// one available answered:
    ///
    /// ```text
    /// a client past the cutover must be able to establish a
    /// conversation: "application messages must carry their
    /// sender binding after the SPEC-061 cutover"
    /// ```
    #[test]
    fn a_conversation_can_be_established_past_the_cutover() {
        let alice = engine(ALICE, 0x31, "alice-a", true);
        let bob = engine(BOB, 0x32, "bob-a", true);

        let bob_kp = key_package(&bob);
        let c_alice = CString::new(ALICE).unwrap();
        let started = take_start(airdress_mls_start_group_bound(
            alice.id,
            bob_kp.as_ptr(),
            bob_kp.len(),
            b"hello bob".as_ptr(),
            b"hello bob".len(),
            c_alice.as_ptr(),
        ))
        .expect("a client past the cutover must be able to establish a conversation");

        take_bytes(airdress_mls_process_welcome(
            bob.id,
            started.welcome.as_ptr(),
            started.welcome.len(),
        ))
        .expect("bob joins");

        let plaintext = take_bytes(airdress_mls_decrypt_bound(
            bob.id,
            started.group_id.as_ptr(),
            started.group_id.len(),
            started.first_application.as_ptr(),
            started.first_application.len(),
            c_alice.as_ptr(),
        ))
        .expect("the establishment's first message decrypts under its binding");
        assert_eq!(plaintext, b"hello bob");

        // And the group is a working group afterwards, not just a
        // successful call: the conversation carries traffic in both
        // directions under the same binding.
        let c_bob = CString::new(BOB).unwrap();
        let reply = take_bytes(airdress_mls_encrypt_bound(
            bob.id,
            started.group_id.as_ptr(),
            started.group_id.len(),
            b"hi alice".as_ptr(),
            b"hi alice".len(),
            c_bob.as_ptr(),
        ))
        .expect("bob replies into the established group");
        assert_eq!(
            take_bytes(airdress_mls_decrypt_bound(
                alice.id,
                started.group_id.as_ptr(),
                started.group_id.len(),
                reply.as_ptr(),
                reply.len(),
                c_bob.as_ptr(),
            ))
            .expect("alice reads the reply"),
            b"hi alice"
        );
    }

    /// **SPEC-061 task 7.2 — the self thread of a single-device owner.**
    ///
    /// Retiring the `self.local` companion credential makes the self
    /// thread a conversation whose members are the owner's own devices.
    /// An owner with one device therefore has a conversation with one
    /// member, which no establishment export could express: they all
    /// take a peer `KeyPackage`, and the only one a lone device holds
    /// is its own — a duplicate member under the task 3.3 identity.
    ///
    /// Before this export existed the closest a lone device could get
    /// was to consume its own package, which answers:
    ///
    /// ```text
    /// commit: duplicate signature key, hpke key or identity found at
    /// index 0
    /// ```
    ///
    /// Asserted here through the FFI boundary specifically, because the
    /// buffer contract is where an export with an intentionally EMPTY
    /// welcome could go wrong: the caller still frees three buffers.
    #[test]
    fn a_lone_device_establishes_its_own_thread() {
        let alice = engine(ALICE, 0x41, "alice-only", true);
        let c_alice = CString::new(ALICE).unwrap();

        let started = take_start(airdress_mls_start_group_solo(
            alice.id,
            b"note to self".as_ptr(),
            b"note to self".len(),
            c_alice.as_ptr(),
        ))
        .expect("a single-device owner must still have a self thread");

        assert!(
            started.welcome.is_empty(),
            "nobody was added, so there is no Welcome to put on the wire"
        );
        assert!(!started.group_id.is_empty());
        assert!(!started.first_application.is_empty());

        // The group works: the owner keeps writing into it.
        let more = take_bytes(airdress_mls_encrypt_bound(
            alice.id,
            started.group_id.as_ptr(),
            started.group_id.len(),
            b"and another".as_ptr(),
            b"and another".len(),
            c_alice.as_ptr(),
        ))
        .expect("the solo group carries traffic");
        assert!(!more.is_empty());
    }

    /// A solo establishment with no sender is refused, exactly as the
    /// peer form is (FR-17a, D-10). The self lane is not an exemption —
    /// SPEC-054's self thread was the one place a "it is only me
    /// anyway" argument could have been made, and it is wrong: the AAD
    /// binds the sender as well as the group, and an operator relaying
    /// a sibling copy is the party that asserts it.
    #[test]
    fn a_solo_establishment_without_a_sender_is_refused() {
        let alice = engine(ALICE, 0x42, "alice-only-2", true);
        let err = take_start(airdress_mls_start_group_solo(
            alice.id,
            b"note to self".as_ptr(),
            b"note to self".len(),
            std::ptr::null(),
        ))
        .expect_err("a null sender is a caller bug, not an unbound call");
        assert!(err.contains("from_airdress"), "unexpected refusal: {err}");
    }

    /// The unbound export **refuses** past the cutover rather than
    /// establishing an unbound group — the convention the agent lane
    /// (PR #97) and the client's self lane both already follow. A
    /// silent fallback to an empty AAD is indistinguishable on the wire
    /// from an unbound message, which would make the binding
    /// attacker-selectable.
    ///
    /// It refuses *before* consuming the peer's `KeyPackage` or
    /// building a Commit: the peer's package is single-use, and a
    /// refusal that burns one leaves the peer a leaf short for a group
    /// that was never created.
    #[test]
    fn unbound_establishment_is_refused_past_the_cutover() {
        let alice = engine(ALICE, 0x33, "alice-b", true);
        let bob = engine(BOB, 0x34, "bob-b", true);

        let bob_kp = key_package(&bob);
        let err = take_start(airdress_mls_start_group(
            alice.id,
            bob_kp.as_ptr(),
            bob_kp.len(),
            b"hello bob".as_ptr(),
            b"hello bob".len(),
        ))
        .expect_err("an unbound establishment past the cutover must be refused");
        assert!(
            err.contains("must carry their sender binding"),
            "unexpected refusal: {err}"
        );

        // Nothing was created. Alice's state dir holds no group, so
        // the refusal cost the caller nothing to retry from.
        assert!(
            !alice._dir.path().join("groups").exists()
                || std::fs::read_dir(alice._dir.path().join("groups"))
                    .expect("groups dir")
                    .next()
                    .is_none(),
            "the refused establishment left a group on disk"
        );

        // The same call with a binding succeeds against the SAME
        // KeyPackage — proof the refusal did not consume it.
        let c_alice = CString::new(ALICE).unwrap();
        take_start(airdress_mls_start_group_bound(
            alice.id,
            bob_kp.as_ptr(),
            bob_kp.len(),
            b"hello bob".as_ptr(),
            b"hello bob".len(),
            c_alice.as_ptr(),
        ))
        .expect("the bound form succeeds where the unbound one refused");
    }

    /// **AC-11 at the establishment path.** MLS transmits
    /// `authenticated_data` in the clear, so binding the AAD is only
    /// half the mechanism — the receiver must recompute it and compare.
    /// An establishment's first message re-attributed to another
    /// sender, or presented against another group, must fail to decrypt
    /// rather than render under the wrong heading with a valid
    /// signature.
    #[test]
    fn a_misrouted_establishment_message_does_not_decrypt() {
        let alice = engine(ALICE, 0x35, "alice-c", true);
        let bob = engine(BOB, 0x36, "bob-c", true);

        let c_alice = CString::new(ALICE).unwrap();
        let bob_kp = key_package(&bob);
        let started = take_start(airdress_mls_start_group_bound(
            alice.id,
            bob_kp.as_ptr(),
            bob_kp.len(),
            b"hello bob".as_ptr(),
            b"hello bob".len(),
            c_alice.as_ptr(),
        ))
        .expect("establish");
        take_bytes(airdress_mls_process_welcome(
            bob.id,
            started.welcome.as_ptr(),
            started.welcome.len(),
        ))
        .expect("bob joins");

        // A second conversation between the same two airdresses. Under
        // D-10 "re-filed into another conversation" IS "presented
        // against another group", because that is what the receiver
        // files by.
        let other_kp = key_package(&bob);
        let other = take_start(airdress_mls_start_group_bound(
            alice.id,
            other_kp.as_ptr(),
            other_kp.len(),
            b"second thread".as_ptr(),
            b"second thread".len(),
            c_alice.as_ptr(),
        ))
        .expect("a second group");
        take_bytes(airdress_mls_process_welcome(
            bob.id,
            other.welcome.as_ptr(),
            other.welcome.len(),
        ))
        .expect("bob joins the second group");
        assert_ne!(started.group_id, other.group_id);

        take_bytes(airdress_mls_decrypt_bound(
            bob.id,
            other.group_id.as_ptr(),
            other.group_id.len(),
            started.first_application.as_ptr(),
            started.first_application.len(),
            c_alice.as_ptr(),
        ))
        .expect_err("a ciphertext presented against another group must not decrypt");

        // Re-attributed to another sender.
        let c_bob = CString::new(BOB).unwrap();
        let err = take_bytes(airdress_mls_decrypt_bound(
            bob.id,
            started.group_id.as_ptr(),
            started.group_id.len(),
            started.first_application.as_ptr(),
            started.first_application.len(),
            c_bob.as_ptr(),
        ))
        .expect_err("a re-attributed establishment message must not decrypt");
        assert!(
            err.contains("does not belong to this group or sender"),
            "unexpected error: {err}"
        );

        // And an UNBOUND decrypt of it is refused too, so a receiver
        // cannot sidestep the comparison by dropping the binding.
        take_bytes(airdress_mls_decrypt(
            bob.id,
            started.group_id.as_ptr(),
            started.group_id.len(),
            started.first_application.as_ptr(),
            started.first_application.len(),
        ))
        .expect_err("an unbound decrypt past the cutover must be refused");

        // The honest binding still works after all three rejections —
        // no rejection ratcheted the group forward behind the caller.
        assert_eq!(
            take_bytes(airdress_mls_decrypt_bound(
                bob.id,
                started.group_id.as_ptr(),
                started.group_id.len(),
                started.first_application.as_ptr(),
                started.first_application.len(),
                c_alice.as_ptr(),
            ))
            .expect("the correctly bound decrypt still works"),
            b"hello bob"
        );
    }

    /// Back-compat: before the cutover the unbound export is still the
    /// right call and still works, AAD empty on both sides.
    #[test]
    fn unbound_establishment_still_works_before_the_cutover() {
        let alice = engine(ALICE, 0x37, "alice-d", false);
        let bob = engine(BOB, 0x38, "bob-d", false);

        let bob_kp = key_package(&bob);
        let started = take_start(airdress_mls_start_group(
            alice.id,
            bob_kp.as_ptr(),
            bob_kp.len(),
            b"hello bob".as_ptr(),
            b"hello bob".len(),
        ))
        .expect("pre-cutover establishment is unchanged");
        take_bytes(airdress_mls_process_welcome(
            bob.id,
            started.welcome.as_ptr(),
            started.welcome.len(),
        ))
        .expect("bob joins");
        assert_eq!(
            take_bytes(airdress_mls_decrypt(
                bob.id,
                started.group_id.as_ptr(),
                started.group_id.len(),
                started.first_application.as_ptr(),
                started.first_application.len(),
            ))
            .expect("unbound decrypt"),
            b"hello bob"
        );
    }

    /// A null sender on a bound export is a caller bug, not an unbound
    /// call. D-10 removed the other half of the old "supplied by
    /// halves" rule with the conversation id itself; this is what is
    /// left of it, and it still has to be an error rather than a
    /// silently empty AAD.
    #[test]
    fn a_missing_sender_is_rejected_at_the_boundary() {
        let alice = engine(ALICE, 0x39, "alice-e", true);
        let bob = engine(BOB, 0x3a, "bob-e", true);
        let bob_kp = key_package(&bob);

        let err = take_start(airdress_mls_start_group_bound(
            alice.id,
            bob_kp.as_ptr(),
            bob_kp.len(),
            b"hi".as_ptr(),
            b"hi".len(),
            std::ptr::null(),
        ))
        .expect_err("a bound establishment without a sender must be refused");
        assert!(err.contains("from_airdress"), "unexpected error: {err}");

        let err = take_bytes(airdress_mls_encrypt_bound(
            alice.id,
            b"gid".as_ptr(),
            3,
            b"hi".as_ptr(),
            2,
            std::ptr::null(),
        ))
        .expect_err("a bound encrypt without a sender must be refused");
        assert!(err.contains("from_airdress"), "unexpected error: {err}");
    }

    /// **Design D-10, the second half.** The receiver files by the
    /// group it decrypted under, so it has to be able to read that
    /// group off the framing without a key and without a handle. RFC
    /// 9420 puts `group_id` in `PrivateMessage` in the clear; this
    /// export is the client's access to it.
    ///
    /// A Welcome carries none — the group's identity is inside the
    /// encrypted `GroupInfo` — and answers with an error rather than a
    /// guess, because a Welcome is filed by the conversation it was
    /// sent for and that is establishment-time trust, unchanged by
    /// D-10.
    #[test]
    fn the_group_id_is_readable_off_the_framing() {
        let alice = engine(ALICE, 0x3b, "alice-f", true);
        let bob = engine(BOB, 0x3c, "bob-f", true);

        let c_alice = CString::new(ALICE).unwrap();
        let bob_kp = key_package(&bob);
        let started = take_start(airdress_mls_start_group_bound(
            alice.id,
            bob_kp.as_ptr(),
            bob_kp.len(),
            b"hello bob".as_ptr(),
            b"hello bob".len(),
            c_alice.as_ptr(),
        ))
        .expect("establish");

        assert_eq!(
            take_bytes(airdress_mls_message_group_id(
                started.first_application.as_ptr(),
                started.first_application.len(),
            ))
            .expect("an application message names its group in the clear"),
            started.group_id,
            "the framing's group id is the group the receiver must file by"
        );

        take_bytes(airdress_mls_message_group_id(
            started.welcome.as_ptr(),
            started.welcome.len(),
        ))
        .expect_err("a Welcome carries no group id in its framing");

        take_bytes(airdress_mls_message_group_id(
            b"not an mls message".as_ptr(),
            18,
        ))
        .expect_err("garbage is a parse error, not a group id");
    }
}
