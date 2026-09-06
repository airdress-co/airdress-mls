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

use super::binding::MessageBinding;
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

/// Start a group with a peer's KeyPackage.
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

    let mut guard = ENGINES.lock().expect("poisoned");
    let engine = match guard.get_mut(&handle_id) {
        Some(e) => e,
        None => return ffi_start_group_err("invalid handle"),
    };

    match engine.start_group(peer_kp, first_msg, None) {
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
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.encrypt(group_id, plaintext, None) {
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
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.decrypt(group_id, message, None) {
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

/// Borrow the optional AAD binding arguments (SPEC-061 FR-17a).
///
/// Both null means "no binding", which is legal only while the engine
/// is pre-cutover; the engine refuses it afterwards rather than
/// silently falling back to an empty AAD.
///
/// # Safety
///
/// `conversation_id` must point at `conversation_id_len` readable
/// bytes when non-null; `from_airdress` must be a NUL-terminated
/// UTF-8 string when non-null.
unsafe fn borrow_binding<'a>(
    conversation_id: *const u8,
    conversation_id_len: usize,
    from_airdress: *const c_char,
) -> Result<Option<MessageBinding<'a>>, String> {
    if conversation_id.is_null() && from_airdress.is_null() {
        return Ok(None);
    }
    if conversation_id.is_null() || from_airdress.is_null() {
        return Err("a message binding needs both conversation_id and from_airdress".to_owned());
    }
    if conversation_id_len != 16 {
        return Err(format!(
            "conversation_id must be 16 raw bytes, got {conversation_id_len}"
        ));
    }
    let conv: [u8; 16] = unsafe { std::slice::from_raw_parts(conversation_id, 16) }
        .try_into()
        .map_err(|_| "conversation_id length error".to_owned())?;
    let airdress = required_str(from_airdress, "from_airdress")?;
    Ok(Some(MessageBinding::new(conv, airdress)))
}

/// Encrypt with the SPEC-061 FR-17a conversation binding.
///
/// `airdress_mls_encrypt` stays as the unbound form so a pre-cutover
/// client keeps working unchanged; this is the symbol the client moves
/// to at cutover. Pass a 16-byte raw `conversation_id` and the sending
/// airdress.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_encrypt_bound(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    conversation_id_ptr: *const u8,
    conversation_id_len: usize,
    from_airdress: *const c_char,
) -> FfiBytes {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let plaintext = unsafe { std::slice::from_raw_parts(plaintext_ptr, plaintext_len) };
    let binding =
        match unsafe { borrow_binding(conversation_id_ptr, conversation_id_len, from_airdress) } {
            Ok(b) => b,
            Err(e) => return FfiBytes::err(e),
        };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.encrypt(group_id, plaintext, binding) {
            Ok(bytes) => FfiBytes::ok(bytes),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Decrypt with the SPEC-061 FR-17a conversation binding. The
/// counterpart to `airdress_mls_encrypt_bound`; the binding is
/// computed from the envelope's cleartext columns before the call.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_decrypt_bound(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    conversation_id_ptr: *const u8,
    conversation_id_len: usize,
    from_airdress: *const c_char,
) -> FfiBytes {
    let group_id = unsafe { std::slice::from_raw_parts(group_id_ptr, group_id_len) };
    let message = unsafe { std::slice::from_raw_parts(message_ptr, message_len) };
    let binding =
        match unsafe { borrow_binding(conversation_id_ptr, conversation_id_len, from_airdress) } {
            Ok(b) => b,
            Err(e) => return FfiBytes::err(e),
        };
    let mut guard = ENGINES.lock().expect("poisoned");
    match guard.get_mut(&handle_id) {
        Some(engine) => match engine.decrypt(group_id, message, binding) {
            Ok(bytes) => FfiBytes::ok(bytes),
            Err(e) => FfiBytes::err(e.to_string()),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Propose adding a member from its published KeyPackage (FR-3).
/// Returns the bare proposal message to publish.
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
            Ok(bytes) => FfiBytes::ok(bytes),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Propose removing the leaf at `leaf_index` (FR-2). Refused when the
/// leaf belongs to another airdress (FR-25).
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
            Ok(bytes) => FfiBytes::ok(bytes),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
    }
}

/// Propose replacing this device's own leaf key (FR-1).
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
