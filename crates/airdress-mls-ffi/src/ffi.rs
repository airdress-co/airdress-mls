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

use super::engine::MlsEngine;

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

    match engine.start_group(peer_kp, first_msg) {
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
        Some(engine) => match engine.encrypt(group_id, plaintext) {
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
        Some(engine) => match engine.decrypt(group_id, message) {
            Ok(bytes) => FfiBytes::ok(bytes),
            Err(e) => FfiBytes::err(e),
        },
        None => FfiBytes::err("invalid handle".into()),
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
