//! C-compatible FFI exports for `dart:ffi`.
//!
//! ## Memory contract
//!
//! - `FfiBytes` returned by Rust must be freed by Dart via
//!   `airdress_mls_free_bytes`.
//! - `FfiBytes` passed TO Rust (as arguments) are borrowed — Rust
//!   does not free them.
//! - `handle_id` values are opaque integers. Dart must not fabricate
//!   them; only use values returned by `airdress_mls_create_engine`.

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

/// Create a new MLS engine for `airdress`. Returns a handle ID + public key.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_create_engine(airdress: *const c_char) -> FfiHandleResult {
    let airdress = unsafe { CStr::from_ptr(airdress) }
        .to_str()
        .unwrap_or("unknown");
    match MlsEngine::new(airdress) {
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
        Err(msg) => {
            let c_str = std::ffi::CString::new(msg).unwrap_or_default();
            FfiHandleResult {
                handle_id: 0,
                public_key_ptr: std::ptr::null_mut(),
                public_key_len: 0,
                error: c_str.into_raw(),
            }
        }
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
