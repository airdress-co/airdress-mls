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
//!
//! ## Error codes
//!
//! Every non-null `error` string has a stable code, read with
//! `airdress_mls_error_code(error)` before the string is freed. The
//! values are [`ErrorCode`]'s and never change; branch on them, never on
//! the message. `5` (`EpochUnavailable`) is the trimmed-epoch case whose
//! message reads "this message is older than the keys still on this
//! device". The result structs are unchanged: a field would have moved
//! every byte of `FfiBytesList` under apps already in the field.
//!
//! ## Safety contract
//!
//! Every `unsafe extern "C"` function below relies on its caller — the
//! Dart bindings in airdress-chat (`lib/ffi/mls_bindings.dart`) and the
//! tests in this file — for the same five things. Each function's own
//! `# Safety` section names which of its arguments they apply to.
//!
//! 1. **Byte inputs.** A `(ptr, len)` input is null with `len == 0` (an
//!    empty input), or points to `len` initialised bytes that stay valid
//!    and are not written for the duration of the call. The library only
//!    borrows inputs: the Dart side `calloc`s them, and frees them after
//!    the call returns. A null pointer with a non-zero length, and a
//!    length above `isize::MAX`, are refused with an error rather than
//!    trusted.
//! 2. **String inputs.** A `*const c_char` input is null (refused with an
//!    error) or points to a NUL-terminated string that stays valid and
//!    unwritten for the call (Dart's `toNativeUtf8`). Invalid UTF-8 is
//!    refused.
//! 3. **Results.** Every pointer in a returned struct (`FfiBytes`,
//!    `FfiBytesList`, `FfiStartGroupResult`, `FfiCommitResult`,
//!    `FfiHandleResult`) was allocated by Rust and goes back to the
//!    matching `airdress_mls_free_*` export exactly once, with its length
//!    unchanged — never to the C allocator's `free`.
//! 4. **Callbacks.** A lookup callback is a function pointer that stays
//!    callable until the engine it was registered on is destroyed or the
//!    callback is replaced. It is invoked synchronously, on the thread
//!    that made the engine call, while that call is in progress: the Dart
//!    side's `NativeCallable.isolateLocal` requires exactly this, so the
//!    caller must only call into an engine from the isolate that
//!    registered its callbacks. A callback must not call back into this
//!    library, and must not unwind.
//! 5. **Threads.** Engines live in one table behind one lock, so any
//!    export may be called from any thread; a call blocks while another
//!    is running.
//!
//! Every export runs its body under `catch_unwind`: a Rust panic —
//! a bug here, or one inside `mls-rs` on hostile input — becomes an
//! error result instead of unwinding into Dart, which would abort the
//! app. A panic that happens while the engine table is locked poisons
//! the lock; [`engines`] recovers it rather than failing every later
//! call.

use std::any::Any;
use std::collections::HashMap;
use std::ffi::CStr;
use std::os::raw::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};

use airdress_mls::engine::{CommitOutcome, EngineError, ErrorCode, MlsEngine};

// ---------------------------------------------------------------------------
// Handle table
// ---------------------------------------------------------------------------

static NEXT_ID: AtomicU64 = AtomicU64::new(1);
static ENGINES: std::sync::LazyLock<Mutex<HashMap<u64, MlsEngine>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// The engine table, recovering it if a caught panic poisoned it.
///
/// A panic inside an engine operation unwinds through the guard and
/// poisons the mutex. Before, every later call then failed `expect`
/// inside an `extern "C"` function, which aborts the process — and
/// would again on every relaunch that reached the same state. The table
/// itself is a `HashMap` that no engine operation mutates (inserts and
/// removes happen in the create and destroy exports, which do not call
/// into an engine while doing so), so it is never left half-written; the
/// engine that panicked keeps the state its own operation left it in,
/// which is the state an error return leaves it in too.
fn engines() -> MutexGuard<'static, HashMap<u64, MlsEngine>> {
    ENGINES.lock().unwrap_or_else(|poisoned| {
        ENGINES.clear_poison();
        poisoned.into_inner()
    })
}

/// Run `f` on the engine named by `handle_id`, or `missing()` when no
/// such engine exists.
fn with_engine<T>(
    handle_id: u64,
    missing: impl FnOnce() -> T,
    f: impl FnOnce(&mut MlsEngine) -> T,
) -> T {
    let mut table = engines();
    #[cfg(test)]
    tests::maybe_inject_panic();
    match table.get_mut(&handle_id) {
        Some(engine) => f(engine),
        None => missing(),
    }
}

/// The error a caught panic becomes.
fn panic_error(payload: &(dyn Any + Send)) -> FfiError {
    let detail = payload
        .downcast_ref::<&str>()
        .map(|s| (*s).to_owned())
        .or_else(|| payload.downcast_ref::<String>().cloned())
        .unwrap_or_else(|| "no message".to_owned());
    FfiError::new(
        ErrorCode::Internal,
        format!("internal error in airdress-mls (a panic was caught): {detail}"),
    )
}

/// Run an export's body, turning a panic into `on_panic(message)`.
///
/// `AssertUnwindSafe` is sound here because nothing the closure borrows
/// is observed after a panic except through [`engines`], whose
/// recovery is argued there.
fn guarded<T>(on_panic: impl FnOnce(FfiError) -> T, body: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|payload| on_panic(panic_error(&*payload)))
}

// ---------------------------------------------------------------------------
// Argument checks
// ---------------------------------------------------------------------------

/// Borrow a `(ptr, len)` byte input.
///
/// Null with `len == 0` is the empty input (Dart may hand over a null
/// pointer for an empty `calloc`); null with any other length is an
/// error, and so is a length no allocation can have.
///
/// # Safety
///
/// `ptr` is null, or points to `len` initialised bytes that stay valid
/// and are not written for `'a` (contract 1).
unsafe fn borrowed<'a>(ptr: *const u8, len: usize, name: &str) -> Result<&'a [u8], FfiError> {
    if ptr.is_null() {
        return if len == 0 {
            Ok(&[])
        } else {
            Err(FfiError::invalid_argument(format!(
                "{name} is null with a length of {len}"
            )))
        };
    }
    // No allocation is larger than `isize::MAX` bytes, so such a length is
    // the caller's mistake; `from_raw_parts` would be undefined behaviour
    // (and a process abort in a debug build) rather than an error.
    if isize::try_from(len).is_err() {
        return Err(FfiError::invalid_argument(format!(
            "{name} has an impossible length {len}"
        )));
    }
    // SAFETY: `ptr` is non-null; the caller guarantees it points to `len`
    // initialised bytes that live and stay unwritten for `'a`; `u8` needs
    // no alignment; and `len <= isize::MAX` was checked above.
    Ok(unsafe { std::slice::from_raw_parts(ptr, len) })
}

/// Borrow a required C string argument, rejecting null and invalid UTF-8.
///
/// # Safety
///
/// `ptr` is null, or points to a NUL-terminated string that stays valid
/// and unwritten for `'a` (contract 2).
unsafe fn required_str<'a>(ptr: *const c_char, name: &str) -> Result<&'a str, FfiError> {
    if ptr.is_null() {
        return Err(FfiError::invalid_argument(format!("{name} is null")));
    }
    // SAFETY: `ptr` is non-null and, per the caller's contract, points to
    // a NUL-terminated string valid and unwritten for `'a`.
    unsafe { CStr::from_ptr(ptr) }
        .to_str()
        .map_err(|e| FfiError::invalid_argument(format!("{name} is not valid UTF-8: {e}")))
}

/// Copy a required 32-byte argument, rejecting null and wrong lengths.
///
/// The copy is the caller's to zeroize when it holds a secret.
///
/// # Safety
///
/// As [`borrowed`]: `ptr` is null, or points to `len` initialised bytes
/// valid and unwritten for the call (contract 1).
unsafe fn required_key32(ptr: *const u8, len: usize, name: &str) -> Result<[u8; 32], FfiError> {
    if ptr.is_null() {
        return Err(FfiError::invalid_argument(format!("{name} is null")));
    }
    if len != 32 {
        return Err(FfiError::invalid_argument(format!(
            "{name} must be 32 bytes, got {len}"
        )));
    }
    // SAFETY: forwarded from this function's own contract.
    let slice = unsafe { borrowed(ptr, len, name) }?;
    slice
        .try_into()
        .map_err(|e| FfiError::invalid_argument(format!("{name} length error: {e}")))
}

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

/// Hand an owned buffer to the caller: a pointer `airdress_mls_free_bytes`
/// turns back into this `Box<[u8]>`, and its length.
///
/// An empty buffer gives a dangling, non-null pointer and length 0, which
/// the free export skips.
fn into_raw_bytes(data: Vec<u8>) -> (*mut u8, usize) {
    let boxed = data.into_boxed_slice();
    let len = boxed.len();
    (Box::into_raw(boxed).cast::<u8>(), len)
}

/// An owned C string for an `error` field, freed by
/// `airdress_mls_free_error`, with its code recorded for
/// `airdress_mls_error_code`. A message with an interior NUL becomes the
/// empty string, which is still a non-null error.
fn into_raw_error(error: &FfiError) -> *mut c_char {
    let raw = std::ffi::CString::new(error.message.as_str())
        .unwrap_or_default()
        .into_raw();
    error_codes().insert(raw as usize, error.code.as_i32());
    raw
}

/// Error strings this library has handed out and not yet had back,
/// keyed by address, with their codes.
///
/// A side table rather than a field: `FfiBytes` is returned by value
/// and laid out in arrays (`FfiBytesList`), so a new field would change
/// its size under every app already in the field. The address of a live
/// allocation is unique, and an entry leaves the table when its string
/// is freed, before the allocator can hand the address out again.
static ERROR_CODES: std::sync::LazyLock<Mutex<HashMap<usize, i32>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// The error-code table, recovered if a panic poisoned it (as
/// [`engines`]; nothing panics while holding it).
fn error_codes() -> MutexGuard<'static, HashMap<usize, i32>> {
    ERROR_CODES.lock().unwrap_or_else(|poisoned| {
        ERROR_CODES.clear_poison();
        poisoned.into_inner()
    })
}

/// An error on its way across the boundary: a stable code for the
/// caller to branch on and a sentence for a person or a journal.
#[derive(Debug)]
struct FfiError {
    code: ErrorCode,
    message: String,
}

impl FfiError {
    fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }

    fn invalid_argument(message: String) -> Self {
        Self::new(ErrorCode::InvalidArgument, message)
    }

    fn invalid_handle() -> Self {
        Self::new(ErrorCode::InvalidHandle, "invalid handle")
    }

    /// The unbound exports' post-cutover refusal.
    fn binding_required() -> Self {
        Self::new(ErrorCode::BindingRequired, UNBOUND_PAST_CUTOVER)
    }
}

/// An engine operation's `String` error: no code of its own.
impl From<String> for FfiError {
    fn from(message: String) -> Self {
        Self::new(ErrorCode::Engine, message)
    }
}

/// An engine error keeps its own code, so `EpochUnavailable` is
/// distinguishable across the boundary without reading the sentence.
impl From<EngineError> for FfiError {
    fn from(error: EngineError) -> Self {
        Self::new(error.code(), error.to_string())
    }
}

impl FfiBytes {
    fn ok(data: Vec<u8>) -> Self {
        let (ptr, len) = into_raw_bytes(data);
        Self {
            ptr,
            len,
            error: std::ptr::null_mut(),
        }
    }

    fn err(error: impl Into<FfiError>) -> Self {
        Self {
            ptr: std::ptr::null_mut(),
            len: 0,
            error: into_raw_error(&error.into()),
        }
    }

    fn from_result<E: Into<FfiError>>(result: Result<Vec<u8>, E>) -> Self {
        match result {
            Ok(data) => Self::ok(data),
            Err(e) => Self::err(e),
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

/// What an `i32`-returning export answers when its body panicked. Every
/// such export documents `0` as success, so the Dart side's `!= 0` and
/// `< 0` checks treat it as a failure.
const PANIC_I32: i32 = -3;

/// What an `i64`-returning export answers when its body panicked: `-2`,
/// the generic failure those exports already document, because the Dart
/// side checks for `-1` and `-2` by value and would read any other
/// negative number as a count or an epoch.
const PANIC_I64: i64 = -2;

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

fn ffi_handle_err(error: impl Into<FfiError>) -> FfiHandleResult {
    FfiHandleResult {
        handle_id: 0,
        public_key_ptr: std::ptr::null_mut(),
        public_key_len: 0,
        error: into_raw_error(&error.into()),
    }
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
///
/// # Safety
///
/// `(session_seed, session_seed_len)`, `(root_pubkey, root_pubkey_len)`
/// and `(state_key, state_key_len)` are byte inputs (contract 1);
/// `airdress`, `delegation_json` and `state_dir` are string inputs
/// (contract 2). The result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_create_engine_from_seed(
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
    guarded(ffi_handle_err, || {
        let parsed = (|| -> Result<MlsEngine, FfiError> {
            // SAFETY: each pointer is an input of the kind this
            // function's `# Safety` names.
            let (airdress, root, delegation, state_dir) = unsafe {
                (
                    required_str(airdress, "airdress")?,
                    required_key32(root_pubkey, root_pubkey_len, "root_pubkey")?,
                    required_str(delegation_json, "delegation_json")?,
                    required_str(state_dir, "state_dir")?,
                )
            };
            // The two secrets are copied onto the stack by the checks,
            // so both copies are zeroized however the build ends.
            // SAFETY: a byte input (contract 1).
            let seed = zeroize::Zeroizing::new(unsafe {
                required_key32(session_seed, session_seed_len, "session_seed")
            }?);
            // SAFETY: a byte input (contract 1).
            let key = zeroize::Zeroizing::new(unsafe {
                required_key32(state_key, state_key_len, "state_key")
            }?);
            Ok(MlsEngine::from_seed(
                airdress, &seed, &root, delegation, state_dir, &key,
            )?)
        })();

        match parsed {
            Ok(engine) => {
                let (public_key_ptr, public_key_len) = into_raw_bytes(engine.public_key().to_vec());
                let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
                engines().insert(id, engine);
                FfiHandleResult {
                    handle_id: id,
                    public_key_ptr,
                    public_key_len,
                    error: std::ptr::null_mut(),
                }
            }
            Err(e) => ffi_handle_err(e),
        }
    })
}

/// Host-supplied root-key cache callback.
///
/// Called with a pin subject (NUL-terminated UTF-8) and a 32-byte
/// output buffer. The subject is the peer's bare airdress for an
/// owner's leaf, and `airdress ‖ 0x1F ‖ person_id` for the leaf of
/// another person of that airdress (a `v: 3` credential), whose root is
/// their own. The host returns 1 after filling the buffer with the root
/// public key its cache holds for that subject (24h TTL, populated at
/// first contact), or 0 when it has none — which rejects the peer's
/// leaf. A host that does not resolve person roots returns 0 for any
/// subject containing 0x1F. The callback must be thread-safe and must
/// not call back into this library.
pub type AirdressRootKeyLookupFn =
    extern "C" fn(airdress: *const c_char, out_root_public_key: *mut u8) -> i32;

struct CallbackRootKeyLookup(AirdressRootKeyLookupFn);

impl airdress_mls::credential::RootKeyLookup for CallbackRootKeyLookup {
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
/// -1 for an invalid handle or a null callback, -3 on an internal error.
///
/// # Safety
///
/// `lookup` is null (refused) or a callback under contract 4.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_set_root_key_lookup(
    handle_id: u64,
    lookup: Option<AirdressRootKeyLookupFn>,
) -> i32 {
    guarded(
        |_| PANIC_I32,
        || {
            let Some(lookup) = lookup else { return -1 };
            with_engine(
                handle_id,
                || -1,
                |engine| {
                    engine.set_root_key_lookup(std::sync::Arc::new(CallbackRootKeyLookup(lookup)));
                    0
                },
            )
        },
    )
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

impl airdress_mls::credential::RevocationLookup for CallbackRevocationLookup {
    fn device_status(&self, device_id: &str) -> Option<airdress_mls::credential::DeviceStatus> {
        let c_device_id = std::ffi::CString::new(device_id).ok()?;
        match (self.0)(c_device_id.as_ptr()) {
            1 => Some(airdress_mls::credential::DeviceStatus::Active),
            0 => Some(airdress_mls::credential::DeviceStatus::Revoked),
            // Unknown answers are "cannot answer", not "fine" — the
            // caller gets RevocationUnavailable, which is a reject.
            _ => None,
        }
    }
}

/// Register the host's device-revocation state (SPEC-061 FR-19).
/// Returns 0 on success, -1 for an invalid handle or a null callback,
/// -3 on an internal error.
///
/// **Required past the v2 cutover.** An engine that has entered
/// `airdress_mls_set_v2_cutover` refuses every leaf
/// (`device revocation state unavailable`) until this is registered:
/// the two switches are coupled, in either order (fail closed, since
/// 0.3.0; before, check 5 was silently skipped).
///
/// # Safety
///
/// `lookup` is null (refused) or a callback under contract 4.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_set_revocation_lookup(
    handle_id: u64,
    lookup: Option<AirdressRevocationLookupFn>,
) -> i32 {
    guarded(
        |_| PANIC_I32,
        || {
            let Some(lookup) = lookup else { return -1 };
            with_engine(
                handle_id,
                || -1,
                |engine| {
                    engine.set_revocation_lookup(std::sync::Arc::new(CallbackRevocationLookup(
                        lookup,
                    )));
                    0
                },
            )
        },
    )
}

/// Enter the SPEC-061 v2 credential cutover (FR-20): `v: 1`
/// identities stop being accepted and the per-device member identity
/// becomes the only form in the tree. One-way within the process, per
/// NFR-15 — there is no symmetric "unset" export, deliberately.
///
/// **Couples to `airdress_mls_set_revocation_lookup`.** Past the cutover
/// no leaf verifies until a revocation lookup is registered on this
/// engine — before or after this call — so a host that enters the
/// cutover must register one (fail closed, since 0.3.0).
///
/// Returns 0 on success, -1 for an invalid handle, -3 on an internal
/// error.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_set_v2_cutover(handle_id: u64) -> i32 {
    guarded(
        |_| PANIC_I32,
        || {
            with_engine(
                handle_id,
                || -1,
                |engine| {
                    engine.set_v2_cutover();
                    0
                },
            )
        },
    )
}

/// Whether the v2 cutover has been entered on this engine. Returns 1
/// for yes, 0 for no, -1 for an invalid handle, -3 on an internal error.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_is_v2_cutover(handle_id: u64) -> i32 {
    guarded(
        |_| PANIC_I32,
        || with_engine(handle_id, || -1, |engine| i32::from(engine.is_v2_cutover())),
    )
}

/// Destroy an MLS engine and free its resources.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_destroy_engine(handle_id: u64) {
    // Taken out under the lock and dropped after it, so a panic in an
    // engine's `Drop` (there is none today) cannot poison the table.
    let removed = guarded(|_| None, || engines().remove(&handle_id));
    guarded(|_| (), move || drop(removed));
}

/// Generate a serialized KeyPackage.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_generate_key_package(handle_id: u64) -> FfiBytes {
    guarded(FfiBytes::err, || {
        with_engine(
            handle_id,
            || FfiBytes::err(FfiError::invalid_handle()),
            |engine| FfiBytes::from_result(engine.generate_key_package()),
        )
    })
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
        let items: Box<[FfiBytes]> = buffers.into_iter().map(FfiBytes::ok).collect();
        let len = items.len();
        Self {
            items: Box::into_raw(items).cast::<FfiBytes>(),
            len,
            error: std::ptr::null_mut(),
        }
    }

    fn err(error: impl Into<FfiError>) -> Self {
        Self {
            items: std::ptr::null_mut(),
            len: 0,
            error: into_raw_error(&error.into()),
        }
    }

    fn from_result<E: Into<FfiError>>(result: Result<Vec<Vec<u8>>, E>) -> Self {
        match result {
            Ok(buffers) => Self::ok(buffers),
            Err(e) => Self::err(e),
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
    guarded(FfiBytesList::err, || {
        with_engine(
            handle_id,
            || FfiBytesList::err(FfiError::invalid_handle()),
            |engine| FfiBytesList::from_result(engine.generate_key_packages(count)),
        )
    })
}

/// The publishable public messages of every unconsumed KeyPackage in
/// the pool — for first publish and for re-publish after a restart.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_stored_key_packages(handle_id: u64) -> FfiBytesList {
    guarded(FfiBytesList::err, || {
        with_engine(
            handle_id,
            || FfiBytesList::err(FfiError::invalid_handle()),
            |engine| FfiBytesList::from_result(engine.stored_key_packages()),
        )
    })
}

/// Number of unconsumed KeyPackage private halves in the pool.
/// Returns -1 for an invalid handle, -2 on a storage error or an
/// internal error.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_key_package_pool_count(handle_id: u64) -> i64 {
    guarded(
        |_| PANIC_I64,
        || {
            with_engine(
                handle_id,
                || -1,
                |engine| match engine.key_package_pool_count() {
                    Ok(count) => i64::try_from(count).unwrap_or(i64::MAX),
                    Err(_) => -2,
                },
            )
        },
    )
}

/// Free a byte-buffer list previously returned by
/// `airdress_mls_generate_key_packages` or
/// `airdress_mls_stored_key_packages` (frees each buffer, each
/// per-item error, and the list itself).
///
/// # Safety
///
/// `list` must have been returned by a Rust FFI function in this
/// crate, unchanged, and must not have been freed before (contract 3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_free_bytes_list(list: FfiBytesList) {
    guarded(
        |_| (),
        || {
            if !list.items.is_null() && list.len > 0 {
                // SAFETY: a non-empty list's `items` is the pointer
                // `FfiBytesList::ok` made from a `Box<[FfiBytes]>` of exactly
                // `len` items; rebuilding that fat pointer returns it to the
                // allocator that made it, once (the caller's contract).
                let items = unsafe {
                    Box::from_raw(std::ptr::slice_from_raw_parts_mut(list.items, list.len))
                };
                for item in items {
                    // SAFETY: each item was built by `FfiBytes::ok`, so its
                    // buffer and its (null) error are this crate's, and they
                    // are freed once, with the list.
                    unsafe {
                        airdress_mls_free_bytes(item.ptr, item.len);
                        airdress_mls_free_error(item.error);
                    }
                }
            }
            // SAFETY: the list's error is null or this crate's, freed once.
            unsafe { airdress_mls_free_error(list.error) };
        },
    );
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
///
/// # Safety
///
/// `(peer_kp_ptr, peer_kp_len)` and `(first_msg_ptr, first_msg_len)` are
/// byte inputs (contract 1). The result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_start_group(
    handle_id: u64,
    peer_kp_ptr: *const u8,
    peer_kp_len: usize,
    first_msg_ptr: *const u8,
    first_msg_len: usize,
) -> FfiStartGroupResult {
    guarded(ffi_start_group_err, || {
        // SAFETY: two byte inputs (contract 1), per `# Safety`.
        let inputs = unsafe {
            borrowed(peer_kp_ptr, peer_kp_len, "peer_kp")
                .and_then(|kp| Ok((kp, borrowed(first_msg_ptr, first_msg_len, "first_msg")?)))
        };
        match inputs {
            Ok((peer_kp, first_msg)) => start_group_into_ffi(handle_id, peer_kp, first_msg, None),
            Err(e) => ffi_start_group_err(e),
        }
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
///
/// # Safety
///
/// `(peer_kp_ptr, peer_kp_len)` and `(first_msg_ptr, first_msg_len)` are
/// byte inputs (contract 1); `from_airdress` is a string input
/// (contract 2). The result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_start_group_bound(
    handle_id: u64,
    peer_kp_ptr: *const u8,
    peer_kp_len: usize,
    first_msg_ptr: *const u8,
    first_msg_len: usize,
    from_airdress: *const c_char,
) -> FfiStartGroupResult {
    guarded(ffi_start_group_err, || {
        // SAFETY: two byte inputs (contract 1) and a string input
        // (contract 2), per `# Safety`.
        let inputs = unsafe {
            (|| -> Result<_, FfiError> {
                Ok((
                    borrowed(peer_kp_ptr, peer_kp_len, "peer_kp")?,
                    borrowed(first_msg_ptr, first_msg_len, "first_msg")?,
                    required_str(from_airdress, "from_airdress")?,
                ))
            })()
        };
        match inputs {
            Ok((peer_kp, first_msg, airdress)) => {
                start_group_into_ffi(handle_id, peer_kp, first_msg, Some(airdress))
            }
            Err(e) => ffi_start_group_err(e),
        }
    })
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
///
/// # Safety
///
/// `(first_msg_ptr, first_msg_len)` is a byte input (contract 1);
/// `from_airdress` is a string input (contract 2). The result is freed
/// per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_start_group_solo(
    handle_id: u64,
    first_msg_ptr: *const u8,
    first_msg_len: usize,
    from_airdress: *const c_char,
) -> FfiStartGroupResult {
    guarded(ffi_start_group_err, || {
        // SAFETY: a byte input (contract 1) and a string input
        // (contract 2), per `# Safety`.
        let inputs = unsafe {
            borrowed(first_msg_ptr, first_msg_len, "first_msg")
                .and_then(|msg| Ok((msg, required_str(from_airdress, "from_airdress")?)))
        };
        let (first_msg, airdress) = match inputs {
            Ok(inputs) => inputs,
            Err(e) => return ffi_start_group_err(e),
        };
        with_engine(
            handle_id,
            || ffi_start_group_err(FfiError::invalid_handle()),
            |engine| marshal_start_group(engine.start_group_solo(first_msg, airdress)),
        )
    })
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
    with_engine(
        handle_id,
        || ffi_start_group_err(FfiError::invalid_handle()),
        |engine| {
            let from_airdress = match from_airdress {
                Some(a) => a,
                None if engine.is_v2_cutover() => {
                    return ffi_start_group_err(FfiError::binding_required());
                }
                // Pre-cutover the AAD is empty regardless, so the value is
                // never read. Naming it here keeps the unbound export
                // working unchanged rather than giving it a second code
                // path.
                None => "",
            };
            marshal_start_group(engine.start_group(peer_kp, first_msg, from_airdress))
        },
    )
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
const UNBOUND_PAST_CUTOVER: &str =
    "application messages must carry their sender binding after the v2 credential cutover";

/// Hand three owned buffers to the caller under the Rust-allocates /
/// Dart-frees contract. Shared by every establishment export so the
/// memory contract exists in exactly one place.
fn marshal_start_group(
    outcome: Result<airdress_mls::engine::StartGroupOutcome, String>,
) -> FfiStartGroupResult {
    match outcome {
        Ok(outcome) => {
            let (group_id_ptr, group_id_len) = into_raw_bytes(outcome.group_id);
            let (welcome_ptr, welcome_len) = into_raw_bytes(outcome.welcome);
            let (first_app_ptr, first_app_len) = into_raw_bytes(outcome.first_application);
            FfiStartGroupResult {
                group_id_ptr,
                group_id_len,
                welcome_ptr,
                welcome_len,
                first_app_ptr,
                first_app_len,
                error: std::ptr::null_mut(),
            }
        }
        Err(e) => ffi_start_group_err(e),
    }
}

/// Process an inbound Welcome. Returns the group ID.
///
/// # Safety
///
/// `(welcome_ptr, welcome_len)` is a byte input (contract 1). The result
/// is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_process_welcome(
    handle_id: u64,
    welcome_ptr: *const u8,
    welcome_len: usize,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        // SAFETY: a byte input (contract 1), per `# Safety`.
        let welcome = match unsafe { borrowed(welcome_ptr, welcome_len, "welcome") } {
            Ok(w) => w,
            Err(e) => return FfiBytes::err(e),
        };
        with_engine(
            handle_id,
            || FfiBytes::err(FfiError::invalid_handle()),
            |engine| FfiBytes::from_result(engine.process_welcome(welcome)),
        )
    })
}

/// Borrow a `(group id, payload)` pair of byte inputs, the shape most
/// group operations take.
///
/// # Safety
///
/// Both pairs are byte inputs (contract 1), valid for `'a`.
unsafe fn group_and_payload<'a>(
    group_id_ptr: *const u8,
    group_id_len: usize,
    payload_ptr: *const u8,
    payload_len: usize,
    payload_name: &str,
) -> Result<(&'a [u8], &'a [u8]), FfiError> {
    // SAFETY: forwarded from this function's own contract.
    unsafe {
        Ok((
            borrowed(group_id_ptr, group_id_len, "group_id")?,
            borrowed(payload_ptr, payload_len, payload_name)?,
        ))
    }
}

/// Encrypt plaintext under an existing group.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` and `(plaintext_ptr, plaintext_len)`
/// are byte inputs (contract 1). The result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_encrypt(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        // SAFETY: two byte inputs (contract 1), per `# Safety`.
        let inputs = unsafe {
            group_and_payload(
                group_id_ptr,
                group_id_len,
                plaintext_ptr,
                plaintext_len,
                "plaintext",
            )
        };
        let (group_id, plaintext) = match inputs {
            Ok(inputs) => inputs,
            Err(e) => return FfiBytes::err(e),
        };
        with_engine(
            handle_id,
            || FfiBytes::err(FfiError::invalid_handle()),
            |engine| {
                if engine.is_v2_cutover() {
                    return FfiBytes::err(FfiError::binding_required());
                }
                FfiBytes::from_result(engine.encrypt(group_id, plaintext, ""))
            },
        )
    })
}

/// Decrypt an inbound application message.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` and `(message_ptr, message_len)` are
/// byte inputs (contract 1). The result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_decrypt(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    message_ptr: *const u8,
    message_len: usize,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        // SAFETY: two byte inputs (contract 1), per `# Safety`.
        let inputs = unsafe {
            group_and_payload(
                group_id_ptr,
                group_id_len,
                message_ptr,
                message_len,
                "message",
            )
        };
        let (group_id, message) = match inputs {
            Ok(inputs) => inputs,
            Err(e) => return FfiBytes::err(e),
        };
        with_engine(
            handle_id,
            || FfiBytes::err(FfiError::invalid_handle()),
            |engine| {
                if engine.is_v2_cutover() {
                    return FfiBytes::err(FfiError::binding_required());
                }
                // SPEC-061 FR-22: the variant is distinguishable in Rust;
                // across the C boundary it is still one sentence, per the
                // `credential.rs` discipline.
                FfiBytes::from_result(
                    engine
                        .decrypt(group_id, message, "")
                        .map_err(FfiError::from),
                )
            },
        )
    })
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

fn ffi_commit_err(error: impl Into<FfiError>) -> FfiCommitResult {
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
        error: into_raw_error(&error.into()),
    }
}

fn ffi_commit_ok(outcome: CommitOutcome) -> FfiCommitResult {
    let (commit_ptr, commit_len) = into_raw_bytes(outcome.commit);
    let (welcome_ptr, welcome_len) = outcome
        .welcome
        .map_or((std::ptr::null_mut(), 0), into_raw_bytes);

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
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` and `(plaintext_ptr, plaintext_len)`
/// are byte inputs (contract 1); `from_airdress` is a string input
/// (contract 2). The result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_encrypt_bound(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    plaintext_ptr: *const u8,
    plaintext_len: usize,
    from_airdress: *const c_char,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        // SAFETY: two byte inputs (contract 1) and a string input
        // (contract 2), per `# Safety`.
        let inputs = unsafe {
            group_and_payload(
                group_id_ptr,
                group_id_len,
                plaintext_ptr,
                plaintext_len,
                "plaintext",
            )
            .and_then(|(g, p)| Ok((g, p, required_str(from_airdress, "from_airdress")?)))
        };
        let (group_id, plaintext, airdress) = match inputs {
            Ok(inputs) => inputs,
            Err(e) => return FfiBytes::err(e),
        };
        with_engine(
            handle_id,
            || FfiBytes::err(FfiError::invalid_handle()),
            |engine| FfiBytes::from_result(engine.encrypt(group_id, plaintext, airdress)),
        )
    })
}

/// Decrypt with the SPEC-061 FR-17a binding. The counterpart to
/// `airdress_mls_encrypt_bound`: the sender comes from the envelope's
/// cleartext `from` column and the group from the framing, so the AAD
/// is computable before the decrypt.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` and `(message_ptr, message_len)` are
/// byte inputs (contract 1); `from_airdress` is a string input
/// (contract 2). The result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_decrypt_bound(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    message_ptr: *const u8,
    message_len: usize,
    from_airdress: *const c_char,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        // SAFETY: two byte inputs (contract 1) and a string input
        // (contract 2), per `# Safety`.
        let inputs = unsafe {
            group_and_payload(
                group_id_ptr,
                group_id_len,
                message_ptr,
                message_len,
                "message",
            )
            .and_then(|(g, m)| Ok((g, m, required_str(from_airdress, "from_airdress")?)))
        };
        let (group_id, message, airdress) = match inputs {
            Ok(inputs) => inputs,
            Err(e) => return FfiBytes::err(e),
        };
        with_engine(
            handle_id,
            || FfiBytes::err(FfiError::invalid_handle()),
            |engine| {
                FfiBytes::from_result(
                    engine
                        .decrypt(group_id, message, airdress)
                        .map_err(FfiError::from),
                )
            },
        )
    })
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
///
/// # Safety
///
/// `(message_ptr, message_len)` is a byte input (contract 1). The result
/// is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_message_group_id(
    message_ptr: *const u8,
    message_len: usize,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        // SAFETY: a byte input (contract 1), per `# Safety`.
        let message = match unsafe { borrowed(message_ptr, message_len, "message") } {
            Ok(m) => m,
            Err(e) => return FfiBytes::err(e),
        };
        FfiBytes::from_result(airdress_mls::engine::message_group_id(message))
    })
}

/// Stage an `Add` for the group's next commit (FR-3). Staged by value
/// — the commit built by `airdress_mls_commit_pending` carries it, so
/// no separate proposal message goes on the wire. Returns an empty
/// buffer on success.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` and `(key_package_ptr,
/// key_package_len)` are byte inputs (contract 1). The result is freed
/// per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_propose_add(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    key_package_ptr: *const u8,
    key_package_len: usize,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        // SAFETY: two byte inputs (contract 1), per `# Safety`.
        let inputs = unsafe {
            group_and_payload(
                group_id_ptr,
                group_id_len,
                key_package_ptr,
                key_package_len,
                "key_package",
            )
        };
        let (group_id, kp) = match inputs {
            Ok(inputs) => inputs,
            Err(e) => return FfiBytes::err(e),
        };
        with_engine(
            handle_id,
            || FfiBytes::err(FfiError::invalid_handle()),
            |engine| FfiBytes::from_result(engine.propose_add(group_id, kp).map(|()| Vec::new())),
        )
    })
}

/// Stage a `Remove` of `leaf_index` for the group's next commit
/// (FR-2), by value. Refused when the leaf belongs to another airdress
/// (FR-25), or, once a `v: 3` leaf is involved, to another person of
/// the same airdress, unless it is a `v: 3` leaf whose device the
/// lookup registered with `airdress_mls_set_revocation_lookup` answers
/// revoked (SPEC-144 F-7, FR-53). Returns an empty buffer on success.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` is a byte input (contract 1). The
/// result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_propose_remove(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    leaf_index: u32,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        // SAFETY: a byte input (contract 1), per `# Safety`.
        let group_id = match unsafe { borrowed(group_id_ptr, group_id_len, "group_id") } {
            Ok(g) => g,
            Err(e) => return FfiBytes::err(e),
        };
        with_engine(
            handle_id,
            || FfiBytes::err(FfiError::invalid_handle()),
            |engine| {
                FfiBytes::from_result(
                    engine
                        .propose_remove(group_id, leaf_index)
                        .map(|()| Vec::new()),
                )
            },
        )
    })
}

/// Propose replacing this device's own leaf key (FR-1). Returns the
/// bare proposal for publication — the one operation that must travel
/// by reference, because RFC 9420 forbids a committer from including
/// its own `Update`.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` is a byte input (contract 1). The
/// result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_propose_update(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        // SAFETY: a byte input (contract 1), per `# Safety`.
        let group_id = match unsafe { borrowed(group_id_ptr, group_id_len, "group_id") } {
            Ok(g) => g,
            Err(e) => return FfiBytes::err(e),
        };
        with_engine(
            handle_id,
            || FfiBytes::err(FfiError::invalid_handle()),
            |engine| FfiBytes::from_result(engine.propose_update(group_id)),
        )
    })
}

/// Hold an inbound bare proposal for the next commit (FR-5). Returns
/// an empty buffer on success.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` and `(message_ptr, message_len)` are
/// byte inputs (contract 1). The result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_process_proposal(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    message_ptr: *const u8,
    message_len: usize,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        // SAFETY: two byte inputs (contract 1), per `# Safety`.
        let inputs = unsafe {
            group_and_payload(
                group_id_ptr,
                group_id_len,
                message_ptr,
                message_len,
                "message",
            )
        };
        let (group_id, message) = match inputs {
            Ok(inputs) => inputs,
            Err(e) => return FfiBytes::err(e),
        };
        with_engine(
            handle_id,
            || FfiBytes::err(FfiError::invalid_handle()),
            |engine| {
                FfiBytes::from_result(
                    engine
                        .process_proposal(group_id, message)
                        .map(|()| Vec::new()),
                )
            },
        )
    })
}

/// Commit held proposals WITHOUT persisting (FR-7, phase one of two).
///
/// The caller publishes `commit_ptr` and only then calls
/// `airdress_mls_confirm_commit`. On a `409` or a network failure it
/// calls `airdress_mls_abort_commit`. Persisting before the operator
/// has accepted the commit forks the group.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` is a byte input (contract 1). The
/// result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_commit_pending(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> FfiCommitResult {
    guarded(ffi_commit_err, || {
        // SAFETY: a byte input (contract 1), per `# Safety`.
        let group_id = match unsafe { borrowed(group_id_ptr, group_id_len, "group_id") } {
            Ok(g) => g,
            Err(e) => return ffi_commit_err(e),
        };
        with_engine(
            handle_id,
            || ffi_commit_err(FfiError::invalid_handle()),
            |engine| match engine.commit_pending(group_id) {
                Ok(outcome) => ffi_commit_ok(outcome),
                Err(e) => ffi_commit_err(e),
            },
        )
    })
}

/// Persist a commit built by `airdress_mls_commit_pending` (phase two).
/// Returns the resulting epoch, `-1` for an invalid handle, `-2` when
/// no commit was awaiting confirmation, the write failed, the group id
/// was refused, or an internal error happened.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` is a byte input (contract 1).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_confirm_commit(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> i64 {
    guarded(
        |_| PANIC_I64,
        || {
            // SAFETY: a byte input (contract 1), per `# Safety`.
            let Ok(group_id) = (unsafe { borrowed(group_id_ptr, group_id_len, "group_id") }) else {
                return -2;
            };
            with_engine(
                handle_id,
                || -1,
                |engine| {
                    engine
                        .confirm_commit(group_id)
                        .map_or(-2, |e| i64::try_from(e).unwrap_or(i64::MAX))
                },
            )
        },
    )
}

/// Discard a commit built by `airdress_mls_commit_pending`, reloading
/// the group from sealed storage. Returns the epoch the group is back
/// at, `-1` for an invalid handle, `-2` when nothing was pending, the
/// group id was refused, or an internal error happened.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` is a byte input (contract 1).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_abort_commit(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> i64 {
    guarded(
        |_| PANIC_I64,
        || {
            // SAFETY: a byte input (contract 1), per `# Safety`.
            let Ok(group_id) = (unsafe { borrowed(group_id_ptr, group_id_len, "group_id") }) else {
                return -2;
            };
            with_engine(
                handle_id,
                || -1,
                |engine| {
                    engine
                        .abort_commit(group_id)
                        .map_or(-2, |e| i64::try_from(e).unwrap_or(i64::MAX))
                },
            )
        },
    )
}

/// Apply another member's commit (FR-4): advance the epoch, persist,
/// and report the membership delta. `self_removed` is `1` when this
/// device was the leaf removed.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` and `(message_ptr, message_len)` are
/// byte inputs (contract 1). The result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_process_commit(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
    message_ptr: *const u8,
    message_len: usize,
) -> FfiCommitResult {
    guarded(ffi_commit_err, || {
        // SAFETY: two byte inputs (contract 1), per `# Safety`.
        let inputs = unsafe {
            group_and_payload(
                group_id_ptr,
                group_id_len,
                message_ptr,
                message_len,
                "message",
            )
        };
        let (group_id, message) = match inputs {
            Ok(inputs) => inputs,
            Err(e) => return ffi_commit_err(e),
        };
        with_engine(
            handle_id,
            || ffi_commit_err(FfiError::invalid_handle()),
            |engine| match engine.process_commit(group_id, message) {
                Ok(outcome) => ffi_commit_ok(outcome),
                Err(e) => ffi_commit_err(e),
            },
        )
    })
}

/// The group's current epoch — the value the client declares as
/// `commit_from_epoch`. Returns `-1` for an invalid handle, `-2` when
/// the group is not on disk, the group id was refused, or an internal
/// error happened.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` is a byte input (contract 1).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_group_epoch(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> i64 {
    guarded(
        |_| PANIC_I64,
        || {
            // SAFETY: a byte input (contract 1), per `# Safety`.
            let Ok(group_id) = (unsafe { borrowed(group_id_ptr, group_id_len, "group_id") }) else {
                return -2;
            };
            with_engine(
                handle_id,
                || -1,
                |engine| {
                    engine
                        .group_epoch(group_id)
                        .map_or(-2, |e| i64::try_from(e).unwrap_or(i64::MAX))
                },
            )
        },
    )
}

/// Every member identity in the group, in leaf-index order — for the
/// membership UI and for AC-4.
///
/// # Safety
///
/// `(group_id_ptr, group_id_len)` is a byte input (contract 1). The
/// result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_group_members(
    handle_id: u64,
    group_id_ptr: *const u8,
    group_id_len: usize,
) -> FfiBytesList {
    guarded(FfiBytesList::err, || {
        // SAFETY: a byte input (contract 1), per `# Safety`.
        let group_id = match unsafe { borrowed(group_id_ptr, group_id_len, "group_id") } {
            Ok(g) => g,
            Err(e) => return FfiBytesList::err(e),
        };
        with_engine(
            handle_id,
            || FfiBytesList::err(FfiError::invalid_handle()),
            |engine| {
                FfiBytesList::from_result(
                    engine
                        .group_members(group_id)
                        .map(|members| members.into_iter().map(|m| m.identity).collect()),
                )
            },
        )
    })
}

/// Free an `FfiCommitResult` returned by `airdress_mls_commit_pending`
/// or `airdress_mls_process_commit`.
///
/// # Safety
///
/// `result` must have been returned by one of those two functions,
/// unchanged, and must not have been freed before (contract 3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_free_commit_result(result: FfiCommitResult) {
    guarded(
        |_| (),
        || {
            // SAFETY: every field was made by `ffi_commit_ok` or
            // `ffi_commit_err` and is freed here once, per the caller's
            // contract; the free exports accept the null and empty values
            // the error form holds.
            unsafe {
                airdress_mls_free_bytes(result.commit_ptr, result.commit_len);
                airdress_mls_free_bytes(result.welcome_ptr, result.welcome_len);
                airdress_mls_free_bytes_list(result.added);
                airdress_mls_free_bytes_list(result.removed);
                airdress_mls_free_bytes_list(result.members);
                airdress_mls_free_error(result.error);
            }
        },
    );
}

/// Mint a root-signed delegation for an agent device.
///
/// The ONE export that borrows the airdress root seed: the device that
/// holds the root (the phone) approves an agent device by signing a
/// delegation naming the agent's own key, and never seals the seed to it.
/// The seed is copied once, used for one signature and zeroized; nothing
/// keeps it. Every other export takes a session seed, never this one.
///
/// `device_public_key` is the agent's Ed25519 key (32 bytes), which is
/// also its MLS signing key. `harness` (`[a-z][a-z0-9-]{0,31}`) names the
/// program running the agent and `device_label` is what people are shown.
/// `issued_at_unix` is now, in seconds; the delegation expires thirty days
/// later ([`airdress_mls::delegation::AGENT_DELEGATION_LIFETIME_SECS`]).
///
/// Returns the delegation as UTF-8 JSON (keys sorted, `signature`
/// included), freed with `airdress_mls_free_bytes`, or an error naming the
/// field that failed its shape check.
///
/// # Safety
///
/// `(root_seed, root_seed_len)` and `(device_public_key,
/// device_public_key_len)` are byte inputs (contract 1); `airdress`,
/// `device_id`, `harness` and `device_label` are string inputs
/// (contract 2). The result is freed per contract 3.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_mint_agent_delegation(
    root_seed: *const u8,
    root_seed_len: usize,
    airdress: *const c_char,
    device_id: *const c_char,
    device_public_key: *const u8,
    device_public_key_len: usize,
    harness: *const c_char,
    device_label: *const c_char,
    issued_at_unix: u64,
) -> FfiBytes {
    guarded(FfiBytes::err, || {
        let minted = (|| -> Result<Vec<u8>, FfiError> {
            // SAFETY: a byte input (contract 1), per `# Safety`. The copy is
            // zeroized on drop, on every path out of this closure.
            let seed = zeroize::Zeroizing::new(unsafe {
                required_key32(root_seed, root_seed_len, "root_seed")
            }?);
            // SAFETY: string inputs (contract 2) and a byte input
            // (contract 1), per `# Safety`.
            let req = unsafe {
                airdress_mls::delegation::AgentDelegationRequest {
                    airdress: required_str(airdress, "airdress")?,
                    device_id: required_str(device_id, "device_id")?,
                    device_public_key: required_key32(
                        device_public_key,
                        device_public_key_len,
                        "device_public_key",
                    )?,
                    harness: required_str(harness, "harness")?,
                    device_label: required_str(device_label, "device_label")?,
                    issued_at_unix,
                }
            };
            let delegation = airdress_mls::delegation::mint_agent_delegation(&seed, &req)
                .map_err(|e| e.to_string())?;
            Ok(serde_json::to_vec(&serde_json::Value::Object(delegation))
                .map_err(|e| e.to_string())?)
        })();
        FfiBytes::from_result(minted)
    })
}

/// Free a byte buffer previously returned by any `airdress_mls_*` function.
///
/// # Safety
///
/// `ptr` must have been returned by a Rust FFI function in this crate,
/// with this `len`, and must not have been freed before (contract 3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_free_bytes(ptr: *mut u8, len: usize) {
    guarded(
        |_| (),
        || {
            if !ptr.is_null() && len > 0 {
                // SAFETY: a non-empty buffer was made by `into_raw_bytes`
                // from a `Box<[u8]>` of exactly `len` bytes; rebuilding that
                // fat pointer and dropping the box returns it to the
                // allocator that made it, once (the caller's contract).
                drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
            }
        },
    );
}

/// Free an error string previously returned in an FFI result's `error` field.
///
/// # Safety
///
/// `ptr` is null, or was returned in an `error` field by a Rust FFI
/// function in this crate and has not been freed before (contract 3).
#[unsafe(no_mangle)]
pub unsafe extern "C" fn airdress_mls_free_error(ptr: *mut c_char) {
    guarded(
        |_| (),
        || {
            if !ptr.is_null() {
                // Out of the table before the allocation is released, so
                // a later error at the same address gets its own code.
                error_codes().remove(&(ptr as usize));
                // SAFETY: a non-null error was made by `into_raw_error`
                // (`CString::into_raw`) and is reclaimed once, per the
                // caller's contract.
                drop(unsafe { std::ffi::CString::from_raw(ptr) });
            }
        },
    );
}

/// The stable code of an error string this library returned, for the
/// caller to branch on instead of matching the message (rust guide
/// R-ERR-6). Call it before `airdress_mls_free_error`.
///
/// Returns one of the [`ErrorCode`] values — `5`
/// (`EpochUnavailable`, "older than the keys still on this device") is
/// the one the app routes to catch-up — `0` for a null pointer, and `-1`
/// for a pointer this library did not hand out or has already freed.
/// The pointer is only compared, never read, so any value is safe to
/// pass.
#[unsafe(no_mangle)]
pub extern "C" fn airdress_mls_error_code(error: *const c_char) -> i32 {
    guarded(
        |_| -1,
        || {
            if error.is_null() {
                return 0;
            }
            error_codes().get(&(error as usize)).copied().unwrap_or(-1)
        },
    )
}

fn ffi_start_group_err(error: impl Into<FfiError>) -> FfiStartGroupResult {
    FfiStartGroupResult {
        group_id_ptr: std::ptr::null_mut(),
        group_id_len: 0,
        welcome_ptr: std::ptr::null_mut(),
        welcome_len: 0,
        first_app_ptr: std::ptr::null_mut(),
        first_app_len: 0,
        error: into_raw_error(&error.into()),
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

    use std::cell::Cell;
    use std::ffi::{CStr, CString};

    use ed25519_dalek::SigningKey;

    use airdress_mls::EngineError;

    use super::{
        FfiBytes, FfiStartGroupResult, airdress_mls_create_engine_from_seed, airdress_mls_decrypt,
        airdress_mls_decrypt_bound, airdress_mls_destroy_engine, airdress_mls_encrypt_bound,
        airdress_mls_generate_key_package, airdress_mls_message_group_id,
        airdress_mls_process_welcome, airdress_mls_set_v2_cutover, airdress_mls_start_group,
        airdress_mls_start_group_bound, airdress_mls_start_group_solo,
    };

    thread_local! {
        /// Set by a test to make the next engine lookup ON THIS THREAD
        /// panic while the engine table is locked — the worst place a
        /// panic inside `mls-rs` could happen. Thread-local, so tests
        /// running in parallel never see each other's.
        static INJECT_PANIC: Cell<bool> = const { Cell::new(false) };
    }

    /// The hook `with_engine` calls with the table locked.
    pub(super) fn maybe_inject_panic() {
        assert!(
            !INJECT_PANIC.with(|flag| flag.replace(false)),
            "injected by a test"
        );
    }

    const ALICE: &str = "alice.test.airdress.co";
    const BOB: &str = "bob.test.airdress.co";

    /// A live engine handle plus the state dir it must outlive.
    struct Handle {
        id: u64,
        dir: tempfile::TempDir,
    }

    impl Drop for Handle {
        fn drop(&mut self) {
            airdress_mls_destroy_engine(self.id);
        }
    }

    /// The revocation lookup the test engines register: every device
    /// is active.
    extern "C" fn every_device_active(_device_id: *const std::os::raw::c_char) -> i32 {
        1
    }

    /// Build an engine through the export a host actually calls, and
    /// put it past the v2 cutover when asked.
    fn engine(airdress: &str, seed_byte: u8, device_id: &str, cutover: bool) -> Handle {
        let dir = tempfile::tempdir().expect("state dir");
        let seed = [seed_byte; 32];
        let root = SigningKey::from_bytes(&[seed_byte.wrapping_add(0x40); 32]);
        let session_pub = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let delegation = airdress_mls::credential::test_support::signed_delegation_json_v2(
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
        // SAFETY: every argument is a live local buffer with its own
        // length, or a live `CString`, all outliving the call.
        let result = unsafe {
            airdress_mls_create_engine_from_seed(
                c_airdress.as_ptr(),
                seed.as_ptr(),
                seed.len(),
                root_pub.as_ptr(),
                root_pub.len(),
                c_delegation.as_ptr(),
                c_dir.as_ptr(),
                state_key.as_ptr(),
                state_key.len(),
            )
        };
        assert!(result.error.is_null(), "create_engine_from_seed: {}", {
            // SAFETY: a non-null error is a NUL-terminated string this
            // crate made, not yet freed.
            unsafe { CStr::from_ptr(result.error) }.to_string_lossy()
        });
        // SAFETY: the public key buffer the call returned, freed once.
        unsafe { super::airdress_mls_free_bytes(result.public_key_ptr, result.public_key_len) };
        if cutover {
            assert_eq!(airdress_mls_set_v2_cutover(result.handle_id), 0);
            // Past the cutover nothing verifies until a revocation lookup
            // is registered (fail closed); every device here is active.
            assert_eq!(
                // SAFETY: a plain function, callable for the life of the
                // process, that never calls back into the library.
                unsafe {
                    super::airdress_mls_set_revocation_lookup(
                        result.handle_id,
                        Some(every_device_active),
                    )
                },
                0
            );
        }
        Handle {
            id: result.handle_id,
            dir,
        }
    }

    /// Read and free an error string the crate returned.
    fn take_error(error: *mut std::os::raw::c_char) -> String {
        // SAFETY: a non-null `error` field is a NUL-terminated string this
        // crate made with `CString::into_raw`, not yet freed.
        let msg = unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned();
        // SAFETY: that string, freed once.
        unsafe { super::airdress_mls_free_error(error) };
        msg
    }

    /// Copy out and free one buffer the crate returned.
    fn take_buffer(ptr: *mut u8, len: usize) -> Vec<u8> {
        // SAFETY: a buffer of `len` initialised bytes this crate made
        // (dangling but non-null when empty), not yet freed.
        let bytes = unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec();
        // SAFETY: that buffer, with its own length, freed once.
        unsafe { super::airdress_mls_free_bytes(ptr, len) };
        bytes
    }

    /// Consume an `FfiBytes`, freeing whichever half it carries.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "taking the result by value is the point: it is freed here"
    )]
    fn take_bytes(result: FfiBytes) -> Result<Vec<u8>, String> {
        if result.error.is_null() {
            Ok(take_buffer(result.ptr, result.len))
        } else {
            Err(take_error(result.error))
        }
    }

    /// The three buffers of a start-group outcome, or the refusal.
    #[derive(Debug)]
    struct Started {
        group_id: Vec<u8>,
        welcome: Vec<u8>,
        first_application: Vec<u8>,
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "taking the result by value is the point: it is freed here"
    )]
    fn take_start(result: FfiStartGroupResult) -> Result<Started, String> {
        if !result.error.is_null() {
            return Err(take_error(result.error));
        }
        Ok(Started {
            group_id: take_buffer(result.group_id_ptr, result.group_id_len),
            welcome: take_buffer(result.welcome_ptr, result.welcome_len),
            first_application: take_buffer(result.first_app_ptr, result.first_app_len),
        })
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
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let started = take_start(unsafe {
            airdress_mls_start_group_bound(
                alice.id,
                bob_kp.as_ptr(),
                bob_kp.len(),
                b"hello bob".as_ptr(),
                b"hello bob".len(),
                c_alice.as_ptr(),
            )
        })
        .expect("a client past the cutover must be able to establish a conversation");

        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        take_bytes(unsafe {
            airdress_mls_process_welcome(bob.id, started.welcome.as_ptr(), started.welcome.len())
        })
        .expect("bob joins");

        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let plaintext = take_bytes(unsafe {
            airdress_mls_decrypt_bound(
                bob.id,
                started.group_id.as_ptr(),
                started.group_id.len(),
                started.first_application.as_ptr(),
                started.first_application.len(),
                c_alice.as_ptr(),
            )
        })
        .expect("the establishment's first message decrypts under its binding");
        assert_eq!(plaintext, b"hello bob");

        // And the group is a working group afterwards, not just a
        // successful call: the conversation carries traffic in both
        // directions under the same binding.
        let c_bob = CString::new(BOB).unwrap();
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let reply = take_bytes(unsafe {
            airdress_mls_encrypt_bound(
                bob.id,
                started.group_id.as_ptr(),
                started.group_id.len(),
                b"hi alice".as_ptr(),
                b"hi alice".len(),
                c_bob.as_ptr(),
            )
        })
        .expect("bob replies into the established group");
        assert_eq!(
            // SAFETY: live local buffers and C strings, each with its own
            // length, outliving the call; the result is freed by a take_* helper.
            take_bytes(unsafe {
                airdress_mls_decrypt_bound(
                    alice.id,
                    started.group_id.as_ptr(),
                    started.group_id.len(),
                    reply.as_ptr(),
                    reply.len(),
                    c_bob.as_ptr(),
                )
            })
            .expect("alice reads the reply"),
            b"hi alice"
        );
    }

    /// The pin subjects a test's root-key callback was asked for.
    static ASKED_SUBJECTS: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());
    /// `(pin subject, root)` pairs the test's root-key callback answers.
    static ANSWERS: std::sync::Mutex<Vec<(String, [u8; 32])>> = std::sync::Mutex::new(Vec::new());

    /// A host's root-key cache as the phone implements it: a table
    /// keyed by pin subject, `None` for anything else.
    extern "C" fn subject_table_lookup(
        subject: *const std::os::raw::c_char,
        out_root_public_key: *mut u8,
    ) -> i32 {
        // SAFETY: the library passes a live NUL-terminated string.
        let subject = unsafe { CStr::from_ptr(subject) }
            .to_string_lossy()
            .into_owned();
        ASKED_SUBJECTS.lock().unwrap().push(subject.clone());
        let answers = ANSWERS.lock().unwrap();
        let Some((_, root)) = answers.iter().find(|(s, _)| *s == subject) else {
            return 0;
        };
        // SAFETY: the library passes a 32-byte output buffer.
        unsafe { std::ptr::copy_nonoverlapping(root.as_ptr(), out_root_public_key, 32) };
        1
    }

    /// **A household member's device, over the C ABI.** The host hands
    /// in a `v: 3` delegation (it carries `person_id`) and the person's
    /// own root; no export changes, the version follows the delegation.
    /// A peer verifying that member's key package asks its root-key
    /// callback for the pin subject `airdress ‖ 0x1F ‖ person_id`, and
    /// the leaf is admitted only under that subject.
    #[test]
    fn a_member_leaf_is_verified_under_its_pin_subject_through_the_c_abi() {
        const PERSON: &str = "019f3c2a-5e71-7b04-a8d3-4e1f9c6b2a85";
        let owner = engine(ALICE, 0x51, "owner-phone", true);

        // The member's engine: same airdress, a person root of its own.
        let dir = tempfile::tempdir().expect("state dir");
        let seed = [0x52u8; 32];
        let person_root = SigningKey::from_bytes(&[0x53; 32]);
        let session_pub = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let delegation = airdress_mls::credential::test_support::signed_delegation_json_v3(
            &person_root,
            ALICE,
            PERSON,
            &session_pub,
            "member-phone",
            "2099-01-01T00:00:00Z",
        );
        let c_airdress = CString::new(ALICE).unwrap();
        let c_delegation = CString::new(delegation).unwrap();
        let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
        let person_pub = person_root.verifying_key().to_bytes();
        let state_key = [0x78u8; 32];
        // SAFETY: every argument is a live local buffer with its own
        // length, or a live `CString`, all outliving the call.
        let result = unsafe {
            airdress_mls_create_engine_from_seed(
                c_airdress.as_ptr(),
                seed.as_ptr(),
                seed.len(),
                person_pub.as_ptr(),
                person_pub.len(),
                c_delegation.as_ptr(),
                c_dir.as_ptr(),
                state_key.as_ptr(),
                state_key.len(),
            )
        };
        assert!(
            result.error.is_null(),
            "member engine: {}",
            take_error(result.error)
        );
        // SAFETY: the public key buffer the call returned, freed once.
        unsafe { super::airdress_mls_free_bytes(result.public_key_ptr, result.public_key_len) };
        let member = Handle {
            id: result.handle_id,
            dir,
        };
        let member_kp = key_package(&member);

        // The owner's host pins the airdress root under the bare
        // airdress, as every host does today, and knows nothing for the
        // member's subject yet.
        let owner_root = SigningKey::from_bytes(&[0x51u8.wrapping_add(0x40); 32])
            .verifying_key()
            .to_bytes();
        ANSWERS.lock().unwrap().push((ALICE.to_owned(), owner_root));
        assert_eq!(
            // SAFETY: a plain function, callable for the life of the
            // process, that never calls back into the library.
            unsafe {
                super::airdress_mls_set_root_key_lookup(owner.id, Some(subject_table_lookup))
            },
            0
        );
        let subject = format!("{ALICE}\u{1f}{PERSON}");
        let start = |handle: &Handle| {
            // SAFETY: live local buffers and C strings, each with its own
            // length, outliving the call; the result is freed by take_start.
            take_start(unsafe {
                airdress_mls_start_group_bound(
                    handle.id,
                    member_kp.as_ptr(),
                    member_kp.len(),
                    b"hello".as_ptr(),
                    b"hello".len(),
                    c_airdress.as_ptr(),
                )
            })
        };
        assert!(
            start(&owner).is_err(),
            "a host that cannot resolve the person subject must reject the leaf, \
             whatever it holds for the bare airdress"
        );
        assert!(ASKED_SUBJECTS.lock().unwrap().contains(&subject));

        // Under its own subject, it is admitted.
        ANSWERS.lock().unwrap().push((subject, person_pub));
        let started = start(&owner).expect("the member's leaf verifies under its pin subject");
        // SAFETY: live local buffers, outliving the call; freed by take_bytes.
        take_bytes(unsafe {
            airdress_mls_process_welcome(member.id, started.welcome.as_ptr(), started.welcome.len())
        })
        .expect("the member joins");
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

        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let started = take_start(unsafe {
            airdress_mls_start_group_solo(
                alice.id,
                b"note to self".as_ptr(),
                b"note to self".len(),
                c_alice.as_ptr(),
            )
        })
        .expect("a single-device owner must still have a self thread");

        assert!(
            started.welcome.is_empty(),
            "nobody was added, so there is no Welcome to put on the wire"
        );
        assert!(!started.group_id.is_empty());
        assert!(!started.first_application.is_empty());

        // The group works: the owner keeps writing into it.
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let more = take_bytes(unsafe {
            airdress_mls_encrypt_bound(
                alice.id,
                started.group_id.as_ptr(),
                started.group_id.len(),
                b"and another".as_ptr(),
                b"and another".len(),
                c_alice.as_ptr(),
            )
        })
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
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let err = take_start(unsafe {
            airdress_mls_start_group_solo(
                alice.id,
                b"note to self".as_ptr(),
                b"note to self".len(),
                std::ptr::null(),
            )
        })
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
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let err = take_start(unsafe {
            airdress_mls_start_group(
                alice.id,
                bob_kp.as_ptr(),
                bob_kp.len(),
                b"hello bob".as_ptr(),
                b"hello bob".len(),
            )
        })
        .expect_err("an unbound establishment past the cutover must be refused");
        assert!(
            err.contains("must carry their sender binding"),
            "unexpected refusal: {err}"
        );

        // Nothing was created. Alice's state dir holds no group, so
        // the refusal cost the caller nothing to retry from.
        assert!(
            !alice.dir.path().join("groups").exists()
                || std::fs::read_dir(alice.dir.path().join("groups"))
                    .expect("groups dir")
                    .next()
                    .is_none(),
            "the refused establishment left a group on disk"
        );

        // The same call with a binding succeeds against the SAME
        // KeyPackage — proof the refusal did not consume it.
        let c_alice = CString::new(ALICE).unwrap();
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        take_start(unsafe {
            airdress_mls_start_group_bound(
                alice.id,
                bob_kp.as_ptr(),
                bob_kp.len(),
                b"hello bob".as_ptr(),
                b"hello bob".len(),
                c_alice.as_ptr(),
            )
        })
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
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let started = take_start(unsafe {
            airdress_mls_start_group_bound(
                alice.id,
                bob_kp.as_ptr(),
                bob_kp.len(),
                b"hello bob".as_ptr(),
                b"hello bob".len(),
                c_alice.as_ptr(),
            )
        })
        .expect("establish");
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        take_bytes(unsafe {
            airdress_mls_process_welcome(bob.id, started.welcome.as_ptr(), started.welcome.len())
        })
        .expect("bob joins");

        // A second conversation between the same two airdresses. Under
        // D-10 "re-filed into another conversation" IS "presented
        // against another group", because that is what the receiver
        // files by.
        let other_kp = key_package(&bob);
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let other = take_start(unsafe {
            airdress_mls_start_group_bound(
                alice.id,
                other_kp.as_ptr(),
                other_kp.len(),
                b"second thread".as_ptr(),
                b"second thread".len(),
                c_alice.as_ptr(),
            )
        })
        .expect("a second group");
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        take_bytes(unsafe {
            airdress_mls_process_welcome(bob.id, other.welcome.as_ptr(), other.welcome.len())
        })
        .expect("bob joins the second group");
        assert_ne!(started.group_id, other.group_id);

        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        take_bytes(unsafe {
            airdress_mls_decrypt_bound(
                bob.id,
                other.group_id.as_ptr(),
                other.group_id.len(),
                started.first_application.as_ptr(),
                started.first_application.len(),
                c_alice.as_ptr(),
            )
        })
        .expect_err("a ciphertext presented against another group must not decrypt");

        // Re-attributed to another sender.
        let c_bob = CString::new(BOB).unwrap();
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let err = take_bytes(unsafe {
            airdress_mls_decrypt_bound(
                bob.id,
                started.group_id.as_ptr(),
                started.group_id.len(),
                started.first_application.as_ptr(),
                started.first_application.len(),
                c_bob.as_ptr(),
            )
        })
        .expect_err("a re-attributed establishment message must not decrypt");
        assert!(
            err.contains("does not belong to this group or sender"),
            "unexpected error: {err}"
        );

        // And an UNBOUND decrypt of it is refused too, so a receiver
        // cannot sidestep the comparison by dropping the binding.
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        take_bytes(unsafe {
            airdress_mls_decrypt(
                bob.id,
                started.group_id.as_ptr(),
                started.group_id.len(),
                started.first_application.as_ptr(),
                started.first_application.len(),
            )
        })
        .expect_err("an unbound decrypt past the cutover must be refused");

        // The honest binding still works after all three rejections —
        // no rejection ratcheted the group forward behind the caller.
        assert_eq!(
            // SAFETY: live local buffers and C strings, each with its own
            // length, outliving the call; the result is freed by a take_* helper.
            take_bytes(unsafe {
                airdress_mls_decrypt_bound(
                    bob.id,
                    started.group_id.as_ptr(),
                    started.group_id.len(),
                    started.first_application.as_ptr(),
                    started.first_application.len(),
                    c_alice.as_ptr(),
                )
            })
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
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let started = take_start(unsafe {
            airdress_mls_start_group(
                alice.id,
                bob_kp.as_ptr(),
                bob_kp.len(),
                b"hello bob".as_ptr(),
                b"hello bob".len(),
            )
        })
        .expect("pre-cutover establishment is unchanged");
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        take_bytes(unsafe {
            airdress_mls_process_welcome(bob.id, started.welcome.as_ptr(), started.welcome.len())
        })
        .expect("bob joins");
        assert_eq!(
            // SAFETY: live local buffers and C strings, each with its own
            // length, outliving the call; the result is freed by a take_* helper.
            take_bytes(unsafe {
                airdress_mls_decrypt(
                    bob.id,
                    started.group_id.as_ptr(),
                    started.group_id.len(),
                    started.first_application.as_ptr(),
                    started.first_application.len(),
                )
            })
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

        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let err = take_start(unsafe {
            airdress_mls_start_group_bound(
                alice.id,
                bob_kp.as_ptr(),
                bob_kp.len(),
                b"hi".as_ptr(),
                b"hi".len(),
                std::ptr::null(),
            )
        })
        .expect_err("a bound establishment without a sender must be refused");
        assert!(err.contains("from_airdress"), "unexpected error: {err}");

        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let err = take_bytes(unsafe {
            airdress_mls_encrypt_bound(
                alice.id,
                b"gid".as_ptr(),
                3,
                b"hi".as_ptr(),
                2,
                std::ptr::null(),
            )
        })
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
        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        let started = take_start(unsafe {
            airdress_mls_start_group_bound(
                alice.id,
                bob_kp.as_ptr(),
                bob_kp.len(),
                b"hello bob".as_ptr(),
                b"hello bob".len(),
                c_alice.as_ptr(),
            )
        })
        .expect("establish");

        assert_eq!(
            // SAFETY: live local buffers and C strings, each with its own
            // length, outliving the call; the result is freed by a take_* helper.
            take_bytes(unsafe {
                airdress_mls_message_group_id(
                    started.first_application.as_ptr(),
                    started.first_application.len(),
                )
            })
            .expect("an application message names its group in the clear"),
            started.group_id,
            "the framing's group id is the group the receiver must file by"
        );

        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        take_bytes(unsafe {
            airdress_mls_message_group_id(started.welcome.as_ptr(), started.welcome.len())
        })
        .expect_err("a Welcome carries no group id in its framing");

        // SAFETY: live local buffers and C strings, each with its own
        // length, outliving the call; the result is freed by a take_* helper.
        take_bytes(unsafe { airdress_mls_message_group_id(b"not an mls message".as_ptr(), 18) })
            .expect_err("garbage is a parse error, not a group id");
    }

    /// The minting export, through the C boundary: the vector's inputs give
    /// the vector's delegation, and a malformed key is an error naming it.
    #[test]
    fn mint_agent_delegation_reproduces_the_vector() {
        use base64::Engine as _;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;

        use super::airdress_mls_mint_agent_delegation;

        let fixture: serde_json::Value =
            serde_json::from_str(airdress_mls::vectors::DELEGATION).unwrap();
        let v = fixture["vectors"]
            .as_array()
            .unwrap()
            .iter()
            .find(|v| v["name"] == "agent-delegation")
            .unwrap();
        let m = &v["mint"];
        let b64 = |x: &serde_json::Value| URL_SAFE_NO_PAD.decode(x.as_str().unwrap()).unwrap();
        let cs = |x: &serde_json::Value| CString::new(x.as_str().unwrap()).unwrap();
        let seed = b64(&v["root_seed_b64url"]);
        let key = b64(&m["device_public_key_b64url"]);
        let (airdress, device_id, harness, label) = (
            cs(&m["airdress"]),
            cs(&m["device_id"]),
            cs(&m["harness"]),
            cs(&m["device_label"]),
        );
        let mint = |key: &[u8]| {
            // SAFETY: live local buffers and C strings, each with its own
            // length, outliving the call; the result is freed by a take_* helper.
            take_bytes(unsafe {
                airdress_mls_mint_agent_delegation(
                    seed.as_ptr(),
                    seed.len(),
                    airdress.as_ptr(),
                    device_id.as_ptr(),
                    key.as_ptr(),
                    key.len(),
                    harness.as_ptr(),
                    label.as_ptr(),
                    m["issued_at_unix"].as_u64().unwrap(),
                )
            })
        };
        let json = mint(&key).expect("minted");
        let minted: serde_json::Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(minted, v["delegation"]);

        let err = mint(&key[..31]).expect_err("a short key is refused");
        assert!(err.contains("device_public_key"), "{err}");
    }

    /// An empty input may arrive as a null pointer with length 0 — what
    /// `calloc(0)` can hand Dart — and is the empty slice, not an error.
    #[test]
    fn a_null_input_with_zero_length_is_the_empty_input() {
        let alice = engine(ALICE, 0x51, "alice-null", true);
        let c_alice = CString::new(ALICE).unwrap();
        let started = take_start(
            // SAFETY: a null, zero-length message (the case under test)
            // and a live C string.
            unsafe {
                airdress_mls_start_group_solo(alice.id, std::ptr::null(), 0, c_alice.as_ptr())
            },
        )
        .expect("a null, zero-length first message is an empty one");
        let sent = take_bytes(
            // SAFETY: a live group id with its length, a null zero-length
            // plaintext, and a live C string.
            unsafe {
                airdress_mls_encrypt_bound(
                    alice.id,
                    started.group_id.as_ptr(),
                    started.group_id.len(),
                    std::ptr::null(),
                    0,
                    c_alice.as_ptr(),
                )
            },
        )
        .expect("an empty plaintext encrypts");
        assert!(!sent.is_empty());
    }

    /// A null pointer with a non-zero length, and a length no allocation
    /// can have, are refused with an error naming the argument — before
    /// either reaches `slice::from_raw_parts`, where the first is
    /// undefined behaviour and the second aborts a debug build.
    #[test]
    fn a_null_or_impossible_input_is_an_error_not_a_crash() {
        let err = take_bytes(
            // SAFETY: a null pointer with a non-zero length, refused before
            // any read (the case under test).
            unsafe { airdress_mls_message_group_id(std::ptr::null(), 16) },
        )
        .expect_err("null with a length is refused");
        assert!(err.contains("message is null"), "{err}");

        let alice = engine(ALICE, 0x52, "alice-bad-len", true);
        let c_alice = CString::new(ALICE).unwrap();
        let err = take_bytes(
            // SAFETY: the pointers are live; the length is the bug under
            // test and is refused before any read.
            unsafe {
                airdress_mls_encrypt_bound(
                    alice.id,
                    b"gid".as_ptr(),
                    usize::MAX,
                    b"hi".as_ptr(),
                    2,
                    c_alice.as_ptr(),
                )
            },
        )
        .expect_err("an impossible length is refused");
        assert!(err.contains("group_id has an impossible length"), "{err}");

        // The epoch exports have no error string: a refused input is -2.
        assert_eq!(
            // SAFETY: a null pointer with a length, refused before any read.
            unsafe { super::airdress_mls_group_epoch(alice.id, std::ptr::null(), 4) },
            -2
        );
    }

    /// A panic inside an export — here injected while the engine table
    /// is locked, which is where one inside `mls-rs` would happen —
    /// comes back as an error result instead of unwinding into the
    /// host, and the poisoned table is recovered: the same engine
    /// answers the next call.
    #[test]
    fn a_panic_is_an_error_and_the_engine_keeps_working() {
        let alice = engine(ALICE, 0x53, "alice-panic", true);
        let c_alice = CString::new(ALICE).unwrap();
        let started = take_start(
            // SAFETY: a live message and C string with their lengths.
            unsafe {
                airdress_mls_start_group_solo(alice.id, b"one".as_ptr(), 3, c_alice.as_ptr())
            },
        )
        .expect("establish");

        let encrypt = || {
            take_bytes(
                // SAFETY: live buffers and a C string with their lengths.
                unsafe {
                    airdress_mls_encrypt_bound(
                        alice.id,
                        started.group_id.as_ptr(),
                        started.group_id.len(),
                        b"two".as_ptr(),
                        3,
                        c_alice.as_ptr(),
                    )
                },
            )
        };

        INJECT_PANIC.with(|flag| flag.set(true));
        let err = encrypt().expect_err("a panic is an error result");
        assert!(err.contains("a panic was caught"), "{err}");
        assert!(err.contains("injected by a test"), "{err}");

        // Every return shape has a panic answer, not only `FfiBytes`.
        INJECT_PANIC.with(|flag| flag.set(true));
        assert_eq!(
            super::airdress_mls_is_v2_cutover(alice.id),
            super::PANIC_I32
        );
        INJECT_PANIC.with(|flag| flag.set(true));
        assert_eq!(
            // SAFETY: a live group id with its length.
            unsafe {
                super::airdress_mls_group_epoch(
                    alice.id,
                    started.group_id.as_ptr(),
                    started.group_id.len(),
                )
            },
            super::PANIC_I64
        );

        // The lock was poisoned by the first panic; it is recovered, and
        // the engine carries on from the state the failed call left.
        encrypt().expect("the engine answers after a caught panic");
        assert_eq!(super::airdress_mls_is_v2_cutover(alice.id), 1);
    }

    /// Read an error's code and message, then free it — what the app's
    /// `_checkError` does, in that order.
    #[expect(
        clippy::needless_pass_by_value,
        reason = "taking the result by value is the point: it is freed here"
    )]
    fn take_coded(result: FfiBytes) -> (i32, String) {
        assert!(!result.error.is_null(), "expected an error");
        let code = super::airdress_mls_error_code(result.error);
        (code, take_error(result.error))
    }

    /// Every refusal carries a stable code, readable off the error string
    /// until it is freed, and gone (-1) afterwards; null is 0.
    #[test]
    fn errors_carry_stable_codes() {
        use airdress_mls::ErrorCode;

        let alice = engine(ALICE, 0x54, "alice-codes", true);
        let c_alice = CString::new(ALICE).unwrap();

        let (code, _) = take_coded(airdress_mls_generate_key_package(u64::MAX));
        assert_eq!(code, ErrorCode::InvalidHandle.as_i32());

        let (code, msg) = take_coded(
            // SAFETY: a null pointer with a length, refused before any read.
            unsafe { airdress_mls_message_group_id(std::ptr::null(), 4) },
        );
        assert_eq!(code, ErrorCode::InvalidArgument.as_i32(), "{msg}");

        let (code, _) = take_coded(
            // SAFETY: live buffers with their own lengths.
            unsafe { airdress_mls_decrypt(alice.id, b"gid".as_ptr(), 3, b"msg".as_ptr(), 3) },
        );
        assert_eq!(code, ErrorCode::BindingRequired.as_i32());

        let (code, _) = take_coded(
            // SAFETY: a live buffer with its own length.
            unsafe { airdress_mls_message_group_id(b"junk".as_ptr(), 4) },
        );
        assert_eq!(code, ErrorCode::Engine.as_i32());

        let (code, _) = take_coded(
            // SAFETY: live buffers and a C string with their own lengths.
            unsafe {
                airdress_mls_encrypt_bound(
                    alice.id,
                    b"gid".as_ptr(),
                    3,
                    b"hi".as_ptr(),
                    2,
                    c_alice.as_ptr(),
                )
            },
        );
        assert_eq!(code, ErrorCode::Engine.as_i32());

        INJECT_PANIC.with(|flag| flag.set(true));
        let (code, _) = take_coded(airdress_mls_generate_key_package(alice.id));
        assert_eq!(code, ErrorCode::Internal.as_i32());

        // The trimmed-epoch case the app routes to catch-up: code 5, and
        // the sentence it used to match on, unchanged.
        let (code, msg) = take_coded(FfiBytes::err(EngineError::EpochUnavailable {
            requested: 1,
            oldest_retained: Some(4),
        }));
        assert_eq!(code, 5);
        assert_eq!(code, ErrorCode::EpochUnavailable.as_i32());
        assert_eq!(
            msg,
            "this message is older than the keys still on this device"
        );

        // Freed errors and null are not codes.
        let raw = FfiBytes::err(String::from("x")).error;
        // SAFETY: an error this crate made, freed once.
        unsafe { super::airdress_mls_free_error(raw) };
        assert_eq!(super::airdress_mls_error_code(raw), -1);
        assert_eq!(super::airdress_mls_error_code(std::ptr::null()), 0);
    }

    /// The argument checks on their own, with no engine: what the Miri
    /// lane in CI runs, because these are the raw-pointer paths
    /// (rust guide R-UNS-5) and an engine is too slow under Miri.
    #[test]
    fn arguments_are_checked_before_they_are_read() {
        use super::{borrowed, required_key32, required_str};

        let bytes = [1u8, 2, 3];
        // SAFETY: a live array with its own length.
        assert_eq!(unsafe { borrowed(bytes.as_ptr(), 3, "b") }.unwrap(), &bytes);
        // SAFETY: null with length 0, the empty input.
        let empty = unsafe { borrowed(std::ptr::null(), 0, "b") };
        assert!(empty.unwrap().is_empty());
        // SAFETY: refused before any read.
        assert!(unsafe { borrowed(std::ptr::null(), 1, "b") }.is_err());
        // SAFETY: a live pointer; the length is refused before any read.
        assert!(unsafe { borrowed(bytes.as_ptr(), usize::MAX, "b") }.is_err());

        let key = [7u8; 32];
        // SAFETY: a live 32-byte array.
        let copied = unsafe { required_key32(key.as_ptr(), 32, "k") };
        assert_eq!(copied.unwrap(), key);
        // SAFETY: refused on length before any read.
        assert!(unsafe { required_key32(key.as_ptr(), 31, "k") }.is_err());
        // SAFETY: refused before any read.
        assert!(unsafe { required_key32(std::ptr::null(), 32, "k") }.is_err());

        let name = CString::new("alice").unwrap();
        // SAFETY: a live C string.
        let read = unsafe { required_str(name.as_ptr(), "s") };
        assert_eq!(read.unwrap(), "alice");
        // SAFETY: refused before any read.
        assert!(unsafe { required_str(std::ptr::null(), "s") }.is_err());
        let bad = [0xffu8, 0];
        // SAFETY: a live NUL-terminated byte string.
        assert!(unsafe { required_str(bad.as_ptr().cast(), "s") }.is_err());

        // An error string round-trips through the code table and the free.
        let raw = FfiBytes::err(String::from("x")).error;
        assert_eq!(super::airdress_mls_error_code(raw), 1);
        // SAFETY: an error this crate made, freed once.
        unsafe { super::airdress_mls_free_error(raw) };
        let ok = FfiBytes::ok(vec![1, 2]);
        assert_eq!(take_buffer(ok.ptr, ok.len), [1, 2]);
    }
}
