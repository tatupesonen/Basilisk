//! The interface when binutils is built in: declarations of the C shim
//! (`shim/bk_gdis.h`) and the safe wrappers around it.
//!
//! Soundness rests on three things, each upheld in this file:
//!
//! 1. every call into C happens while [`lock`]'s guard is held, because
//!    neither the shim nor libopcodes is reentrant;
//! 2. the pointers handed to C are valid for the lengths handed with them
//!    for the whole call, and the byte buffer is exclusively owned and
//!    writable (binutils may write to it);
//! 3. a `bk_gdis` pointer is created by `bk_gdis_create`, destroyed once by
//!    `bk_gdis_destroy`, and not used afterwards.

use std::cell::Cell;
use std::ffi::{CStr, CString, c_char, c_int};
use std::ptr::{self, NonNull};
use std::sync::{Mutex, MutexGuard, PoisonError};

use crate::{ArchInfo, RawError, Step, TEXT_CAPACITY};

const BK_GDIS_OK: i32 = 0;
const BK_GDIS_UNKNOWN_ARCH: i32 = 1;
const BK_GDIS_NO_DISASSEMBLER: i32 = 2;
const BK_GDIS_NO_MEMORY: i32 = 3;
const BK_GDIS_ABORTED: i32 = 4;
const BK_GDIS_OPTIONS_CONFLICT: i32 = 6;
const BK_GDIS_QUARANTINED: i32 = 7;

/// What RISC-V's disassembler says about the empty option string the shim
/// gives it so that it restores its defaults (`shim/bk_state.c`).
const RESET_ARTEFACT: &str = "unrecognized disassembler option: ";

/// `bk_gdis`: opaque to Rust.
#[repr(C)]
struct BkGdis {
    _opaque: [u8; 0],
}

/// `bk_gdis_arch`.
#[repr(C)]
struct BkArch {
    arch: u32,
    mach: u64,
    bits_per_word: u32,
    bits_per_address: u32,
    arch_name: *const c_char,
    printable_name: *const c_char,
}

/// `bk_gdis_insn`.
#[repr(C)]
#[derive(Default)]
struct BkInsn {
    length: i32,
    text_len: u32,
    text_truncated: u8,
    read_fault: u8,
    insn_info_valid: u8,
    branch_delay_insns: u8,
    data_size: u8,
    insn_type: u8,
    fault_address: u64,
    target: u64,
    target2: u64,
}

// The same numbers are asserted on the C side (shim/bk_gdis.c).
const _: () = assert!(size_of::<BkInsn>() == 40 && align_of::<BkInsn>() == 8);
#[cfg(target_pointer_width = "64")]
const _: () = assert!(size_of::<BkArch>() == 40);

unsafe extern "C" {
    fn bk_gdis_arch_list(buf: *mut c_char, cap: usize, needed: *mut usize) -> i32;
    fn bk_gdis_scan_arch(name: *const c_char, out: *mut BkArch) -> i32;
    fn bk_gdis_create(
        arch: u32,
        mach: u64,
        big_endian: c_int,
        options: *const c_char,
        status: *mut i32,
    ) -> *mut BkGdis;
    fn bk_gdis_begin(d: *mut BkGdis) -> i32;
    fn bk_gdis_step(
        d: *mut BkGdis,
        buf: *mut u8,
        len: usize,
        vma: u64,
        offset: usize,
        text: *mut c_char,
        text_cap: usize,
        out: *mut BkInsn,
    ) -> i32;
    fn bk_gdis_destroy(d: *mut BkGdis) -> i32;
    fn bk_gdis_take_message(buf: *mut c_char, cap: usize) -> usize;
}

/// Serialises every use of the shim and of libopcodes, whose state is
/// static.
static LIBOPCODES: Mutex<()> = Mutex::new(());

thread_local! {
    /// Whether a [`Request`] of this thread is alive, and so this thread
    /// holds [`LIBOPCODES`].
    static IN_REQUEST: Cell<bool> = const { Cell::new(false) };
}

/// Proof that the current thread may call into C: no other thread can be
/// inside the shim while a value of this type exists.
#[derive(Debug)]
enum Access {
    /// This value holds the lock.
    Locked(#[expect(dead_code, reason = "held for its destructor")] MutexGuard<'static, ()>),
    /// A live [`Request`] of this thread holds the lock, and that request is
    /// not inside C now (this thread is here instead).
    WithinRequest,
}

fn lock() -> MutexGuard<'static, ()> {
    // Nothing panics while the lock is held; a poisoned lock is still fine
    // to take, since the shim re-initialises its state on every request.
    LIBOPCODES.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Access for operations that may run while this thread has a request open
/// (lookups, and dropping a disassembler).
fn access() -> Access {
    if IN_REQUEST.get() {
        Access::WithinRequest
    } else {
        Access::Locked(lock())
    }
}

/// Access for operations that set a disassembler up, which must not happen
/// in the middle of this thread's own request: taking the lock again would
/// deadlock, and going ahead without it would change libopcodes' state
/// under the open request.
fn exclusive_access() -> Result<MutexGuard<'static, ()>, RawError> {
    if IN_REQUEST.get() {
        Err(RawError::RequestInProgress)
    } else {
        Ok(lock())
    }
}

/// The message binutils left behind, if any.
fn take_message(_access: &Access) -> Option<String> {
    let mut buf = [0u8; 256];
    // SAFETY: `buf` is writable for `buf.len()` bytes; `_access` proves no
    // other thread is inside the shim.
    let n = unsafe { bk_gdis_take_message(buf.as_mut_ptr().cast(), buf.len()) };
    let text = buf.get(..n)?;
    let text = String::from_utf8_lossy(text);
    (!text.is_empty() && text != RESET_ARTEFACT).then(|| text.into_owned())
}

fn aborted(held: &Access) -> RawError {
    RawError::Aborted {
        message: take_message(held).unwrap_or_else(|| "no message".to_owned()),
    }
}

/// The error for a shim status other than `BK_GDIS_OK`; `arch` is the
/// architecture the call was about (0 for calls about none).
fn status_error(status: i32, arch: u32, held: &Access) -> RawError {
    match status {
        BK_GDIS_NO_MEMORY => RawError::OutOfMemory,
        BK_GDIS_ABORTED => aborted(held),
        BK_GDIS_OPTIONS_CONFLICT => RawError::OptionsConflict { arch },
        BK_GDIS_QUARANTINED => RawError::Quarantined { arch },
        _ => RawError::Internal,
    }
}

pub(crate) fn architecture_names() -> Result<Vec<String>, RawError> {
    let held = access();
    let mut needed = 0usize;
    // SAFETY: a null buffer with capacity 0 is allowed by the shim; `needed`
    // is a valid out-pointer; `held` gives access.
    let status = unsafe { bk_gdis_arch_list(ptr::null_mut(), 0, &raw mut needed) };
    if status != BK_GDIS_OK {
        return Err(status_error(status, 0, &held));
    }
    let mut buf = vec![0u8; needed];
    // SAFETY: `buf` is writable for `buf.len()` bytes; `needed` is a valid
    // out-pointer; `held` gives access.
    let status = unsafe { bk_gdis_arch_list(buf.as_mut_ptr().cast(), buf.len(), &raw mut needed) };
    if status != BK_GDIS_OK {
        return Err(status_error(status, 0, &held));
    }
    drop(held);
    Ok(buf
        .split(|b| *b == 0)
        .filter(|name| !name.is_empty())
        .map(|name| String::from_utf8_lossy(name).into_owned())
        .collect())
}

pub(crate) fn scan_architecture(name: &str) -> Result<Option<ArchInfo>, RawError> {
    let Ok(name) = CString::new(name) else {
        // A name with a NUL in it names no architecture.
        return Ok(None);
    };
    let mut out = BkArch {
        arch: 0,
        mach: 0,
        bits_per_word: 0,
        bits_per_address: 0,
        arch_name: ptr::null(),
        printable_name: ptr::null(),
    };
    let held = access();
    // SAFETY: `name` is NUL-terminated and outlives the call; `out` is a
    // valid out-pointer; `held` gives access.
    let status = unsafe { bk_gdis_scan_arch(name.as_ptr(), &raw mut out) };
    match status {
        BK_GDIS_OK => {}
        BK_GDIS_UNKNOWN_ARCH => return Ok(None),
        other => return Err(status_error(other, 0, &held)),
    }
    drop(held);
    Ok(Some(ArchInfo {
        arch: out.arch,
        mach: out.mach,
        bits_per_word: out.bits_per_word,
        bits_per_address: out.bits_per_address,
        family: static_c_string(out.arch_name),
        printable_name: static_c_string(out.printable_name),
    }))
}

/// Copies a string out of BFD's constant architecture tables.
fn static_c_string(text: *const c_char) -> String {
    if text.is_null() {
        return String::new();
    }
    // SAFETY: on success the shim stores pointers to the NUL-terminated
    // strings of BFD's `bfd_arch_info_type` tables, which are constant data
    // with static storage duration.
    unsafe { CStr::from_ptr(text) }
        .to_string_lossy()
        .into_owned()
}

/// A disassembler for one architecture, machine, byte order and option
/// string: the in-process counterpart of one running `gdis`.
///
/// Work is done in requests ([`RawDisassembler::request`]): a request
/// corresponds to one block of bytes sent to `gdis`.
#[derive(Debug)]
pub struct RawDisassembler {
    handle: NonNull<BkGdis>,
    /// BFD architecture number, for errors.
    arch: u32,
    /// The request's private copy of the caller's bytes.
    bytes: Vec<u8>,
    /// Where the shim writes one instruction's text.
    text: Box<[u8; TEXT_CAPACITY]>,
}

// SAFETY: the C object behind `handle` has no thread affinity (it is plain
// heap memory plus libopcodes' statics), and every access to it goes through
// `&mut self` or `Drop` and is made under the global lock.
unsafe impl Send for RawDisassembler {}

impl RawDisassembler {
    /// Creates a disassembler for BFD architecture `arch` and machine `mach`
    /// (numbers as in [`ArchInfo`]), big- or little-endian, with an optional
    /// disassembler option string (what `objdump -M` takes).
    pub fn new(
        arch: u32,
        mach: u64,
        big_endian: bool,
        options: Option<&str>,
    ) -> Result<Self, RawError> {
        let options =
            options
                .map(CString::new)
                .transpose()
                .map_err(|nul| RawError::EmbeddedNul {
                    what: "the disassembler option string",
                    position: nul.nul_position(),
                })?;
        let mut status = BK_GDIS_OK;
        let held = Access::Locked(exclusive_access()?);
        // SAFETY: `options` is null or a NUL-terminated string that outlives
        // the call (the shim copies it); `status` is a valid out-pointer;
        // the lock is held.
        let handle = unsafe {
            bk_gdis_create(
                arch,
                mach,
                c_int::from(big_endian),
                options.as_ref().map_or(ptr::null(), |o| o.as_ptr()),
                &raw mut status,
            )
        };
        let Some(handle) = NonNull::new(handle) else {
            return Err(match status {
                BK_GDIS_NO_DISASSEMBLER => RawError::NoDisassembler { arch, mach },
                other => status_error(other, arch, &held),
            });
        };
        // A complaint about the options, if any, belongs to nobody yet.
        let _ = take_message(&held);
        drop(held);
        Ok(Self {
            handle,
            arch,
            bytes: Vec::new(),
            text: Box::new([0; TEXT_CAPACITY]),
        })
    }

    /// Starts a request over `bytes`, which are the bytes at addresses
    /// `address..address + bytes.len()`.
    ///
    /// The disassembler is reset to the state of a fresh `gdis` request, and
    /// the bytes are copied: binutils reads (and, on one target, rewrites)
    /// only that copy.
    ///
    /// The request holds the process-wide binutils lock until it is dropped:
    /// other threads' operations wait for it. On the thread that holds it,
    /// starting another request or creating a disassembler meanwhile fails
    /// with [`RawError::RequestInProgress`] (it could never proceed).
    pub fn request(&mut self, bytes: &[u8], address: u64) -> Result<Request<'_>, RawError> {
        let held = Access::Locked(exclusive_access()?);
        if cfg!(fuzzing) {
            // An exactly sized allocation, so that the address sanitizer
            // sees any read past the end of the request's bytes.
            self.bytes = Vec::with_capacity(bytes.len());
        } else {
            self.bytes.clear();
        }
        self.bytes.extend_from_slice(bytes);
        // Whatever an earlier request left unread is not this one's.
        let _ = take_message(&held);
        // SAFETY: `handle` is live (created in `new`, destroyed only in
        // `drop`); the lock is held.
        let status = unsafe { bk_gdis_begin(self.handle.as_ptr()) };
        if status != BK_GDIS_OK {
            return Err(status_error(status, self.arch, &held));
        }
        IN_REQUEST.set(true);
        Ok(Request {
            owner: self,
            address,
            abandoned: false,
            held,
        })
    }
}

impl Drop for RawDisassembler {
    fn drop(&mut self) {
        let held = access();
        // SAFETY: `handle` is live and is not used after this call; `held`
        // gives access. (Destroying a disassembler while this thread has a
        // request open on another one is fine: the shim only frees this
        // one's memory.)
        let _ = unsafe { bk_gdis_destroy(self.handle.as_ptr()) };
        let _ = take_message(&held);
    }
}

/// One block of bytes being disassembled; see [`RawDisassembler::request`].
#[derive(Debug)]
pub struct Request<'a> {
    owner: &'a mut RawDisassembler,
    address: u64,
    /// binutils aborted during this request; the shim will not continue it.
    abandoned: bool,
    /// Always [`Access::Locked`]; released when the request is dropped.
    held: Access,
}

impl Drop for Request<'_> {
    fn drop(&mut self) {
        // Messages nobody asked for end with the request.
        let _ = take_message(&self.held);
        IN_REQUEST.set(false);
    }
}

impl Request<'_> {
    /// Number of bytes in the request.
    pub fn len(&self) -> usize {
        self.owner.bytes.len()
    }

    /// Whether the request has no bytes.
    pub fn is_empty(&self) -> bool {
        self.owner.bytes.is_empty()
    }

    /// Disassembles the instruction that starts `offset` bytes into the
    /// request (at address `address + offset`, wrapping).
    ///
    /// `Ok` means binutils' print function returned; whether it decoded an
    /// instruction is told by [`Step::length`].
    pub fn step(&mut self, offset: usize) -> Result<Step<'_>, RawError> {
        let len = self.owner.bytes.len();
        if offset >= len {
            return Err(RawError::OffsetOutOfRange { offset, len });
        }
        if self.abandoned {
            return Err(RawError::Aborted {
                message: "the request was abandoned after binutils gave up earlier".to_owned(),
            });
        }
        let mut insn = BkInsn::default();
        // SAFETY:
        // - `handle` is live, and `bk_gdis_begin` succeeded on it when this
        //   request was created; the lock has been held since (`self.held`);
        // - `bytes` is this disassembler's own allocation, valid and
        //   writable for `len` bytes, not aliased (we hold `&mut` to its
        //   owner), and `offset < len`;
        // - `text` is writable for `TEXT_CAPACITY` (> 0) bytes;
        // - `insn` is a valid out-pointer;
        // - the shim keeps none of these pointers after it returns.
        let status = unsafe {
            bk_gdis_step(
                self.owner.handle.as_ptr(),
                self.owner.bytes.as_mut_ptr(),
                len,
                self.address,
                offset,
                self.owner.text.as_mut_ptr().cast(),
                TEXT_CAPACITY,
                &raw mut insn,
            )
        };
        if status != BK_GDIS_OK {
            self.abandoned = true;
            return Err(status_error(status, self.owner.arch, &self.held));
        }
        // The shim reports at most `TEXT_CAPACITY - 1` bytes; `get` keeps
        // even a wrong report from reaching past the buffer.
        let text = self.owner.text.get(..insn.text_len as usize).unwrap_or(&[]);
        Ok(Step {
            length: insn.length,
            text,
            text_truncated: insn.text_truncated != 0,
            read_fault: (insn.read_fault != 0).then_some(insn.fault_address),
            info_valid: insn.insn_info_valid != 0,
            branch_delay_insns: insn.branch_delay_insns,
            data_size: insn.data_size,
            insn_type: insn.insn_type,
            target: insn.target,
            target2: insn.target2,
        })
    }

    /// Takes the first message binutils reported since the last call (for
    /// example about an option it does not recognise), if any.
    pub fn take_message(&mut self) -> Option<String> {
        take_message(&self.held)
    }
}
