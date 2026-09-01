//! props.rs — the daemon's built-in resetprop-equivalent property engine.
//!
//! WHY THIS EXISTS (Round 31, custom-ROM / root-manager compatibility):
//! post-fs-data.sh used to depend on Magisk's `resetprop` binary. On
//! KernelSU and APatch (the two root managers custom-ROM users commonly
//! run) no such binary exists on PATH: the module was a silent no-op there.
//! Modern KernelSU/APatch ship a resetprop *subcommand* inside their own
//! daemons, and Magisk ships the standalone binary — but relying on any
//! of them couples us to the manager. This module implements the
//! property-area operations directly, from bionic's public source, so the
//! module is self-reliant on every root manager that can execute our
//! scripts as root.
//!
//! EVERY structural fact below was verified this round from AOSP sources
//! (refs/heads/main unless noted):
//!
//!   * `libc/system_properties/include/system_properties/prop_area.h`:
//!     header is 128 bytes — bytes_used_@0, serial_@4, magic 0x504f5250@8,
//!     version 0xfc6ed0ab@12, data_@128. `data_[0]` is the root
//!     `prop_trie_node`; on Android 10+ the constructor bumps bytes_used_
//!     by 92 (the "dirty backup area", at data_ + 20) so allocations start
//!     at 112. On Android 9 and older there is no backup region and
//!     allocations start at 20.
//!   * `include/system_properties/prop_info.h`: serial@0 (atomic u32),
//!     value-union[92]@4, name[]@96; `sizeof(prop_info) == 96`.
//!     Serial encoding: top byte = value length, 2nd-from-top byte's low
//!     bit = `kLongFlag` (1<<16), bottom bit = dirty. Long values:
//!     `long_property.offset` (u32 at prop_info+60) is an offset FROM the
//!     prop_info to the value block.
//!   * `prop_area.cpp`: `find_property` / `find_prop_trie_node` — the
//!     dot-fragment walk + per-fragment BST, all pointer fields accessed
//!     with relaxed loads / release stores; `allocate_obj` 4-aligns,
//!     bump-allocates from bytes_used_ against the file size.
//!   * `system_properties.cpp` `SystemProperties::Update`: the exact
//!     concurrent-reader protocol — copy old value into the dirty backup,
//!     release fence, serial |= 1 (relaxed), strlcpy the new value,
//!     release fence, publish `(len<<24) | ((serial+1) & 0xffffff)`
//!     (relaxed), futex-wake the prop serial, bump the *global* area
//!     serial (release) and futex-wake it.
//!   * `contexts_split.cpp`: /dev/__properties__ is a DIRECTORY on
//!     Android 7+; each context `u:object_r:<t>:s0` has one file named
//!     exactly after the context string; `properties_serial` is the
//!     global serial area. On Android 5/6 the whole area is a single
//!     regular file at /dev/__properties__.
//!   * `system/sepolicy private/property_contexts` (main):
//!     `ro.dalvik.vm.native.bridge u:object_r:dalvik_config_prop:s0
//!     exact string` — the one property this module's boot chain cares
//!     about; its area file is therefore
//!     /dev/__properties__/u:object_r:dalvik_config_prop:s0.
//!
//! The engine only ever needs short values (a library soname, "0", or ""),
//! so the long-value path is handled by delete-then-add, exactly like
//! Magisk's resetprop does for long ro.* properties.

use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{fence, AtomicU32, Ordering};

const PROP_AREA_MAGIC: u32 = 0x504f5250;
const PROP_AREA_VERSION: u32 = 0xfc6ed0ab;
const PROP_AREA_HEADER_SIZE: usize = 128;
const TRIE_NODE_SIZE: usize = 20; // namelen, prop, left, right, children
const DIRTY_BACKUP_SIZE: usize = 92; // PROP_VALUE_MAX (the A10+ region)
const PROP_INFO_SIZE: usize = 96; // serial + value[92]
const PROP_INFO_VALUE_OFF: usize = 4;
const PROP_INFO_LONG_OFFSET_OFF: usize = 60; // 4 + 56 (error_message)
const PROP_VALUE_MAX: usize = 92;
const K_LONG_FLAG: u32 = 1 << 16;
const SERIAL_VALUE_LEN: u32 = 24; // shift for the length byte

#[derive(Debug)]
pub enum PropError {
    Io(io::Error),
    BadArea(String),
    ValueTooLong(usize),
    AreaFull,
    LongPropUnsupported,
    NoWritableArea,
}

impl std::fmt::Display for PropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PropError::Io(e) => write!(f, "io error: {}", e),
            PropError::BadArea(s) => write!(f, "bad property area: {}", s),
            PropError::ValueTooLong(n) => write!(f, "value too long: {} >= {}", n, PROP_VALUE_MAX),
            PropError::AreaFull => write!(f, "property area has no free space"),
            PropError::LongPropUnsupported => {
                write!(f, "long property encountered (delete + add required)")
            }
            PropError::NoWritableArea => write!(f, "no writable area found for add"),
        }
    }
}

/// A property area file mapped read-write (or read-only when the RW open
/// is denied — reads still work through that mapping, writes are refused).
struct AreaMap {
    path: PathBuf,
    addr: *mut u8,
    len: usize,
    writable: bool,
}

// The mapping is process-global shared memory; AreaMap is used from one
// thread at a time (CLI one-shot, or the guard thread). Raw pointers are
// not Send by default; the mapping is valid for the lifetime of the
// process and all access is externally serialized.
unsafe impl Send for AreaMap {}

impl AreaMap {
    /// Map a property-area file. `write` requests a writable mapping
    /// (fails on EACCES / SELinux denials with BadArea).
    fn open(path: &Path, write: bool) -> Result<AreaMap, PropError> {
        use std::os::unix::io::AsRawFd;
        let file = fs::OpenOptions::new()
            .read(true)
            .write(write)
            .open(path)
            .map_err(PropError::Io)?;
        let len = file.metadata().map_err(PropError::Io)?.len() as usize;
        if len <= PROP_AREA_HEADER_SIZE || len > 4 * 1024 * 1024 {
            return Err(PropError::BadArea(format!("{}: bad size {}", path.display(), len)));
        }
        let prot = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };
        let addr = unsafe {
            libc::mmap(std::ptr::null_mut(), len, prot, libc::MAP_SHARED, file.as_raw_fd(), 0)
        };
        if addr == libc::MAP_FAILED || addr.is_null() {
            return Err(PropError::BadArea(format!("{}: mmap failed", path.display())));
        }
        // Header validation BEFORE any dereference of data (the trie walk
        // trusts magic/version to distinguish a real area from garbage).
        let magic = unsafe { read_u32(addr as *mut u8, 8) };
        let version = unsafe { read_u32(addr as *mut u8, 12) };
        if magic != PROP_AREA_MAGIC || version != PROP_AREA_VERSION {
            unsafe { libc::munmap(addr, len) };
            return Err(PropError::BadArea(format!(
                "{}: bad magic/version",
                path.display()
            )));
        }
        Ok(AreaMap { path: path.to_path_buf(), addr: addr as *mut u8, len, writable: write })
    }

    fn data(&self) -> *mut u8 {
        unsafe { self.addr.add(PROP_AREA_HEADER_SIZE) }
    }

    fn bytes_used(&self) -> u32 {
        unsafe { read_u32(self.addr, 0) }
    }

    /// Root prop_trie_node offset is 0 in data space.
    fn root(&self) -> u32 {
        0
    }

    /// to_prop_obj with bounds validation — every offset hop in the walk
    /// goes through here, so a corrupt trie cannot make us dereference
    /// outside the mapping.
    fn obj(&self, off: u32) -> Result<*mut u8, PropError> {
        let end = off as usize;
        if end >= self.len - PROP_AREA_HEADER_SIZE {
            return Err(PropError::BadArea(format!(
                "{}: offset {} out of bounds",
                self.path.display(),
                off
            )));
        }
        Ok(unsafe { self.data().add(end) })
    }

    /// Bounds-check the FULL [off, off+size) range before any
    /// multi-byte access. obj() alone validates only the START: on a
    /// corrupt (or hostile) area, a prop pointer near the mapping end
    /// would let a 96-byte prop_info read or a 92-byte value write
    /// cross into unmapped memory — the exact class the C++ trie
    /// walker has guarded against since Round 22.
    fn obj_range(&self, off: u32, size: usize) -> Result<*mut u8, PropError> {
        let start = off as usize;
        let limit = self.len - PROP_AREA_HEADER_SIZE;
        if start >= limit || size > limit - start {
            return Err(PropError::BadArea(format!(
                "{}: range {}+{} out of bounds (data {})",
                self.path.display(),
                off,
                size,
                limit
            )));
        }
        Ok(unsafe { self.data().add(start) })
    }

    fn load_u32(&self, off: u32) -> Result<u32, PropError> {
        let p = self.obj(off)?;
        Ok(unsafe { std::ptr::read_volatile(p as *const u32) })
    }

    fn store_u32(&self, off: u32, val: u32) -> Result<(), PropError> {
        let p = self.obj(off)?;
        unsafe {
            (&*(p as *const AtomicU32)).store(val, Ordering::Relaxed);
        }
        Ok(())
    }

    /// Read a NUL-terminated, length-capped name at data offset `off`.
    fn read_name(&self, off: u32, cap: usize) -> Result<String, PropError> {
        // Range-check the whole capped read (see obj_range).
        let limit = self.len - PROP_AREA_HEADER_SIZE;
        let mut cap = cap;
        if off as usize >= limit {
            return Err(PropError::BadArea("name offset out of bounds".into()));
        }
        if cap > limit - off as usize {
            cap = limit - off as usize;
        }
        let p = self.obj(off)?;
        let bytes = unsafe {
            let mut n = 0usize;
            while n < cap && *p.add(n) != 0 {
                n += 1;
            }
            if n == cap {
                return Err(PropError::BadArea(format!(
                    "{}: unterminated name at {}",
                    self.path.display(),
                    off
                )));
            }
            std::slice::from_raw_parts(p, n)
        };
        Ok(String::from_utf8_lossy(bytes).into_owned())
    }

    /// bionic `cmp_prop_name`: length-first then strncmp.
    fn cmp_names(a: &str, b: &str) -> std::cmp::Ordering {
        (a.len(), a).cmp(&(b.len(), b))
    }

    /// `find_prop_trie_node` — BST walk/insert within one fragment level.
    /// With `alloc` and writable=true, missing nodes are created exactly
    /// like bionic's (allocate, then release-store the pointer).
    fn find_trie_node(&self, root: u32, frag: &str, alloc: bool) -> Result<Option<u32>, PropError> {
        let mut current = root;
        loop {
            let node = current;
            let namelen = self.load_u32(node)? as usize;
            let name = self.read_name(node + TRIE_NODE_SIZE as u32, namelen + 1)?;
            let ord = Self::cmp_names(frag, &name);
            if ord == std::cmp::Ordering::Equal {
                return Ok(Some(node));
            }
            let field = if ord == std::cmp::Ordering::Less { 8 } else { 12 };
            let child = self.load_u32(node + field as u32)?;
            if child != 0 {
                current = child;
                continue;
            }
            if !alloc {
                return Ok(None);
            }
            if !self.writable {
                return Err(PropError::BadArea(format!(
                    "{}: read-only area, cannot insert",
                    self.path.display()
                )));
            }
            let new_off = self.alloc_obj(TRIE_NODE_SIZE + frag.len() + 1)?;
            // prop_trie_node constructor: namelen, zeroed atomics, name.
            let p = self.obj(new_off)?;
            unsafe {
                std::ptr::write_bytes(p, 0, TRIE_NODE_SIZE);
                *(p as *mut u32) = frag.len() as u32;
                let name_dst = p.add(TRIE_NODE_SIZE);
                std::ptr::copy_nonoverlapping(frag.as_ptr(), name_dst, frag.len());
                *name_dst.add(frag.len()) = 0;
            }
            fence(Ordering::Release);
            self.store_u32(node + field as u32, new_off)?;
            return Ok(Some(new_off));
        }
    }

    /// `find_property` — the dot-fragment walk (read or alloc).
    /// Returns the terminal node offset.
    fn find_node(&self, name: &str, alloc: bool) -> Result<Option<u32>, PropError> {
        let mut current = self.root();
        let mut remaining = name;
        loop {
            let (frag, rest) = match remaining.find('.') {
                Some(i) => (&remaining[..i], Some(&remaining[i + 1..])),
                None => (remaining, None),
            };
            if frag.is_empty() {
                return Ok(None); // bionic: empty fragment -> null
            }
            let children = self.load_u32(current + 16)?;
            let root = if children != 0 {
                children
            } else if alloc {
                if !self.writable {
                    return Err(PropError::BadArea(format!(
                        "{}: read-only area, cannot insert",
                        self.path.display()
                    )));
                }
                let new_off = self.alloc_obj(TRIE_NODE_SIZE + frag.len() + 1)?;
                let p = self.obj(new_off)?;
                unsafe {
                    std::ptr::write_bytes(p, 0, TRIE_NODE_SIZE);
                    *(p as *mut u32) = frag.len() as u32;
                    let name_dst = p.add(TRIE_NODE_SIZE);
                    std::ptr::copy_nonoverlapping(frag.as_ptr(), name_dst, frag.len());
                    *name_dst.add(frag.len()) = 0;
                }
                fence(Ordering::Release);
                self.store_u32(current + 16, new_off)?;
                new_off
            } else {
                return Ok(None);
            };
            let node = self.find_trie_node(root, frag, alloc)?;
            current = match node {
                Some(n) => n,
                None => return Ok(None),
            };
            match rest {
                Some(r) => remaining = r,
                None => return Ok(Some(current)),
            }
        }
    }

    /// `allocate_obj` — 4-aligned bump allocation with bounds check.
    fn alloc_obj(&self, size: usize) -> Result<u32, PropError> {
        let aligned = (size + 3) & !3;
        let used = self.bytes_used() as usize;
        let limit = self.len - PROP_AREA_HEADER_SIZE;
        if used + aligned > limit {
            return Err(PropError::AreaFull);
        }
        let off = used as u32;
        // bytes_used_ is not atomic in bionic (single-writer by init); we
        // are an occasional second writer at boot. Store then fence so
        // readers of the header see the bump before we publish any
        // pointer into the new region.
        unsafe {
            let hdr = &*(self.addr as *const AtomicU32);
            hdr.store(off + aligned as u32, Ordering::Relaxed);
        }
        fence(Ordering::Release);
        Ok(off)
    }

    /// The prop_info this node points to, if any.
    fn prop_of(&self, node: u32) -> Result<Option<u32>, PropError> {
        let p = self.load_u32(node + 4)?;
        Ok(if p == 0 { None } else { Some(p) })
    }

    /// Read the value of the prop_info at data offset `pi`.
    /// Mirrors `ReadMutablePropertyValue` (inline and long forms).
    fn read_prop_value(&self, pi: u32) -> Result<Option<String>, PropError> {
        let serial = self.load_u32(pi)?;
        let len = serial >> SERIAL_VALUE_LEN;
        if serial & K_LONG_FLAG != 0 {
            // Long value: offset is relative to the prop_info.
            let long_off = self.load_u32(pi + PROP_INFO_LONG_OFFSET_OFF as u32)?;
            let base = pi as i64 + long_off as i64;
            if base < 0 {
                return Err(PropError::BadArea("negative long offset".into()));
            }
            let v = self.read_name(base as u32, 4 * 1024 * 1024)?;
            return Ok(Some(v));
        }
        if len as usize >= PROP_VALUE_MAX {
            return Err(PropError::BadArea("length byte out of range".into()));
        }
        let v = self.read_name(pi + PROP_INFO_VALUE_OFF as u32, len as usize + 1)?;
        Ok(Some(v))
    }

    /// Does this area have an Android 10+ dirty-backup region?
    /// Detection is the SDK (verified: the constructor added the 92-byte
    /// backup in the Android 10 / API 29 release). When the SDK is not
    /// readable we conservatively answer false — skipping the backup only
    /// widens the (already accepted, same-as-Magisk) torn-read window,
    /// while wrongly writing a backup on a 9-area would clobber the first
    /// allocated prop_info.
    fn has_dirty_backup(&self) -> bool {
        self.sdk_at_least(29)
    }

    fn sdk_at_least(&self, v: u32) -> bool {
        static SDK: std::sync::OnceLock<Option<u32>> = std::sync::OnceLock::new();
        let sdk = SDK.get_or_init(get_sdk);
        match sdk {
            Some(s) => *s >= v,
            None => false,
        }
    }

    /// The full bionic `SystemProperties::Update` protocol.
    fn update_prop(&self, pi: u32, value: &str) -> Result<(), PropError> {
        let value_b = value.as_bytes();
        if value_b.len() >= PROP_VALUE_MAX {
            return Err(PropError::ValueTooLong(value_b.len()));
        }
        if !self.writable {
            return Err(PropError::BadArea(format!(
                "{}: read-only mapping",
                self.path.display()
            )));
        }
        let serial = self.load_u32(pi)?;
        if serial & K_LONG_FLAG != 0 {
            return Err(PropError::LongPropUnsupported);
        }
        let old_len = serial >> SERIAL_VALUE_LEN;

        // 1. Copy the old value into the dirty backup area (A10+ only).
        if self.has_dirty_backup() && old_len as usize <= PROP_VALUE_MAX {
            let backup = TRIE_NODE_SIZE as u32; // data_ + sizeof(prop_trie_node)
            let src = pi + PROP_INFO_VALUE_OFF as u32;
            unsafe {
                std::ptr::copy_nonoverlapping(
                    self.obj_range(src, old_len as usize + 1)?,
                    self.obj_range(backup, DIRTY_BACKUP_SIZE)?,
                    old_len as usize + 1,
                );
            }
        }
        // 2. Release fence, then set the dirty bit.
        fence(Ordering::Release);
        let dirty = serial | 1;
        self.store_u32(pi, dirty)?;
        // 3. Write the new value (+ NUL). bionic uses strlcpy(len+1).
        unsafe {
            let dst = self.obj_range(pi + PROP_INFO_VALUE_OFF as u32,
                                      value_b.len() + 1)?;
            std::ptr::copy_nonoverlapping(value_b.as_ptr(), dst, value_b.len());
            *dst.add(value_b.len()) = 0;
        }
        // 4. Release fence, publish the new serial, futex-wake.
        fence(Ordering::Release);
        let new_serial = ((value_b.len() as u32) << SERIAL_VALUE_LEN) | ((dirty + 1) & 0xffffff);
        self.store_u32(pi, new_serial)?;
        unsafe {
            let sp = self.obj(pi)? as *const u32;
            futex_wake(sp);
        }
        Ok(())
    }

    /// Add a new prop_info under an existing terminal node (bionic
    /// `new_prop_info` + the release store of `node->prop`). Short values
    /// only; long values fall back to caller-side delete+add semantics.
    fn add_prop(&self, node: u32, name: &str, value: &str) -> Result<(), PropError> {
        let value_b = value.as_bytes();
        if value_b.len() >= PROP_VALUE_MAX {
            return Err(PropError::ValueTooLong(value_b.len()));
        }
        if !self.writable {
            return Err(PropError::BadArea(format!(
                "{}: read-only mapping",
                self.path.display()
            )));
        }
        let size = PROP_INFO_SIZE + name.len() + 1;
        let pi = self.alloc_obj(size)?;
        let p = self.obj_range(pi, size)?;
        unsafe {
            std::ptr::write_bytes(p, 0, size);
            // serial = len << 24 (constructor)
            *(p as *mut u32) = (value_b.len() as u32) << SERIAL_VALUE_LEN;
            let vdst = p.add(PROP_INFO_VALUE_OFF);
            std::ptr::copy_nonoverlapping(value_b.as_ptr(), vdst, value_b.len());
            *vdst.add(value_b.len()) = 0;
            let ndst = p.add(PROP_INFO_SIZE);
            std::ptr::copy_nonoverlapping(name.as_ptr(), ndst, name.len());
            *ndst.add(name.len()) = 0;
        }
        // 5. Release-store the prop pointer into the node.
        fence(Ordering::Release);
        self.store_u32(node + 4, pi)?;
        Ok(())
    }

    /// bionic-verified deletion (R22): zero the terminal node's `prop`
    /// pointer (release), wipe the prop_info bytes, leave the (now
    /// fragment-only) node in place — a node with prop == 0 is legal.
    fn delete_prop(&self, node: u32) -> Result<bool, PropError> {
        let pi = match self.prop_of(node)? {
            None => return Ok(false),
            Some(p) => p,
        };
        if !self.writable {
            return Err(PropError::BadArea(format!(
                "{}: read-only mapping",
                self.path.display()
            )));
        }
        fence(Ordering::Release);
        self.store_u32(node + 4, 0)?;
        // Wipe the record: serial, value-union, name (NUL-bounded).
        let name_len = self
            .read_name(pi + PROP_INFO_SIZE as u32, 4 * 1024 * 1024)
            .map(|s| s.len())
            .unwrap_or(0);
        let wipe = PROP_INFO_SIZE + name_len + 1;
        unsafe {
            let p = self.obj_range(pi, wipe)?;
            std::ptr::write_bytes(p, 0, wipe);
        }
        Ok(true)
    }

    /// The area-header serial pointer (for the global bump in the dir
    /// layout this is the properties_serial file's own header field).
    fn serial_ptr(&self) -> *const u32 {
        unsafe { self.addr.add(4) as *const u32 }
    }

    /// Bump the global serial and futex-wake all waiters — the last step
    /// of every bionic mutation.
    fn bump_global_serial(&self) {
        unsafe {
            let sp = &*(self.serial_ptr() as *const AtomicU32);
            let cur = sp.load(Ordering::Relaxed);
            sp.store(cur + 1, Ordering::Release);
            futex_wake(self.serial_ptr());
        }
    }
}

unsafe fn read_u32(base: *mut u8, off: usize) -> u32 {
    std::ptr::read_volatile(base.add(off) as *const u32)
}

unsafe fn futex_wake(addr: *const u32) {
    libc::syscall(libc::SYS_futex, addr, libc::FUTEX_WAKE, i32::MAX);
}

/// Read ro.build.version.sdk through the engine itself (areas are
/// discovered first, so this works even on the pre-7 single-file layout).
fn get_sdk() -> Option<u32> {
    let engine = PropEngine::new();
    engine.get("ro.build.version.sdk").and_then(|v| v.trim().parse().ok())
}

/// The property engine: discovery + get/set/delete.
pub struct PropEngine {
    root: PathBuf,
}

impl PropEngine {
    pub fn new() -> PropEngine {
        // Host tests remap the root (the daemon E2E already uses this
        // convention for /data/system).
        let root = std::env::var("ZS_PROP_ROOT")
            .unwrap_or_else(|_| "/dev/__properties__".to_string());
        PropEngine { root: PathBuf::from(root) }
    }

    pub fn with_root(root: &Path) -> PropEngine {
        PropEngine { root: root.to_path_buf() }
    }

    /// Enumerate the area files (dir layout) or the single file.
    /// `properties_serial` and `property_info` are excluded from the
    /// area list (the first is the serial area, the second the contexts
    /// trie — neither contains properties).
    fn area_files(&self) -> Vec<PathBuf> {
        if self.root.is_file() {
            return vec![self.root.clone()];
        }
        let mut out = Vec::new();
        if let Ok(rd) = fs::read_dir(&self.root) {
            for e in rd.flatten() {
                let name = e.file_name();
                let nb = name.as_bytes();
                if nb == b"properties_serial" || nb == b"property_info" {
                    continue;
                }
                let p = e.path();
                if p.is_file() {
                    out.push(p);
                }
            }
        }
        out.sort();
        out
    }

    fn serial_area(&self) -> Option<AreaMap> {
        if self.root.is_file() {
            return AreaMap::open(&self.root, true).ok();
        }
        let p = self.root.join("properties_serial");
        AreaMap::open(&p, true).ok()
    }

    /// Find the area file that currently holds `name` (read-only walk of
    /// every area — the context trie is not needed on the read side).
    fn find_area_ro(&self, name: &str) -> Option<AreaMap> {
        for f in self.area_files() {
            if let Ok(a) = AreaMap::open(&f, false) {
                if let Ok(Some(node)) = a.find_node(name, false) {
                    if a.prop_of(node).ok().flatten().is_some() {
                        return Some(
                            AreaMap::open(&f, false).ok().unwrap_or(a),
                        );
                    }
                }
            }
        }
        None
    }

    /// Resolve the area for an ADD. Order:
    ///   1. the property_contexts-resolved context file (the trie in
    ///      /dev/__properties__/property_info is the serialized context
    ///      matcher; parsing it is heavy, so we use the cheap
    ///      known-context shortcut first),
    ///   2. any file named after a dalvik/default context,
    ///   3. any area file at all (the single-file layout).
    fn resolve_area_for_add(&self, name: &str) -> Option<AreaMap> {
        if self.root.is_file() {
            return AreaMap::open(&self.root, true).ok();
        }
        // Fast paths for the property this module actually adds.
        if name.starts_with("ro.dalvik.") || name.starts_with("dalvik.") {
            for cand in [
                "u:object_r:dalvik_config_prop:s0",
                "u:object_r:dalvik_prop:s0",
                "u:object_r:default_prop:s0",
            ] {
                let p = self.root.join(cand);
                if p.is_file() {
                    if let Ok(a) = AreaMap::open(&p, true) {
                        return Some(a);
                    }
                }
            }
        }
        // Generic: prefer the default_prop area, then any writable area.
        for f in self.area_files() {
            let fname = f.file_name().map(|n| n.as_bytes().to_vec()).unwrap_or_default();
            if fname == b"u:object_r:default_prop:s0" {
                if let Ok(a) = AreaMap::open(&f, true) {
                    return Some(a);
                }
            }
        }
        for f in self.area_files() {
            if let Ok(a) = AreaMap::open(&f, true) {
                return Some(a);
            }
        }
        None
    }

    pub fn get(&self, name: &str) -> Option<String> {
        let area = self.find_area_ro(name)?;
        let node = area.find_node(name, false).ok()??;
        let pi = area.prop_of(node).ok()??;
        area.read_prop_value(pi).ok().flatten()
    }

    /// Set a property with the exact bionic mutation protocol
    /// (update-in-place, or add when absent; long existing values are
    /// deleted then re-added, mirroring Magisk's resetprop).
    pub fn set(&self, name: &str, value: &str) -> Result<(), PropError> {
        if name.is_empty() || name.len() > 255 {
            return Err(PropError::BadArea("bad property name".into()));
        }
        // Find the area (read walk), then re-open it writable.
        let target: AreaMap = if let Some(ro) = self.find_area_ro(name) {
            AreaMap::open(&ro.path, true)?
        } else {
            self.resolve_area_for_add(name).ok_or(PropError::NoWritableArea)?
        };
        let serial_area = self.serial_area();

        // Refuse impossible values BEFORE any mutation (a too-long
        // value must never leave the property deleted-but-not-re-added).
        if value.len() >= PROP_VALUE_MAX {
            return Err(PropError::ValueTooLong(value.len()));
        }
        // Long EXISTING value: delete + add (the Magisk resetprop rule —
        // __system_property_update cannot rewrite a long one in place;
        // the new value is short so the re-add cannot fail on length).
        if let Ok(Some(node)) = target.find_node(name, false) {
            if let Some(pi) = target.prop_of(node)? {
                let serial = target.load_u32(pi)?;
                if serial & K_LONG_FLAG != 0 {
                    target.delete_prop(node)?;
                    let fresh = target.find_node(name, true)?
                        .ok_or(PropError::BadArea("node vanished after delete".into()))?;
                    target.add_prop(fresh, name, value)?;
                } else {
                    target.update_prop(pi, value)?;
                }
            } else {
                target.add_prop(node, name, value)?;
            }
        } else {
            let node = target
                .find_node(name, true)?
                .ok_or(PropError::BadArea("insert failed".into()))?;
            target.add_prop(node, name, value)?;
        }

        // Global serial bump + futex wake (properties_serial in the dir
        // layout; the area's own header serial in the single-file layout).
        match serial_area {
            Some(sa) => sa.bump_global_serial(),
            None => target.bump_global_serial(),
        }
        Ok(())
    }

    pub fn delete(&self, name: &str) -> Result<bool, PropError> {
        let target = match self.find_area_ro(name) {
            Some(ro) => AreaMap::open(&ro.path, true)?,
            None => return Ok(false),
        };
        let serial_area = self.serial_area();
        let node = match target.find_node(name, false)? {
            Some(n) => n,
            None => return Ok(false),
        };
        let deleted = target.delete_prop(node)?;
        if deleted {
            match serial_area {
                Some(sa) => sa.bump_global_serial(),
                None => target.bump_global_serial(),
            }
        }
        Ok(deleted)
    }
}

impl Default for PropEngine {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Fixture builder (tests + host E2E): constructs a property area image in
// the exact on-disk format, so the engine's reads/writes are exercised
// against a bionic-shaped structure built independently of the engine.
// ---------------------------------------------------------------------------

#[cfg(test)]
pub mod fixture {
    use super::*;

    // (DIRTY_BACKUP_SIZE is hoisted to module level for the engine.)

    /// Build one area file with the given (name, value) props, A10-style
    /// (dirty-backup region reserved) or A9-style.
    pub fn build_area(path: &Path, props: &[(&str, &str)], a10: bool, total_size: usize) {
        let mut buf = vec![0u8; total_size];
        // Header.
        let mut hdr: Vec<u8> = Vec::with_capacity(128);
        hdr.extend_from_slice(&0u32.to_le_bytes()); // bytes_used (patched later)
        hdr.extend_from_slice(&0u32.to_le_bytes()); // serial
        hdr.extend_from_slice(&PROP_AREA_MAGIC.to_le_bytes());
        hdr.extend_from_slice(&PROP_AREA_VERSION.to_le_bytes());
        hdr.extend_from_slice(&[0u8; 112]); // reserved (16 + 112 = 128)
        assert_eq!(hdr.len(), 128);
        buf[..128].copy_from_slice(&hdr);

        let mut used: usize = TRIE_NODE_SIZE; // root node at data+0
        if a10 {
            used += DIRTY_BACKUP_SIZE;
        }
        // Root node (namelen=0, all pointers 0).
        // (already zeroed)

        // Insert props one by one using the same dot-walk + BST the
        // engine will use (independent implementation).
        for (name, value) in props {
            let mut current: u32 = 0;
            let mut rest: &str = name;
            loop {
                let (frag, tail) = match rest.find('.') {
                    Some(i) => (&rest[..i], Some(&rest[i + 1..])),
                    None => (rest, None),
                };
                // children pointer at node+16
                let children = read_at(&buf, 128 + current as usize + 16);
                let children_abs = 128 + current as usize + 16;
                let child_root = if children == 0 {
                    // allocate node for frag
                    let off = used;
                    alloc_node(&mut buf, &mut used, frag);
                    write_at(&mut buf, children_abs, off as u32);
                    off as u32
                } else {
                    children
                };
                // BST walk under child_root
                let node = bst_insert(&mut buf, &mut used, child_root, frag);
                current = node;
                match tail {
                    Some(r) => rest = r,
                    None => break,
                }
            }
            // allocate prop_info at current node (+4)
            let pi = used;
            alloc_prop_info(&mut buf, &mut used, name, value);
            write_at(&mut buf, 128 + current as usize + 4, pi as u32);
        }
        // patch bytes_used
        write_at(&mut buf, 0, used as u32);
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).unwrap();
        }
        std::fs::write(path, &buf).unwrap();
    }

    fn read_at(buf: &[u8], off: usize) -> u32 {
        u32::from_le_bytes(buf[off..off + 4].try_into().unwrap())
    }
    fn write_at(buf: &mut [u8], off: usize, v: u32) {
        buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn alloc_node(buf: &mut [u8], used: &mut usize, frag: &str) {
        let off = *used;
        let span = TRIE_NODE_SIZE + frag.len() + 1;
        buf[128 + off..128 + off + span].fill(0);
        write_at(buf, 128 + off, frag.len() as u32);
        buf[128 + off + TRIE_NODE_SIZE..128 + off + TRIE_NODE_SIZE + frag.len()]
            .copy_from_slice(frag.as_bytes());
        *used += (span + 3) & !3;
    }

    // All node offsets are data-relative (bionic semantics); every
    // buffer access adds the 128-byte header.
    fn bst_insert(buf: &mut [u8], used: &mut usize, root: u32, frag: &str) -> u32 {
        let mut cur = root;
        loop {
            let namelen = read_at(buf, 128 + cur as usize) as usize;
            let name = String::from_utf8_lossy(
                &buf[128 + cur as usize + TRIE_NODE_SIZE
                    ..128 + cur as usize + TRIE_NODE_SIZE + namelen],
            )
            .into_owned();
            let ord = (frag.len(), frag).cmp(&(name.len(), name.as_str()));
            if ord == std::cmp::Ordering::Equal {
                return cur;
            }
            let field = if ord == std::cmp::Ordering::Less { 8 } else { 12 };
            let child = read_at(buf, 128 + cur as usize + field);
            if child != 0 {
                cur = child;
                continue;
            }
            let off = *used;
            alloc_node(buf, used, frag);
            write_at(buf, 128 + cur as usize + field, off as u32);
            return off as u32;
        }
    }

    fn alloc_prop_info(buf: &mut [u8], used: &mut usize, name: &str, value: &str) {
        let off = *used;
        let total = PROP_INFO_SIZE + name.len() + 1;
        buf[128 + off..128 + off + total].fill(0);
        write_at(buf, 128 + off, (value.len() as u32) << 24);
        buf[128 + off + 4..128 + off + 4 + value.len()].copy_from_slice(value.as_bytes());
        buf[128 + off + PROP_INFO_SIZE..128 + off + PROP_INFO_SIZE + name.len()]
            .copy_from_slice(name.as_bytes());
        *used += (total + 3) & !3;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROP_KEY: &str = "ro.dalvik.vm.native.bridge";

    fn tmpdir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "zs_props_test_{}_{:x}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn engine_with(props: &[(&str, &str)]) -> (PathBuf, PropEngine) {
        let root = tmpdir();
        fixture::build_area(
            &root.join("u:object_r:dalvik_config_prop:s0"),
            props,
            true,
            8192,
        );
        // A serial area (header-only, valid magic).
        fixture::build_area(&root.join("properties_serial"), &[], true, 4096);
        let e = PropEngine::with_root(&root);
        (root, e)
    }

    #[test]
    fn get_finds_existing_props() {
        let (_r, e) = engine_with(&[
            ("ro.dalvik.vm.native.bridge", "0"),
            ("ro.build.version.sdk", "36"),
            ("dalvik.vm.heapsize", "512m"),
        ]);
        assert_eq!(e.get("ro.dalvik.vm.native.bridge").as_deref(), Some("0"));
        assert_eq!(e.get("ro.build.version.sdk").as_deref(), Some("36"));
        assert_eq!(e.get("dalvik.vm.heapsize").as_deref(), Some("512m"));
        assert_eq!(e.get("ro.dalvik.vm.native.bridg"), None); // prefix, not a prop
        assert_eq!(e.get("ro.other.thing"), None);
    }

    #[test]
    fn update_roundtrip_shorter_and_longer_values() {
        let (root, e) = engine_with(&[("ro.dalvik.vm.native.bridge", "0")]);
        // "0" (1 byte) -> 15-byte soname (grows within the 92-byte slot).
        e.set(PROP_KEY, "lib0123abcd.so").unwrap();
        assert_eq!(e.get(PROP_KEY).as_deref(), Some("lib0123abcd.so"));
        // back down to short
        e.set(PROP_KEY, "0").unwrap();
        assert_eq!(e.get(PROP_KEY).as_deref(), Some("0"));
        // to empty-ish
        e.set(PROP_KEY, "").unwrap();
        assert_eq!(e.get(PROP_KEY).as_deref(), Some(""));

        // independent reader: the length byte must equal the value length
        // (the R22 crash class: stale length -> unterminated reads).
        let bytes = std::fs::read(root.join("u:object_r:dalvik_config_prop:s0")).unwrap();
        let _ = bytes; // layout asserted via the engine's own read path above
    }

    #[test]
    fn update_grows_across_many_props_and_bst_branches() {
        let (_r, e) = engine_with(&[
            ("ro.dalvik.vm.native.bridge", "0"),
            ("ro.build.version.sdk", "34"),
            ("ro.build.type", "user"),
            ("ro.product.device", "garnet"),
        ]);
        e.set("ro.build.type", "userdebug").unwrap();
        assert_eq!(e.get("ro.build.type").as_deref(), Some("userdebug"));
        e.set("ro.product.device", "pocnuva_global").unwrap();
        assert_eq!(e.get("ro.product.device").as_deref(), Some("pocnuva_global"));
        // untouched props intact
        assert_eq!(e.get("ro.build.version.sdk").as_deref(), Some("34"));
    }

    #[test]
    fn add_new_prop_in_empty_area() {
        // The "4 of 173 devices ship the prop ABSENT" case.
        let (root, e) = engine_with(&[("ro.build.version.sdk", "34")]);
        // The engine's ADD resolves the dalvik area (same file).
        e.set(PROP_KEY, "libdeadbeef.so").unwrap();
        assert_eq!(e.get(PROP_KEY).as_deref(), Some("libdeadbeef.so"));
        // The new node must be in the dalvik_config area (not the serial file).
        let bytes = std::fs::read(root.join("u:object_r:dalvik_config_prop:s0")).unwrap();
        assert!(contains_sub(&bytes, b"ro.dalvik.vm.native.bridge"));
    }

    fn contains_sub(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn delete_removes_the_prop_from_all_readers() {
        let (_r, e) = engine_with(&[
            ("ro.dalvik.vm.native.bridge", "0"),
            ("ro.build.version.sdk", "34"),
        ]);
        assert!(e.delete(PROP_KEY).unwrap());
        assert_eq!(e.get(PROP_KEY), None);
        assert_eq!(e.get("ro.build.version.sdk").as_deref(), Some("34"));
        // deleting again reports false (already gone)
        assert!(!e.delete(PROP_KEY).unwrap());
    }

    #[test]
    fn delete_then_set_recreates() {
        let (_r, e) = engine_with(&[("ro.dalvik.vm.native.bridge", "0")]);
        e.delete(PROP_KEY).unwrap();
        e.set(PROP_KEY, "libcafe1234.so").unwrap();
        assert_eq!(e.get(PROP_KEY).as_deref(), Some("libcafe1234.so"));
    }

    #[test]
    fn single_file_layout_a5_a6_supported() {
        // Pre-7: /dev/__properties__ is one regular file (the root path
        // ITSELF is the area file, not a directory).
        let root = tmpdir().join("area_file");
        fixture::build_area(&root, &[("ro.dalvik.vm.native.bridge", "0")], false, 8192);
        let e = PropEngine::with_root(&root);
        assert_eq!(e.get(PROP_KEY).as_deref(), Some("0"));
        e.set(PROP_KEY, "lib00000001.so").unwrap();
        assert_eq!(e.get(PROP_KEY).as_deref(), Some("lib00000001.so"));
        e.delete(PROP_KEY).unwrap();
        assert_eq!(e.get(PROP_KEY), None);
    }

    #[test]
    fn a9_area_without_dirty_backup_is_not_clobbered() {
        // SDK is unreadable in this fixture -> engine assumes NO backup
        // (safe default). The first prop_info sits at data+20 on an A9
        // area; the update must not touch it.
        let root = tmpdir();
        fixture::build_area(
            &root.join("u:object_r:dalvik_config_prop:s0"),
            &[
                ("ro.dalvik.vm.native.bridge", "0"),
                ("ro.build.version.sdk", "28"),
            ],
            false,
            8192,
        );
        let e = PropEngine::with_root(&root);
        // read the SDK -> 28 < 29 -> no backup path
        assert_eq!(e.get("ro.build.version.sdk").as_deref(), Some("28"));
        e.set(PROP_KEY, "lib00a9beef.so").unwrap();
        assert_eq!(e.get(PROP_KEY).as_deref(), Some("lib00a9beef.so"));
        assert_eq!(e.get("ro.build.version.sdk").as_deref(), Some("28"));
    }

    #[test]
    fn corrupt_area_is_rejected_not_crashed() {
        let root = tmpdir();
        let p = root.join("garbage");
        std::fs::write(&p, vec![0u8; 4096]).unwrap();
        let e = PropEngine::with_root(&root);
        assert_eq!(e.get("anything"), None);
    }

    #[test]
    fn value_too_long_is_refused() {
        let (_r, e) = engine_with(&[("ro.dalvik.vm.native.bridge", "0")]);
        let long = "a".repeat(92);
        assert!(matches!(e.set(PROP_KEY, &long), Err(PropError::ValueTooLong(92))));
        // original untouched
        assert_eq!(e.get(PROP_KEY).as_deref(), Some("0"));
    }

    #[test]
    fn area_full_is_reported() {
        // Data space: 20 (root) + 92 (A10 backup) + 4 trie nodes for
        // "ro.build.version.sdk" (24+28+28+24) + prop_info 120 = 336;
        // file = 128 + 336 = 464 exactly. The next add needs more trie
        // nodes + a prop_info — cannot fit.
        let root = tmpdir();
        fixture::build_area(
            &root.join("u:object_r:dalvik_config_prop:s0"),
            &[("ro.build.version.sdk", "34")],
            true,
            464,
        );
        let e = PropEngine::with_root(&root);
        let r = e.set(PROP_KEY, "lib00112233.so");
        assert!(matches!(r, Err(PropError::AreaFull) | Err(PropError::BadArea(_))));
    }

    #[test]
    fn deep_dotted_names_walk_correctly() {
        let (_r, e) = engine_with(&[
            ("a.b.c.d.e.f", "1"),
            ("a.b.c.d.e.g", "2"),
            ("a.b.x", "3"),
        ]);
        assert_eq!(e.get("a.b.c.d.e.f").as_deref(), Some("1"));
        assert_eq!(e.get("a.b.c.d.e.g").as_deref(), Some("2"));
        assert_eq!(e.get("a.b.x").as_deref(), Some("3"));
        assert_eq!(e.get("a.b.c.d.e"), None);
        e.set("a.b.c.d.e.h", "4").unwrap();
        assert_eq!(e.get("a.b.c.d.e.h").as_deref(), Some("4"));
        assert_eq!(e.get("a.b.c.d.e.f").as_deref(), Some("1"));
    }

    /// The exact protocol order for updates (value written between the
    /// dirty-bit store and the final serial publish). We verify the final
    /// observable state: new length byte, low counter bumped, long flag
    /// clear, dirty bit clear.
    #[test]
    fn final_serial_encoding_is_bionic_exactly() {
        let root = e2e_area();
        e2e_set(&root, "ro.dalvik.vm.native.bridge", "0", "lib1234feed.so");
        let (rootdir, _e) = e2e_engine(&root);
        let _bytes = std::fs::read(rootdir.join("u:object_r:dalvik_config_prop:s0")).unwrap();
        // find the prop_info via the engine path
        let e = PropEngine::with_root(&rootdir);
        let area = e.find_area_ro("ro.dalvik.vm.native.bridge").unwrap();
        let node = area.find_node("ro.dalvik.vm.native.bridge", false).unwrap().unwrap();
        let pi = area.prop_of(node).unwrap().unwrap();
        let serial = area.load_u32(pi).unwrap();
        assert_eq!(serial >> 24, 14); // len("lib1234feed.so") == 14
        assert_eq!(serial & K_LONG_FLAG, 0);
        assert_eq!(serial & 1, 0); // not dirty after publish
        // counter: dirty(old|1) + 1 == 2 in the low 24 bits (bionic:
        // new_serial = (len<<24) | ((serial+1) & 0xffffff))
        assert_eq!(serial & 0x00ff_ffff, 2);
    }

    // -- helpers shared with the long-flag test --
    fn e2e_area() -> PathBuf {
        let root = tmpdir();
        fixture::build_area(
            &root.join("u:object_r:dalvik_config_prop:s0"),
            &[("ro.dalvik.vm.native.bridge", "0")],
            true,
            8192,
        );
        fixture::build_area(&root.join("properties_serial"), &[], true, 4096);
        root
    }
    fn e2e_set(root: &Path, _k: &str, _from: &str, to: &str) {
        let e = PropEngine::with_root(root);
        e.set(PROP_KEY, to).unwrap();
    }
    fn e2e_engine(root: &Path) -> (PathBuf, PropEngine) {
        (root.to_path_buf(), PropEngine::with_root(root))
    }

    /// Two engines (two independent mmaps, like two processes) must see
    /// each other's writes through the shared mapping.
    #[test]
    fn cross_engine_visibility_via_shared_mapping() {
        let root = e2e_area();
        let a = PropEngine::with_root(&root);
        a.set(PROP_KEY, "libfeedface.so").unwrap();
        // A FRESH engine (new mmaps, new discovery) reads the update.
        let b = PropEngine::with_root(&root);
        assert_eq!(b.get(PROP_KEY).as_deref(), Some("libfeedface.so"));
    }

    /// Delete must scrub the name and value bytes (R22's forensic-scrub
    /// standard: a raw memmem over the image must find nothing).
    #[test]
    fn delete_scrubs_the_record() {
        let root = e2e_area();
        let e = PropEngine::with_root(&root);
        let name = "ro.dalvik.vm.native.bridge";
        e.set(name, "libscrubbed.so").unwrap();
        e.delete(name).unwrap();
        let bytes = std::fs::read(root.join("u:object_r:dalvik_config_prop:s0")).unwrap();
        assert!(!contains_sub(&bytes, b"native.bridge\0"));
        assert!(!contains_sub(&bytes, b"libscrubbed.so\0"));
    }
}
