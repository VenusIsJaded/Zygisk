// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/hide_advanced.h
//
// Advanced runtime stealth layer — additional hiding techniques
// layered on top of the basic hide layer in hide.h.
//
// The basic layer (hide.cpp) does three things:
//   1. unshare(CLONE_NEWNS) + umount2(/data/adb/...)
//   2. __system_property_set(magisk_keys, "")
//   3. munmap(our_own_so_files)
//
// The advanced layer (hide_advanced.cpp) does four more things, all
// of which are publicly-documented Android rooting techniques:
//
//   4. Clone the property area MAP_PRIVATE so a direct
//      __system_property_get() (or a direct mmap of
//      /dev/__properties__/...) returns scrubbed values, not just
//      the __system_property_set() view.
//
//   5. Hook libc open()/openat() via PLT/GOT patching so reads of
//      /proc/self/maps and /proc/self/mounts return a filtered
//      version with our entries removed. Defeats the standard
//      "read /proc/self/maps and grep for lib*.so" detection.
//
//   6. After fork, scrub our file descriptors and any environment
//      variables we set during init. Defeats the "check open fds"
//      and "check env" detection.
//
//   7. Reset all signal handlers to default and clear any
//      alternate signal stacks. Defeats the "install a SIGSEGV
//      handler and check it's still there" detection.
//
// All seven together is what one would call "the Magisk +
// Shamiko + DenyList + a bit of extra paranoia" surface. Every
// piece here is documented in either the Magisk guide, the
// Shamiko README, or in public Android security research writeups.
//
// Public surface (called from entry.cpp at the right times):
//
//   hide_advanced_init()                — call once at payload init
//   hide_advanced_apply_pre_fork()     — call from pre-fork path
//   hide_advanced_apply_post_fork()    — call from post-fork path,
//                                         AFTER the basic hide_apply_for_target()

#pragma once

namespace zygisk_study {

void hide_advanced_init();
void hide_advanced_apply_pre_fork();
void hide_advanced_apply_post_fork(const char* package_name);

} // namespace zygisk_study
