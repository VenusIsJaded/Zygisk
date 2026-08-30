// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/hide.h
//
// The hide layer — public surface used by entry.cpp.
//
// The hiding mechanisms here are all PUBLIC, well-documented Android
// rooting techniques (Magisk DenyList, Shamiko, mount namespace
// isolation, props spoofing). Nothing here is novel; it's the
// minimum set of techniques needed to keep Magisk-flavored root
// signals out of an app's first observable callback.
//
// Three entry points:
//
//   1. hide_register_globals()
//      Called once at payload init. Snapshots the *initial* state of
//      /proc/self/maps and a few other probes so we can later compute
//      a delta of "what did *we* add to this process".
//
//   2. hide_setup_for_target(const char* package_name)
//      Called from preAppSpecialize. Decides whether the target is on
//      the DenyList and, if so, queues up the post-fork hide actions.
//
//   3. hide_apply_for_target(const char* package_name)
//      Called from postAppSpecialize, AFTER the process has setresuid
//      to the target app's uid. Performs the actual scrubbing.
//
// All three are designed to be cheap on the fast path (target not on
// DenyList) and only do the real work on the slow path (target is).

#pragma once

#include <cstddef>

namespace zygisk_study {

// Initialize the hide layer (snapshot initial state, pre-resolve
// dlsym lookups so the post-fork hot path doesn't pay for them).
void hide_register_globals();

// Pre-resolve libc function pointers (e.g. __system_property_set)
// that the post-fork hide path uses. Idempotent. Called from
// hide_register_globals() at init time, but exposed separately so
// tests can call it in isolation.
void hide_pre_resolve_symbols();

// Decide whether to hide for this target. Returns 1 if yes, 0 if no.
int  hide_setup_for_target(const char* package_name);

// Apply the hide actions. Only meaningful if hide_setup_for_target
// returned 1. Idempotent; safe to call twice.
void hide_apply_for_target(const char* package_name);

// Clean up any traces we left behind after apply, before user code
// runs. The caller (entry.cpp) calls this from postAppSpecialize.
void hide_clean_trace();

} // namespace zygisk_study
