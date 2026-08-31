// SPDX-License-Identifier: Apache-2.0
// native/libpayload/src/hide_stealth.h
//
// Additional stealth layer (layer 3, on top of the basic + advanced
// layers in hide.h and hide_advanced.h).
//
// Each technique here targets a detection signal that the basic
// and advanced layers do NOT cover. All techniques are publicly
// documented Android rooting concepts (see docs/hiding.md for the
// reference list); the implementation is original to this repo.
//
// Public surface (called from entry.cpp at the right times):
//
//   hide_stealth_init()                  — call once at payload init
//   hide_stealth_apply_post_fork(pkg)   — call AFTER hide_apply_for_target
//                                          AND hide_advanced_apply_post_fork

#pragma once

namespace zygisk_study {

void hide_stealth_init();
void hide_stealth_apply_post_fork(const char* package_name);

// Exposed for unit tests only — NOT called by the shipped pipeline.
// See hide_stealth.cpp's header comment for why each was removed
// (each one made the child LESS stock-looking, not more).
void set_pdeathsig_if_safe();
void set_dumpable_zero();
void set_no_new_privs();
void disable_core_dumps();

} // namespace zygisk_study
