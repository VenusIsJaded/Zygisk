# SPDX-License-Identifier: Apache-2.0
# tests/Makefile

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra
INCLUDES  = -I../native/common -I.. -DZS_HOST_TEST

TESTS = test_obfstr test_hide test_hide_advanced test_hide_stealth test_e2e_hide \
	test_perf test_unmap_trampoline test_module_dispatch \
	test_version_compat test_zn_loader test_race

# The REAL payload, built as a shared library so the trampoline test
# can dlopen it and exercise the actual Tier A code path. Named
# libpayload.so deliberately: the maps snapshot matches on that name,
# so the record set is real.
PAYLOAD_SRC = \
    ../native/libpayload/src/entry.cpp \
    ../native/libpayload/src/module_dispatch.cpp \
    ../native/libpayload/src/hide.cpp \
    ../native/libpayload/src/hide_advanced.cpp \
    ../native/libpayload/src/hide_stealth.cpp

# The trampoline blob is per-arch; x86_64 on the host.
UNAME_M := $(shell uname -m)
ifeq ($(UNAME_M),x86_64)
TRAMPOLINE_SRC = ../native/libpayload/src/unmap_trampoline_x86_64.S
else ifeq ($(UNAME_M),aarch64)
TRAMPOLINE_SRC = ../native/libpayload/src/unmap_trampoline_aarch64.S
else
TRAMPOLINE_SRC =
endif

.PHONY: all run clean

all: $(TESTS) libpayload.so

test_hide: test_hide.cpp ../native/libpayload/src/hide.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

test_hide_advanced: test_hide_advanced.cpp ../native/libpayload/src/hide_advanced.cpp ../native/libpayload/src/hide.cpp ../native/common/log.h test_framework.h libpayload.so
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< ../native/libpayload/src/hide.cpp -ldl -pthread

test_hide_stealth: test_hide_stealth.cpp ../native/libpayload/src/hide_stealth.cpp ../native/libpayload/src/hide_advanced.cpp ../native/libpayload/src/hide.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< ../native/libpayload/src/hide.cpp -ldl

test_e2e_hide: test_e2e_hide.cpp ../native/libpayload/src/hide.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

test_perf: test_perf.cpp ../native/libpayload/src/hide.cpp ../native/libpayload/src/hide_advanced.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

test_unmap_trampoline: test_unmap_trampoline.cpp libpayload.so test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

# Round 12 — the module dispatch e2e test. Links the REAL payload
# (libpayload.so, dlopen'd) plus a REAL module .so built from
# module_stub.cpp. -rdynamic exports the test binary's fake
# JNI_GetCreatedJavaVMs into the global dlsym scope so libpayload's
# REAL env-acquisition path resolves it.
test_module_dispatch: test_module_dispatch.cpp libzs_test_module.so \
	libpayload.so test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl -pthread -rdynamic

libzs_test_module.so: module_stub.cpp ../zygisk.hpp
	$(CXX) $(CXXFLAGS) -fPIC -shared -I.. -o $@ $<

libpayload.so: $(PAYLOAD_SRC) $(TRAMPOLINE_SRC) \
	../native/libpayload/src/module_dispatch.h \
	../native/common/log.h
	$(CXX) $(CXXFLAGS) -fPIC -shared $(INCLUDES) -o $@ $(PAYLOAD_SRC) $(TRAMPOLINE_SRC) -ldl -Wl,-z,nodelete

# Round 25 — the host build of the BRIDGE library itself (libzygisk).
# The version-compat tests dlopen it exactly the way ART's
# Runtime::Init does, and verify the table + the constructor bootstrap
# that this round's AOSP research established (see
# native/libzygisk/src/entry.cpp's header comment).
libzygisk.so: ../native/libzygisk/src/entry.cpp ../native/common/log.h
	$(CXX) $(CXXFLAGS) -fPIC -shared $(INCLUDES) -o $@ $< -ldl -Wl,-z,nodelete

test_version_compat: test_version_compat.cpp libzygisk.so \
	test_framework.h ../native/common/log.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

# Round 31 — race-condition suite: multithreaded hammering of the
# hook layer (dlopen/dlclose churn, concurrent filtered opens,
# chdir-vs-relative-open). Plain build = stress + integrity checks;
# `make race` re-runs it under ThreadSanitizer.
race_fixture.so: race_fixture.c
	$(CC) -shared -fPIC -o $@ $<

test_race: test_race.cpp ../native/libpayload/src/hide_advanced.cpp \
	../native/libpayload/src/hide.cpp ../native/common/log.h \
	test_framework.h race_fixture.so
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< \
		../native/libpayload/src/hide.cpp -ldl -pthread

.PHONY: race
# ROUND 34 (C6 — the false-green TSan): the build line had
# `2>/dev/null || true` and the target executed /tmp/test_race_tsan
# unconditionally: a FAILED TSan compile left a MISSING (or STALE
# from an earlier run — /tmp is shared) binary, and both cases piped
# "not found"/old output through grep, matched nothing, and printed
# "TSAN: no data races" with exit 0. Exactly the R34 lesson
# (toolchain absence misreported as success) repeated one target
# over. Now: build into ./ (never /tmp), remove the `|| true`,
# verify the binary exists and is FRESH (newer than its sources), and
# treat a missing/broken TSan toolchain as an explicit SKIP, not a
# silent pass.
race: test_race.cpp ../native/libpayload/src/hide_advanced.cpp \
	../native/libpayload/src/hide.cpp race_fixture.c test_framework.h
	$(MAKE) test_race
	$(CC) -shared -fPIC -o race_fixture.so race_fixture.c
	rm -f ./test_race_tsan
	@if $(CXX) -std=c++17 -O1 -g -fsanitize=thread $(INCLUDES) -o \
		./test_race_tsan $< ../native/libpayload/src/hide.cpp \
		-ldl -pthread 2>/tmp/zs_tsan_build.log; then \
	    echo "== TSan race suite =="; \
	    if ./test_race_tsan 2>&1 | tee /tmp/zs_tsan_out.txt | \
	        grep -q "WARNING: ThreadSanitizer"; then \
	        echo "TSAN: DATA RACES FOUND"; \
	        grep -c "WARNING: ThreadSanitizer" /tmp/zs_tsan_out.txt; exit 1; \
	    else \
	        echo "TSAN: no data races"; \
	    fi; \
	elif grep -q "cannot find -ltsan\|-fsanitize=thread" /tmp/zs_tsan_build.log 2>/dev/null; then \
	    echo "TSAN: toolchain absent — SKIP (install libtsan to enable; NOT reported as clean)"; \
	else \
	    echo "TSAN: BUILD FAILED (source regression, not a skip):"; \
	    cat /tmp/zs_tsan_build.log; exit 1; \
	fi
	@./test_race

# Round 33 — the compile-time string obfuscator's own unit tests
# (decode correctness, decode-once semantics, StrTable integrity).
test_obfstr: test_obfstr.cpp ../native/common/obfstr.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $<

# Round 28 — libzn_loader (the init-oriented API bridge) gets its
# first dedicated test binary. Compiles the REAL entry.cpp with
# -DZS_HOST_TEST (the zs_test_zn_* seams) and exercises the
# socket-path resolver plus the live I/C protocol against a unix
# socket. See tests/test_zn_loader.cpp for the regression story.
test_zn_loader: test_zn_loader.cpp ../native/libzn_loader/src/entry.cpp \
	../zygisk_study_api.h ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< \
	../native/libzn_loader/src/entry.cpp -ldl -pthread

# ROUND 34: verify-trampolines is now a HARD dependency of `run` —
# the arm64 arg-register bug (base/size loaded into x23/x24 instead
# of the syscall argument registers x0/x1) shipped precisely because
# this verification existed but nothing in CI invoked it. Its
# arg-register and scrub gates are the only automated check of the
# arm64 blob's syscall ABI (the host executes only the x86_64 blob).
run: all verify-public-header verify-scripts verify-trampolines
	@fail=0; \
	for t in $(TESTS); do \
	echo "=== $$t ==="; \
	./$$t || fail=1; \
	done; \
	exit $$fail

# Round 28 — the PUBLIC API header must compile standalone in both
# C and C++ translation units. The header documents
# `#include "zygisk_study_api.h"` as the only include a module needs;
# before the sys/types.h fix that contract was broken (uid_t/gid_t
# undeclared in both languages).
.PHONY: verify-public-header
verify-public-header:
	@printf '#include "zygisk_study_api.h"\nint main(void){return 0;}\n' > /tmp/zs_api_c.c
	@if ! $(CC) -std=c99 -Wall -Wextra -I.. -fsyntax-only /tmp/zs_api_c.c; then \
		echo "FAIL: zygisk_study_api.h does not compile standalone (C99)"; exit 1; \
	fi
	@printf '#include "zygisk_study_api.h"\nint main(){return 0;}\n' > /tmp/zs_api_cpp.cpp
	@if ! $(CXX) $(CXXFLAGS) -I.. -fsyntax-only /tmp/zs_api_cpp.cpp; then \
		echo "FAIL: zygisk_study_api.h does not compile standalone (C++)"; exit 1; \
	fi
	@rm -f /tmp/zs_api_c.c /tmp/zs_api_cpp.cpp
	@echo "public API header: standalone C99 + C++17 compile OK"

# Round 10: sanitized build of the logic suites (ASan + UBSan, leak
# detection on). This is where the memcmp("/proc/") overread was
# found; keep it green in CI-style runs.
#
# test_unmap_trampoline is deliberately NOT in this target: its whole
# purpose is raw mapping manipulation -- the Tier A anonymize step
# memcpy()s entire read-only segments of libpayload.so, and under
# instrumentation those segments CONTAIN ASan global redzones, so the
# copy trips a false "global-buffer-overflow" on the first redzone
# byte (read size = exact page multiple from a page-aligned start;
# ASan reports the first poisoned byte, not the access start). The
# unsanitized `run` target exercises it against real mappings.
# test_module_dispatch is also excluded: it dlopens an UNINSTRUMENTED
# module .so into an instrumented process and forks real children —
# the cross-instrumentation boundary (module callbacks recorded from
# forked children through a shared mmap) produces noise, not signal.
SAN_CXXFLAGS = -std=c++17 -O1 -g -Wall -Wextra -fno-omit-frame-pointer \
	-fsanitize=address,undefined
SAN_TESTS = test_hide test_hide_advanced test_hide_stealth \
	test_e2e_hide test_perf test_race

.PHONY: run-sanitize

run-sanitize:
	@fail=0; \
	for t in $(SAN_TESTS); do \
	echo "=== $$t (ASan+UBSan) ==="; \
	$(MAKE) $$t CXXFLAGS="$(SAN_CXXFLAGS)"; \
	ASAN_OPTIONS=detect_leaks=1:abort_on_error=0 \
	UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=0 \
	./$$t || fail=1; \
	done; \
	$(MAKE) clean >/dev/null; \
	exit $$fail

# Round 22 — binary verification of BOTH self-unmap trampoline blobs
# (keystone-engine assembles every instruction and cross-checks the
# wrapper-frame/restore-slot contracts register-by-register). Exits 77
# (skip) when keystone is not installed; 0 = all green.
# Round 28 — LIVE end-to-end verification of the zygiskd daemon
# binary: builds it with cargo, runs it against a remapped /data
# tree, and probes the real socket (session handshake, cloak,
# L/I/C/P verbs, zombie reaping, restart cleanup). Exits 77 (skip)
# when no Rust toolchain is installed; 0 = all green.
.PHONY: verify-daemon

verify-daemon:
	@if command -v python3 >/dev/null 2>&1; then \
	python3 ../scripts/verify_daemon.py; \
	rc=$$?; \
	if [ $$rc -eq 77 ]; then \
	echo "NOTE: no Rust toolchain (cargo) — daemon E2E skipped."; \
	fi; \
	exit $$rc; \
	else \
	echo "python3 unavailable; skipping"; \
	fi

.PHONY: verify-trampolines

verify-trampolines:
	@if command -v python3 >/dev/null 2>&1; then \
	python3 ../scripts/verify_trampolines.py; \
	rc=$$?; \
	if [ $$rc -eq 77 ]; then \
	echo "NOTE: keystone-engine missing — pip install keystone-engine to enable (SKIP, not a failure — Round 34: CI installs it, so the gate is enforced there)."; \
	rc=0; \
	fi; \
	exit $$rc; \
	else \
	echo "python3 unavailable; skipping"; \
	fi

# Round 29 - the module's shell scripts run for real against a fake
# Magisk environment (fake resetprop/log, ZS_TEST_ROOT remap). This is
# the harness that would have caught the "0"-only swap guard and the
# never-created $MODPATH/zygiskd launcher.
.PHONY: verify-scripts
verify-scripts:
	@if command -v python3 >/dev/null 2>&1; then \
	python3 ../scripts/verify_scripts.py; \
	rc=$$?; \
	exit $$rc; \
	else \
	echo "python3 unavailable; skipping"; \
	fi

clean:
	rm -f $(TESTS) libpayload.so libzs_test_module.so libzygisk.so
