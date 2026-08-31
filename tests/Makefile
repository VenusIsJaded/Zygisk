# SPDX-License-Identifier: Apache-2.0
# tests/Makefile

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra
INCLUDES  = -I../native/common -I.. -DZS_HOST_TEST

TESTS = test_hide test_hide_advanced test_hide_stealth test_e2e_hide \
	test_perf test_unmap_trampoline test_module_dispatch

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

test_hide_advanced: test_hide_advanced.cpp ../native/libpayload/src/hide_advanced.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

test_hide_stealth: test_hide_stealth.cpp ../native/libpayload/src/hide_stealth.cpp ../native/libpayload/src/hide_advanced.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

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
	$(CXX) $(CXXFLAGS) -fPIC -shared $(INCLUDES) -o $@ $(PAYLOAD_SRC) $(TRAMPOLINE_SRC) -ldl

run: all
	@fail=0; \
	for t in $(TESTS); do \
		echo "=== $$t ==="; \
		./$$t || fail=1; \
	done; \
	exit $$fail

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
	    test_e2e_hide test_perf

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

clean:
	rm -f $(TESTS) libpayload.so libzs_test_module.so
