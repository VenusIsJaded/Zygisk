# SPDX-License-Identifier: Apache-2.0
# tests/Makefile

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra
INCLUDES  = -I../native/common -I.. -DZS_HOST_TEST

TESTS = test_hide test_hide_advanced test_hide_stealth test_e2e_hide \
        test_perf test_unmap_trampoline

# The REAL payload, built as a shared library so the trampoline test
# can dlopen it and exercise the actual Tier A code path. Named
# libpayload.so deliberately: the maps snapshot matches on that name,
# so the record set is real.
PAYLOAD_SRC = \
    ../native/libpayload/src/entry.cpp \
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

libpayload.so: $(PAYLOAD_SRC) $(TRAMPOLINE_SRC) ../native/common/log.h
	$(CXX) $(CXXFLAGS) -fPIC -shared $(INCLUDES) -o $@ $(PAYLOAD_SRC) $(TRAMPOLINE_SRC) -ldl

run: all
	@fail=0; \
	for t in $(TESTS); do \
		echo "=== $$t ==="; \
		./$$t || fail=1; \
	done; \
	exit $$fail

clean:
	rm -f $(TESTS) libpayload.so
