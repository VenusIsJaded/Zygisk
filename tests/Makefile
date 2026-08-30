# SPDX-License-Identifier: Apache-2.0
# tests/Makefile
#
# Build and run the host-side unit tests for the hide layer. These
# tests compile the production .cpp files directly (via #include) so
# we can exercise the static helpers without modifying the production
# source.
#
# Build deps: g++ (any version supporting C++17), and the standard
# Linux headers (provided by g++ on Debian/Ubuntu/Fedora/etc.).
#
# Usage:
#   make            # build all three test binaries
#   make run         # build + run all tests, return non-zero on any failure
#   make clean

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra
INCLUDES  = -I../native/common -DZS_HOST_TEST

TESTS = test_hide test_hide_advanced test_e2e_hide

.PHONY: all run clean

all: $(TESTS)

# Each test binary is a single self-contained translation unit. We
# compile with -ldl because the production hide layer uses dlopen().
test_hide: test_hide.cpp ../native/libpayload/src/hide.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

test_hide_advanced: test_hide_advanced.cpp ../native/libpayload/src/hide_advanced.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

test_e2e_hide: test_e2e_hide.cpp ../native/libpayload/src/hide.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

run: all
	@fail=0; \
	for t in $(TESTS); do \
	    echo "=== $$t ==="; \
	    ./$$t || fail=1; \
	done; \
	exit $$fail

clean:
	rm -f $(TESTS)
