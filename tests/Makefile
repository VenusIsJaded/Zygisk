# SPDX-License-Identifier: Apache-2.0
# tests/Makefile

CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -g -Wall -Wextra
INCLUDES  = -I../native/common -DZS_HOST_TEST

TESTS = test_hide test_hide_advanced test_hide_stealth test_e2e_hide test_perf

.PHONY: all run clean

all: $(TESTS)

test_hide: test_hide.cpp ../native/libpayload/src/hide.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

test_hide_advanced: test_hide_advanced.cpp ../native/libpayload/src/hide_advanced.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

test_hide_stealth: test_hide_stealth.cpp ../native/libpayload/src/hide_stealth.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

test_e2e_hide: test_e2e_hide.cpp ../native/libpayload/src/hide.cpp ../native/common/log.h test_framework.h
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $< -ldl

test_perf: test_perf.cpp ../native/libpayload/src/hide.cpp ../native/libpayload/src/hide_advanced.cpp ../native/common/log.h test_framework.h
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
