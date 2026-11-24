UNAME_S := $(shell uname -s)
UNAME_M := $(shell uname -m)

ifeq ($(UNAME_S),Darwin)
  CC_X86 := clang -arch x86_64
  ifeq ($(UNAME_M),arm64)
    RUN_X86 := arch -x86_64
  else
    RUN_X86 :=
  endif
else
  CC_X86 := clang
  RUN_X86 :=
endif

.PHONY: test verify-stubs clean

test:
	@mkdir -p build
	$(CC_X86) -O2 tests/test_ptsm.c src/ptsm_fixup.s -o build/test_ptsm
	$(RUN_X86) ./build/test_ptsm </dev/null
	$(CC_X86) -O2 tests/test_net_failfast.c src/net_failfast_test.s -o build/test_net_failfast
	$(RUN_X86) ./build/test_net_failfast
	$(CC_X86) -O2 tests/test_nikeid.c src/nikeid_guard_test.s -o build/test_nikeid
	$(RUN_X86) ./build/test_nikeid </dev/null
	$(CC_X86) -O2 tests/test_seasons.c src/seasons_guard_test.s -o build/test_seasons
	$(RUN_X86) ./build/test_seasons </dev/null

verify-stubs:
	python3 src/rebuild_stubs.py

clean:
	rm -rf build
