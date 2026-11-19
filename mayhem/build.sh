#!/usr/bin/env bash
#
# mayhem/build.sh — build this repo's fuzz harness(es). EDIT per repo.
#
# Runs inside the commit image (mayhem/Dockerfile) as `mayhem` in /mayhem. The base image
# (ghcr.io/savantenvs/base) already exports the build contract — use these, don't redefine:
#   CC, CXX             stock clang / clang++
#   LIB_FUZZING_ENGINE  -fsanitize=fuzzer   (link into each harness that has a LLVMFuzzer entry)
#   SANITIZER_FLAGS     -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
#                       (ASan + UBSan, both set to HALT — so Mayhem catches memory AND UB defects)
#   DEBUG_FLAGS         -g -gdwarf-3   (DWARF debug info — always on for fuzz/standalone builds,
#                       independent of the sanitizer off-switch; DWARF version must be < 4)
#   RUST_DEBUG_FLAGS    -C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3
#                       (thread through RUSTFLAGS on every cargo-fuzz build)
#   GO_DEBUG_FLAGS      -gcflags=all=-N -l
#                       (thread through go build / go-fuzz-build so the linked ELF keeps symbols)
#   SRC                 /mayhem (the repo source)
#
# Contract: build EVERYTHING here — one runnable binary per fuzz harness, AND the project's test
# suite (so mayhem/test.sh only has to RUN it, never compile). Keep it ADDITIVE (build upstream as
# upstream documents; don't edit upstream files). IMPORTANT: build the PROJECT ITSELF with
# $SANITIZER_FLAGS and $DEBUG_FLAGS (not just the harness) so the fuzzed code is instrumented
# AND carries DWARF < 4 symbols — otherwise ASan/UBSan only see the harness, not the library
# you're trying to find bugs in, and backtraces won't resolve project source lines. Build the TEST
# suite with the project's NORMAL flags (a clean, independent build) so test.sh stays an honest
# functional oracle and won't false-fail on benign UB. Leave the test binary/runner where test.sh
# expects it.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' (empty) — it must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# Build knobs come from the ENVIRONMENT (overridable), with sane defaults — no if-statements,
# just parameter-expansion fallbacks. Default sanitizers are the base's ASan+UBSan (halting); override
# per build via the Dockerfile's `--build-arg SANITIZER_FLAGS="..."`.
# NB: SANITIZER_FLAGS uses `=` (no colon) on purpose — `=` only fills when the var is UNSET, so an
# explicit EMPTY value (`--build-arg SANITIZER_FLAGS=`) is honored and builds with NO sanitizers
# (useful when you want the program's natural crash / full backtrace, not an ASan report). The other
# knobs use `:=` (default on empty too). MAYHEM_JOBS sets build parallelism (falls back to nproc).
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer}"
# DEBUG_FLAGS carries DWARF debug info INDEPENDENTLY of the sanitizer off-switch (so an empty
# SANITIZER_FLAGS still yields DWARF symbols). DWARF MUST be < 4 (Mayhem triage can't read >=4); clang-19's
# plain `-g` emits DWARF-5, so `-gdwarf-3` is explicit. Apply $DEBUG_FLAGS to the fuzz/harness/standalone
# builds (NOT the test/oracle build). Rust/Go carry the same intent via their language flags below.
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
: "${RUST_DEBUG_FLAGS:=-C debuginfo=2 -C force-frame-pointers=yes -C llvm-args=-gdwarf-3}"
: "${GO_DEBUG_FLAGS:=-gcflags=all=-N -l}"
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# COVERAGE_FLAGS: empty by default → no effect on the normal oracle build. Set it via the Dockerfile's
# `--build-arg COVERAGE_FLAGS="-fprofile-instr-generate -fcoverage-mapping"` to instrument the TEST
# build for source-coverage measurement (how much of the project the test suite actually exercises —
# a quality signal for the oracle; complements the anti-reward-hack sabotage check). APPEND it to the
# test build's compile+link flags in step 3 (NOT the fuzz build); after `test.sh` runs, merge with
# `llvm-profdata` and report with `llvm-cov`. Empty value is honored (`=`, not `:=`).
: "${COVERAGE_FLAGS=}"
export SANITIZER_FLAGS DEBUG_FLAGS RUST_DEBUG_FLAGS GO_DEBUG_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS COVERAGE_FLAGS

cd "$SRC"

HARNESSES="http_request http_response websocket redis_reply dns ini url multipart hlog util unpack mqtt_client http_server"
LIBHV_OPTS=(-DBUILD_SHARED=OFF -DBUILD_STATIC=ON -DBUILD_EXAMPLES=OFF -DBUILD_UNITTEST=OFF
            -DWITH_PROTOCOL=ON -DWITH_MQTT=ON -DWITH_REDIS=ON -DCMAKE_BUILD_TYPE=Debug)

# Fuzz compile flags. -fsanitize=fuzzer-no-link puts SanCov edges into libhv itself (the
# harness link adds the libFuzzer runtime). Two UBSan checks are relaxed because they fire on
# every input on benign upstream patterns, so no target could fuzz past them:
#   function:  every hloop event dispatch calls hio_handle_events/timer callbacks through a
#              `void (*)(hevent_t*)` (event/hloop.c), and the multipart parser calls C++
#              callbacks through C function-pointer types (http/multipart_parser.c).
#   alignment: dns.c reads uint16 fields straight out of the packet buffer (x86-benign).
# ASan and the rest of UBSan stay on and halting.
FUZZ_FLAGS="$SANITIZER_FLAGS -fno-sanitize=function,alignment $DEBUG_FLAGS -fsanitize=fuzzer-no-link"

# 1) libhv itself, sanitized + DWARF 3, static, out of tree in build-fuzz/ (gitignored by
#    upstream's `build-*`). Debug keeps upstream's assert()s live (Release adds -DNDEBUG).
cmake -S . -B build-fuzz "${LIBHV_OPTS[@]}" \
      -DCMAKE_C_FLAGS="$FUZZ_FLAGS" -DCMAKE_CXX_FLAGS="$FUZZ_FLAGS"
cmake --build build-fuzz -j"$MAYHEM_JOBS" --target hv_static
FUZZ_INC=(-I"$SRC/build-fuzz/include/hv")
FUZZ_LIB="$SRC/build-fuzz/lib/libhv.a"

# 2) harnesses: libFuzzer binary + standalone reproducer each, with the LSan-off hook.
mkdir -p build-fuzz/obj
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c++ mayhem/lsan_off.cc -o build-fuzz/obj/lsan_off.o
$CC  $SANITIZER_FLAGS $DEBUG_FLAGS -c -x c "$STANDALONE_FUZZ_MAIN" -o build-fuzz/obj/standalone_main.o
for h in $HARNESSES; do
  $CXX $FUZZ_FLAGS -std=c++11 "${FUZZ_INC[@]}" -c "mayhem/harnesses/fuzz_$h.cpp" \
       -o "build-fuzz/obj/fuzz_$h.o"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS $LIB_FUZZING_ENGINE "build-fuzz/obj/fuzz_$h.o" \
       build-fuzz/obj/lsan_off.o "$FUZZ_LIB" -lpthread -ldl -o "/mayhem/fuzz_$h"
  $CXX $SANITIZER_FLAGS $DEBUG_FLAGS build-fuzz/obj/standalone_main.o "build-fuzz/obj/fuzz_$h.o" \
       build-fuzz/obj/lsan_off.o "$FUZZ_LIB" -lpthread -ldl -o "/mayhem/fuzz_$h-standalone"
done

# 3) upstream's unit tests (the asserting ones from scripts/unittest.sh), NORMAL flags, against a
#    separate unsanitized libhv in build-tests/. Same compile lines as upstream's `make unittest`.
cmake -S . -B build-tests "${LIBHV_OPTS[@]}" \
      -DCMAKE_C_FLAGS="$COVERAGE_FLAGS" -DCMAKE_CXX_FLAGS="$COVERAGE_FLAGS"
cmake --build build-tests -j"$MAYHEM_JOBS" --target hv_static
T=build-tests/unittest; mkdir -p "$T"
TLIB=build-tests/lib/libhv.a
CF=(-g -O0 $COVERAGE_FLAGS)
$CC  "${CF[@]}" -std=c99   -I. -Ibase -o $T/hbase_test   unittest/hbase_test.c   base/hbase.c
$CC  "${CF[@]}" -std=c99   -I. -Iutil -o $T/base64       unittest/base64_test.c  util/base64.c
$CC  "${CF[@]}" -std=c99   -I. -Iutil -o $T/md5          unittest/md5_test.c     util/md5.c
$CC  "${CF[@]}" -std=c99   -I. -Iutil -o $T/sha1         unittest/sha1_test.c    util/sha1.c
$CC  "${CF[@]}" -std=c99   -I. -Ibase -o $T/rbtree_test  unittest/rbtree_test.c  base/rbtree.c
$CXX "${CF[@]}" -std=c++11 -I. -Ibase -Icpputil -o $T/hurl_test    unittest/hurl_test.cpp    cpputil/hurl.cpp base/hbase.c
$CXX "${CF[@]}" -std=c++11 -I. -Ibase -Icpputil -o $T/hstring_test unittest/hstring_test.cpp cpputil/hstring.cpp
$CXX "${CF[@]}" -std=c++11 -Ihttp/server -o $T/http_router_test unittest/http_router_test.cpp
$CXX "${CF[@]}" -std=c++11 -I. -Ibase -Ievent -Issl -Ievpp -o $T/tlv_test unittest/tlv_test.cpp
$CXX "${CF[@]}" -std=c++11 -I. -Ibase -Ihttp -o $T/websocket_parser_test unittest/websocket_parser_test.cpp $TLIB -pthread
$CXX "${CF[@]}" -std=c++11 -I. -Ibase -Ievent -Icpputil -Iredis -o $T/redis_protocol_test unittest/redis_protocol_test.cpp redis/RedisMessage.cpp
echo "build.sh: done"
