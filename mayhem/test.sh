#!/usr/bin/env bash
#
# mayhem/test.sh — RUN this repo's OWN functional test suite (already built by mayhem/build.sh).
# exit 0 = pass. EDIT per repo. PATCH-grade oracle: after an agent patches the source, the grader
# rebuilds (build.sh) then runs this. DELETE this file if the repo has no meaningful tests.
#
# IMPORTANT:
#  * Must assert BEHAVIOR/OUTPUT, not just exit status. The oracle has to check asserted values /
#    golden-output diffs / known-answer results — so a PATCH that "fixes" a bug by making the program
#    exit(0) (or any no-op) FAILS here. Running inputs and checking only "exit 0 / didn't crash" is
#    NOT a functional test (it's trivially reward-hackable) — use the project's real assertion suite.
#  * Do NOT build here — mayhem/build.sh already compiled the test suite (with the project's normal
#    flags). This script only RUNS the pre-built tests and reports counts. If the test runner is
#    missing, that's a build.sh bug — fail loudly rather than silently rebuilding.
#  * REQUIRED OUTPUT — a CTRF (https://ctrf.io) summary so Mayhem/the PATCH grader reads the counts:
#      - writes a CTRF JSON report to ${CTRF_REPORT:-$SRC/ctrf-report.json}, and
#      - prints a one-line `CTRF {...}` marker to stdout (same JSON, compact).
#    Only `results.summary` (with tests/passed/failed/pending/skipped/other) is required.
#    Use the emit_ctrf helper below; it computes tests = passed+failed+skipped and sets the exit
#    code (0 iff failed==0). Map your framework's output to passed/failed/skipped.
set -uo pipefail
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH
: "${MAYHEM_JOBS:=$(nproc)}"   # build parallelism; env-overridable, falls back to nproc (use -j"$MAYHEM_JOBS")
cd "$SRC"

# emit_ctrf <tool> <passed> <failed> [skipped] [pending] [other]
# Writes a CTRF report (file + stdout `CTRF {...}` marker) and returns non-zero iff failed>0.
emit_ctrf() {
  local tool="$1" passed="$2" failed="$3" skipped="${4:-0}" pending="${5:-0}" other="${6:-0}"
  local tests=$(( passed + failed + skipped + pending + other ))
  cat > "${CTRF_REPORT:-$SRC/ctrf-report.json}" <<JSON
{
  "results": {
    "tool": { "name": "$tool" },
    "summary": {
      "tests": $tests,
      "passed": $passed,
      "failed": $failed,
      "pending": $pending,
      "skipped": $skipped,
      "other": $other
    }
  }
}
JSON
  printf 'CTRF {"results":{"tool":{"name":"%s"},"summary":{"tests":%d,"passed":%d,"failed":%d,"pending":%d,"skipped":%d,"other":%d}}}\n' \
    "$tool" "$tests" "$passed" "$failed" "$pending" "$skipped" "$other"
  [ "$failed" -eq 0 ]
}

# Upstream's asserting unit tests (the ones scripts/unittest.sh runs), built by build.sh with
# normal flags into build-tests/unittest. Each case checks behavior: an exit status AND either a
# known answer (md5/sha1/base64 vectors) or a golden diff of the test's own printed results in
# mayhem/test-golden/ (assert-only tests that print nothing: websocket_parser, redis_protocol).
T="$SRC/build-tests/unittest"
G="$SRC/mayhem/test-golden"
for b in hbase_test base64 md5 sha1 rbtree_test hurl_test hstring_test http_router_test tlv_test \
         websocket_parser_test redis_protocol_test; do
  [ -x "$T/$b" ] || { echo "missing test binary $T/$b — build.sh did not build it" >&2; exit 2; }
done
WORK=$(mktemp -d "${TMPDIR:-/tmp}/libhv-test.XXXXXX"); trap 'rm -rf "$WORK"' EXIT
passed=0; failed=0
ok()   { echo "PASS $1"; passed=$((passed+1)); }
bad()  { echo "FAIL $1"; failed=$((failed+1)); }

# golden-output cases
check_golden() {  # <name> <cmd...>
  local name="$1"; shift
  local out rc
  out=$("$@" 2>&1); rc=$?
  [ "$name" = hbase_test ] && out=$(printf '%s\n' "$out" | grep -v '^hv_rand\|^hv_random_string')
  if [ $rc -eq 0 ] && [ "$out" = "$(cat "$G/$name.golden")" ]; then ok "$name"; else bad "$name (rc=$rc)"; diff <(printf '%s\n' "$out") "$G/$name.golden" | head -20; fi
}
for t in hbase_test rbtree_test hurl_test hstring_test http_router_test tlv_test; do check_golden "$t" "$T/$t"; done

# known-answer vectors
[ "$("$T/md5" -s abc)" = 900150983cd24fb0d6963f7d28e17f72 ] && ok md5_abc || bad md5_abc
[ "$("$T/md5" -s "")" = d41d8cd98f00b204e9800998ecf8427e ] && ok md5_empty || bad md5_empty
[ "$("$T/sha1" -s abc)" = a9993e364706816aba3e25717850c26c9cd0d89d ] && ok sha1_abc || bad sha1_abc
printf 'hello world' > "$WORK/in"
if "$T/base64" "$WORK/in" "$WORK/enc" >/dev/null && [ "$(cat "$WORK/enc")" = aGVsbG8gd29ybGQ= ] \
   && "$T/base64" -d "$WORK/enc" "$WORK/dec" >/dev/null && cmp -s "$WORK/in" "$WORK/dec"; then ok base64_roundtrip; else bad base64_roundtrip; fi

# assert()-based suites with no printed results (built without NDEBUG)
for t in websocket_parser_test redis_protocol_test; do
  if "$T/$t" >"$WORK/$t.log" 2>&1; then ok "$t"; else bad "$t"; tail -20 "$WORK/$t.log"; fi
done

emit_ctrf "libhv-unittest" "$passed" "$failed" 0
