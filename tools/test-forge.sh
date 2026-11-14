#!/bin/sh
# Run the same mandatory stages locally and in Forge CI.
set -eu
repo=$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)
cd "$repo"
usage() {
    echo "usage: $0 --all | --native | --native-dev | --native-sanitize | --native-presets | --references | --differential" >&2
    exit 2
}
test "$#" = 1 || usage
suite=tests/differential
case ${BUILD_ROOT:-build} in
    /*) ;;
    *) BUILD_ROOT="$repo/${BUILD_ROOT:-build}" ;;
esac
export BUILD_ROOT
export FORGE_TEST_RUN_ID="${FORGE_TEST_RUN_ID:-$(python3 -c 'import uuid; print(uuid.uuid4())')}"
stage() (
    name=$1
    shift
    start=$(date +%s)
    rc=0
    FORGE_CI_TIMING_SUMMARY="${GITHUB_STEP_SUMMARY:-}" "$@" || rc=$?
    if test -n "${GITHUB_OUTPUT:-}"; then
        outcome=success
        if test "$rc" != 0; then outcome=failure; fi
        echo "$name=$outcome" >> "$GITHUB_OUTPUT"
    fi
    if test -n "${GITHUB_STEP_SUMMARY:-}"; then
        elapsed=$(( $(date +%s) - start ))
        printf -- '- %s took %ss (exit %s)\n' "$name" "$elapsed" "$rc" >> "$GITHUB_STEP_SUMMARY"
    fi
    return "$rc"
)

run_differential() (
    status=0
    CMAKE_GENERATOR=Xcode stage debug ./tools/run-differential.sh --all --jobs "${FORGE_DIFF_JOBS:-1}" --config debug --forge "$BUILD_ROOT/sanitize/forge" || status=1
    stage release ./tools/run-differential.sh --all --jobs "${FORGE_DIFF_JOBS:-1}" --config release --forge "$BUILD_ROOT/dev/forge" || status=1
    stage negative_tests python3 -B "$suite/test_native_differential.py" --forge "$BUILD_ROOT/dev/forge" || status=1
    exit "$status"
)
require_native() {
    test "$(uname -sm)" = 'Darwin arm64' || { echo "Full native tests require macOS arm64." >&2; exit 1; }
}

native_tests() (
    preset=$1
    export FORGE_TEST_PROVISIONING=1
    result="$BUILD_ROOT/$preset/required-tests.xml"
    # A fresh result is necessary even when reusing a configured build tree.
    if test -f "$result"; then unlink "$result"; fi
    name=$preset
    if test "$name" = dev; then name=debug; fi
    stage "$name" make test PRESET="$preset" BUILD_TESTING=ON CTEST_ARGS="--output-junit \"$result\""
    stage "${preset}_oracles" python3 - "$result" <<'PYTHON'
import sys
from xml.etree import ElementTree
tests = ElementTree.parse(sys.argv[1]).findall(".//testcase")
for name in ("native", "differential", "guest_stack", "build_provisioning"):
    found = [t for t in tests if t.get("name") == name]
    if len(found) != 1 or found[0].get("status") != "run" or len(found[0].findall("skipped")):
        sys.exit(f"Required CTest {name} did not execute. Activate the documented build-tools environment before running the native gate.")
PYTHON
)

check_layout() {
    test ! -f "$BUILD_ROOT/CMakeCache.txt" &&
        test -z "$(find . -maxdepth 1 -type d -name 'build-*' -print)" &&
        test -z "$(git status --porcelain --untracked-files=all)"
}

case "$1" in
--native)
    require_native
    stage formatting make format-check
    stage lint make lint
    native_tests dev
    native_tests sanitize ;;
--native-dev | --native-sanitize)
    require_native
    native_tests "${1#--native-}"
    check_layout ;;
--native-presets)
    require_native
    stage formatting make format-check
    stage lint make lint
    stage release make test PRESET=release CTEST_ARGS='-R ^cli$$'
    stage xcode_debug make test PRESET=xcode CONFIG=Debug CTEST_ARGS='-R ^cli$$'
    test -x "$BUILD_ROOT/xcode/Debug/forge"
    # Both configurations use the tree configured by the Xcode Debug check.
    stage xcode_release_build cmake --build "$BUILD_ROOT/xcode" --config Release
    stage xcode_release_ctest ctest --test-dir "$BUILD_ROOT/xcode" --output-on-failure --no-tests=error -C Release -R '^cli$'
    test -x "$BUILD_ROOT/xcode/Release/forge"
    stage layout check_layout ;;
--references)
    docker info >/dev/null || { echo "Start a Docker engine with Linux amd64 support for the pinned MinGW and Wine images." >&2; exit 1; }
    python3 -B "$suite/manifests.py"
    python3 -B "$suite/test_fixture_shape.py"
    stage build ./tools/build-windows-fixtures.sh --all
    stage capture ./tools/run-windows-references.sh --all
    stage wine_tests python3 -B "$suite/reference/test_wine.py" ;;
--differential)
    status=0
    run_differential || status=1
    # The hosted regression-gate independently verifies the downloaded evidence.
    if test "${GITHUB_ACTIONS:-}" != true; then
        outcome=success
        if test "$status" != 0; then outcome=failure; fi
        python3 -B "$suite/coverage_report.py" --comparison "$outcome" || status=1
    fi
    exit "$status" ;;
--all)
    native=success
    references=success
    compare=skipped
    "$repo/tools/test-forge.sh" --native || native=failure
    "$repo/tools/test-forge.sh" --references || references=failure
    if test "$native/$references" = success/success; then
        compare=success
        run_differential || compare=failure
    fi
    exec python3 -B "$suite/coverage_report.py" --local-jobs "$native" "$references" "$compare" ;;
*) usage ;;
esac
