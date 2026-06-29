#!/usr/bin/env bash
# Build the bgp VGI worker and run the SQLLogic tests against it using the
# haybarn DuckDB distribution's unittest runner (which ships the signed `vgi`
# extension via the community repository).
#
# Prerequisites (one-time):
#   uv tool install haybarn-unittest      # the DuckDB unittest binary
#   echo "INSTALL vgi FROM community;" | uvx haybarn-cli   # install the vgi ext
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

UNITTEST="${VGI_UNITTEST:-$(command -v haybarn-unittest || true)}"
if [[ -z "$UNITTEST" || ! -x "$UNITTEST" ]]; then
    echo "ERROR: haybarn-unittest not found. Install it with:" >&2
    echo "       uv tool install haybarn-unittest" >&2
    exit 1
fi

# Ensure the vgi community extension is installed for this haybarn version.
if ! echo "LOAD vgi;" | uvx haybarn-cli >/dev/null 2>&1; then
    echo "==> Installing vgi extension from community repository"
    echo "INSTALL vgi FROM community;" | uvx haybarn-cli
fi

echo "==> Building bgp-worker (release)"
cargo build --release --bin bgp-worker

WORKER="$REPO_ROOT/target/release/bgp-worker"
# NOTE: this is a Catch2 test-name filter, not a shell glob. Catch2 only honors a
# trailing `*` wildcard, so use `test/sql/*` (not `test/sql/*.test`).
TEST_GLOB="${1:-test/sql/*}"

echo "==> Running SQLLogic tests"
echo "    worker:   $WORKER"
echo "    unittest: $UNITTEST"
echo "    tests:    $TEST_GLOB"

# VGI_BGP_BATCH_ROWS=1 forces one row per Arrow batch so the suite exercises the
# byte-offset scan state crossing batch boundaries (see scan_state.test). The
# worker inherits this env from the launching DuckDB process.
VGI_BGP_WORKER="$WORKER" \
VGI_BGP_BATCH_ROWS="1" \
VGI_WORKER_CATALOG_NAME="bgp" \
    "$UNITTEST" --test-dir "$REPO_ROOT" "$TEST_GLOB"
