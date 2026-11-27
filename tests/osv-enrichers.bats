#!/usr/bin/env bats
#
# scripts/osv-enrichers.sh: osv-scanner's enrichers fail whole - one failed
# deps.dev request and scalibr's licence enricher returns before it writes a
# single licence, the deprecation one likewise, and one failed osv.dev query
# leaves vulnerability matching empty or partial - and osv-scanner logs it and
# carries on. Its exit code then says 1 ("found something") whenever anything
# else was found, so the log line is the only record and the osv target fails
# on it.
#
# The log lines below are verbatim from osv-scanner v2.7.0 with each endpoint
# made unreachable (HTTPS_PROXY to a closed port, NO_PROXY for the other);
# re-capture them when osv-scanner is bumped.

load helper

setup() { TMP="$(mktemp -d)"; }
teardown() { rm -rf "$TMP"; }

LICENCE='Error during extraction: (extracting as license/depsdev) failed to get version information max retries exhausted: failed after 4 attempts: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 127.0.0.1:9: connect: connection refused"'
DEPRECATION='Error during extraction: (extracting as packagedeprecation/depsdev) depsdev.GetVersionBatch failed: max retries exhausted: failed after 4 attempts: rpc error: code = Unavailable desc = connection error: desc = "transport: Error while dialing: dial tcp 127.0.0.1:9: connect: connection refused"'
VULNMATCH='Error during extraction: (extracting as vulnmatch/osvdev) max retries exceeded: attempt 4: request failed: Post "https://api.osv.dev/v1/querybatch": proxyconnect tcp: dial tcp 127.0.0.1:9: connect: connection refused'
CLEAN='Scanning dir .
Scanned /src/rust/Cargo.lock file and found 3 packages
Loaded filter from: /src/rust/osv-scanner.toml
overriding license for package crates.io/ring/0.16.20 with MIT'

check() { run bash "$ROOT/scripts/osv-enrichers.sh" "$TMP/stderr.log" "${1:-default}"; }
log() { printf '%s\n' "$CLEAN" "$@" > "$TMP/stderr.log"; }

@test "a failed licence lookup fails, naming the enricher" {
    log "$LICENCE"
    check
    [ "$status" -ne 0 ]
    [[ "$output" == *"::error::"*"license/depsdev"*"Unavailable"* ]]
}

@test "a failed deprecation lookup fails too, licences on or off" {
    log "$DEPRECATION"
    check none
    [ "$status" -ne 0 ]
    [[ "$output" == *"packagedeprecation/depsdev"* ]]
}

# No advisories at all would otherwise pass as a clean scan: CVEs and MAL-*
# both come from this one enricher.
@test "a failed osv.dev query fails, licences on or off" {
    log "$VULNMATCH"
    check none
    [ "$status" -ne 0 ]
    [[ "$output" == *"vulnmatch/osvdev"* ]]
    [[ "$output" == *"advisor"* ]]
}

# With licences off the licence result is never read. `none` is matched the
# way osv.jq matches it: trimmed, any case - and nothing looser.
@test "a failed licence lookup is ignored only when licence checks are off" {
    log "$LICENCE"
    check " None "
    [ "$status" -eq 0 ]
    check "n one"
    [ "$status" -ne 0 ]
}

@test "a clean log passes" {
    log
    check
    [ "$status" -eq 0 ]
}

@test "a missing log fails rather than passing unchecked" {
    run bash "$ROOT/scripts/osv-enrichers.sh" "$TMP/nope.log" default
    [ "$status" -ne 0 ]
}
