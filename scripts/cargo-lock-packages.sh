#!/usr/bin/env bash
#
# Index every [[package]] in every Cargo.lock under a root, as JSON:
#
#   [{"path":"rust/Cargo.lock","name":"spin","version":"0.9.8","line":5,"git":false}, ...]
#
# `path` is relative to the root, `line` is the [[package]] header - where a
# SARIF region should point - and `git` says whether `source` is a git URL.
#
# For the osv target. osv-scanner's JSON names a deprecated crate but not
# where it sits or where it came from, and deps.dev decides "deprecated" by name
# and version alone, so a crate built from a git fork is flagged whenever
# crates.io yanked the same release. The lockfile is the only record of the
# difference.
set -euo pipefail

root="${1:?usage: cargo-lock-packages.sh <root>}"
cd "$root"

# One TSV line per package, then jq shapes it. mawk-compatible: no gensub.
index_one() {
    awk -v path="${1#./}" '
        function flush() {
            if (line) printf "%s\t%s\t%s\t%d\t%s\n", path, name, version, line, git
            name = ""; version = ""; line = 0; git = "false"
        }
        /^\[\[package\]\]/ { flush(); line = FNR; next }
        /^name = "/        { v = $0; sub(/^name = "/, "", v);    sub(/"$/, "", v); name = v }
        /^version = "/     { v = $0; sub(/^version = "/, "", v); sub(/"$/, "", v); version = v }
        /^source = "git\+/ { git = "true" }
        END { flush() }
    ' "$1"
}

find . -name Cargo.lock -type f | LC_ALL=C sort | while IFS= read -r f; do
    index_one "$f"
done | jq -R -s -c '
    split("\n") | map(select(length > 0) | split("\t")
        | {path: .[0], name: .[1], version: .[2], line: (.[3] | tonumber), git: (.[4] == "true")})'
