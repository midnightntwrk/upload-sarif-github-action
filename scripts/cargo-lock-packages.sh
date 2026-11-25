#!/usr/bin/env bash
#
# Index every [[package]] in every Cargo.lock under a root, as JSON:
#
#   [{"path":"rust/Cargo.lock","name":"spin","version":"0.9.8","line":5,"source":"crates.io"}, ...]
#
# `path` is relative to the root, `line` is the [[package]] header - where a
# SARIF region should point - and `source` is crates.io, registry (any other),
# git or path (a workspace member or path dependency has no `source =` line).
#
# For the osv target. osv-scanner's JSON names a crate but not where it sits
# or where it came from, and deps.dev knows crates.io alone: it calls a git
# fork, a path crate (a workspace member, or a yanked crate vendored to patch
# it) or another registry's crate "yanked" whenever crates.io yanked the same
# name and version, and has no licence for any of them. The lockfile is the
# only record of the difference. Cargo writes crates.io as the git index URL
# whatever the protocol; the sparse form is accepted too.
set -euo pipefail

root="${1:?usage: cargo-lock-packages.sh <root>}"
cd "$root"

# One TSV line per package, then jq shapes it. mawk-compatible: no gensub.
index_one() {
    awk -v path="${1#./}" '
        function flush() {
            if (line) printf "%s\t%s\t%s\t%d\t%s\n", path, name, version, line, src
            name = ""; version = ""; line = 0; src = "path"
        }
        # Any table header ends the current package. Only [[package]] opens
        # one: [[patch.unused]] has a name and version too, and a field read
        # from there would overwrite the last real package.
        /^\[\[package\]\]/ { flush(); in_pkg = 1; line = FNR; next }
        /^\[/              { flush(); in_pkg = 0; next }
        !in_pkg            { next }
        /^name = "/        { v = $0; sub(/^name = "/, "", v);    sub(/"$/, "", v); name = v }
        /^version = "/     { v = $0; sub(/^version = "/, "", v); sub(/"$/, "", v); version = v }
        /^source = "git\+/                { src = "git" }
        /^source = "(registry|sparse)\+/  { src = "registry" }
        /^source = "registry\+https:\/\/github\.com\/rust-lang\/crates\.io-index"$/ { src = "crates.io" }
        /^source = "sparse\+https:\/\/index\.crates\.io\/"$/                        { src = "crates.io" }
        END { flush() }
    ' "$1"
}

find . -name Cargo.lock -type f | LC_ALL=C sort | while IFS= read -r f; do
    index_one "$f"
done | jq -R -s -c '
    split("\n") | map(select(length > 0) | split("\t")
        | {path: .[0], name: .[1], version: .[2], line: (.[3] | tonumber), source: .[4]})'
