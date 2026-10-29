#!/usr/bin/env bats
#
# scripts/spdx.jq: is a package's licence expression satisfied by an allowlist?
#
# osv-scanner's own --licenses evaluator cannot be used: it rejects any `WITH`
# form in the allowlist as non-SPDX and never matches one against its base
# licence, so `GPL-3.0-or-later WITH Classpath-exception-2.0` - 53 crates in
# midnight-node, allowed by policy - can only ever be a violation there.

load helper

# allowed <allowlist csv> <expression>... -- "true"/"false" per expression
allowed() {
    local list="$1"; shift
    for e in "$@"; do
        jq -rn -L "$ROOT/scripts" --arg list "$list" --arg e "$e" \
            'include "spdx"; $e | allowed_by($list | allowlist)'
    done | paste -sd' ' -
}

@test "a single identifier matches itself, case-insensitively" {
    [ "$(allowed "MIT,Apache-2.0" MIT mit Apache-2.0 GPL-3.0-only)" = "true true true false" ]
}

@test "OR needs one side, AND needs both" {
    [ "$(allowed "MIT,Apache-2.0" "Apache-2.0 OR MIT" "MIT OR GPL-3.0-only" "GPL-3.0-only OR AGPL-3.0")" = "true true false" ]
    [ "$(allowed "MIT,Apache-2.0" "Apache-2.0 AND MIT" "MIT AND GPL-3.0-only")" = "true false" ]
}

@test "AND binds tighter than OR, and parentheses override" {
    # unicode-ident: (MIT OR Apache-2.0) AND Unicode-DFS-2016
    [ "$(allowed "MIT" "(MIT OR Apache-2.0) AND Unicode-DFS-2016")" = false ]
    [ "$(allowed "MIT,Unicode-DFS-2016" "(MIT OR Apache-2.0) AND Unicode-DFS-2016")" = true ]
    # a AND b OR c == (a AND b) OR c
    [ "$(allowed "MIT" "GPL-3.0-only AND LGPL-3.0-only OR MIT")" = true ]
    [ "$(allowed "MIT" "GPL-3.0-only AND (LGPL-3.0-only OR MIT)")" = false ]
}

# An exception only grants more than the base licence does, so an allowed base
# carries its exceptions. A banned base is allowed with a named exception only.
@test "WITH: an allowed base allows its exceptions; a banned base needs the exact form" {
    [ "$(allowed "Apache-2.0" "Apache-2.0 WITH LLVM-exception")" = true ]
    [ "$(allowed "MIT" "GPL-3.0-or-later WITH Classpath-exception-2.0")" = false ]
    [ "$(allowed "MIT,GPL-3.0-or-later WITH Classpath-exception-2.0" \
        "GPL-3.0-or-later WITH Classpath-exception-2.0" "GPL-3.0-or-later" "GPL-3.0-only WITH Classpath-exception-2.0")" \
        = "true false false" ]
}

# deps.dev hands back pre-SPDX-3 spellings: `GPL-3.0+`, bare `LGPL-3.0`.
@test "legacy spellings are normalised: X+ is X-or-later, bare GPL-x.y is -only" {
    [ "$(allowed "LGPL-3.0-or-later" "LGPL-3.0+" "LGPL-3.0-or-later" "LGPL-3.0")" = "true true false" ]
    [ "$(allowed "LGPL-3.0-only" "LGPL-3.0" "LGPL-3.0-only" "LGPL-3.0+")" = "true true false" ]
    [ "$(allowed "GPL-3.0-only,gpl-3.0-or-later" "GPL-3.0" "GPL-3.0+")" = "true true" ]
}

# SPDX retired the one-token exception ids in 3.0; deps.dev still hands some
# back. Each means its modern `base WITH exception` form.
@test "a deprecated one-token exception id reads as its WITH form" {
    [ "$(allowed "GPL-2.0-only WITH Classpath-exception-2.0" "GPL-2.0-with-classpath-exception" "GPL-2.0-with-GCC-exception")" = "true false" ]
    [ "$(allowed "GPL-3.0-only WITH GCC-exception-3.1" "GPL-3.0-with-GCC-exception" "gpl-3.0-with-gcc-exception")" = "true true" ]
    [ "$(allowed "MIT" "GPL-2.0-with-classpath-exception")" = "false" ]
}

@test "the allowlist tolerates spaces and empty items" {
    [ "$(allowed " MIT , , Apache-2.0 " MIT Apache-2.0)" = "true true" ]
}

@test "UNKNOWN, non-standard and empty expressions are never allowed" {
    [ "$(allowed "MIT,UNKNOWN" UNKNOWN non-standard "")" = "false false false" ]
}

@test "a malformed expression is not allowed rather than an error" {
    [ "$(allowed "MIT" "MIT OR" "(MIT" "MIT AND AND Apache-2.0")" = "false false false" ]
}

# An allowed base allows its exceptions, but only when there is one: an
# operator or a bracket after WITH is a broken expression, not a grant.
@test "WITH needs an exception identifier, even on an allowed base" {
    [ "$(allowed "Apache-2.0" "Apache-2.0 WITH (" "Apache-2.0 WITH OR" "Apache-2.0 WITH" "Apache-2.0 WITH LLVM-exception")" = "false false false true" ]
}

# SPDX gives WITH a simple expression on its left - an identifier, never a
# bracketed group. `(MIT) WITH x` is malformed, and malformed grants nothing.
@test "WITH takes an identifier on its left, not a bracketed group" {
    [ "$(allowed "MIT" "(MIT) WITH Classpath-exception-2.0" "(MIT OR Apache-2.0) WITH LLVM-exception" "MIT WITH LLVM-exception")" = "false false true" ]
}

# SPDX separates tokens with whitespace, not only the space character.
@test "tabs and runs of whitespace separate tokens" {
    [ "$(allowed "MIT" "$(printf 'MIT\tOR  GPL-3.0-only')" "$(printf 'MIT\n AND\tApache-2.0')")" = "true false" ]
}

# deps.dev gives a list; every entry has to be satisfied.
@test "a package with several expressions needs all of them allowed" {
    [ "$(jq -rn -L "$ROOT/scripts" 'include "spdx"; ["MIT", "Apache-2.0 OR MIT"] | package_allowed("MIT" | allowlist)')" = true ]
    [ "$(jq -rn -L "$ROOT/scripts" 'include "spdx"; ["MIT", "GPL-3.0-only"] | package_allowed("MIT" | allowlist)')" = false ]
    [ "$(jq -rn -L "$ROOT/scripts" 'include "spdx"; [] | package_allowed("MIT" | allowlist)')" = false ]
}
