# SPDX licence expressions against an allowlist, for osv.jq.
#
#   include "spdx";   # jq -L scripts
#   "Apache-2.0 OR MIT" | allowed_by("MIT,Apache-2.0" | allowlist)   # true
#
# Why not osv-scanner's --licenses: it rejects a `WITH` form in the allowlist
# as non-SPDX and never matches one against its base, so an expression with an
# exception can only ever be a violation there. Grammar is SPDX 2.3 annex D:
#
#   expr   := and ( OR and )*          OR needs one side
#   and    := with ( AND with )*       AND needs both; binds tighter than OR
#   with   := atom ( WITH exc )?       an exception only grants more than the
#                                      base does, so an allowed base allows
#                                      every `WITH`; a banned base is allowed
#                                      with a named exception only
#   atom   := id | '(' expr ')'
#
# Identifiers compare case-insensitively (SPDX says so), after normalising the
# pre-2.0 spellings deps.dev still hands back: `GPL-3.0+` is `GPL-3.0-or-later`,
# a bare `GPL-3.0` is `GPL-3.0-only`, and the one-token exception ids SPDX
# retired in 3.0 (`GPL-2.0-with-classpath-exception`) are their `WITH` form.
# UNKNOWN is never allowed - the caller reports it under its own rule - and
# neither is anything malformed.

def legacy_with: {
    "gpl-2.0-with-autoconf-exception":  "gpl-2.0-only with autoconf-exception-2.0",
    "gpl-2.0-with-bison-exception":     "gpl-2.0-only with bison-exception-2.2",
    "gpl-2.0-with-classpath-exception": "gpl-2.0-only with classpath-exception-2.0",
    "gpl-2.0-with-font-exception":      "gpl-2.0-only with font-exception-2.0",
    "gpl-2.0-with-gcc-exception":       "gpl-2.0-only with gcc-exception-2.0",
    "gpl-3.0-with-autoconf-exception":  "gpl-3.0-only with autoconf-exception-3.0",
    "gpl-3.0-with-gcc-exception":       "gpl-3.0-only with gcc-exception-3.1" };

def normalise:
    ascii_downcase
    | if endswith("+") then .[:-1] + "-or-later" else . end
    | if test("^(a?gpl|lgpl)-[0-9]+\\.[0-9]+$") then . + "-only" else . end
    | legacy_with[.] // .;

# "MIT, Apache-2.0" -> {"mit": true, "apache-2.0": true}; a `WITH` item is one
# key with single spaces.
def allowlist:
    split(",") | map(gsub("^\\s+|\\s+$"; "") | select(length > 0)
                     | gsub("\\s+"; " ") | split(" ") | map(normalise) | join(" "))
    | map({key: ., value: true}) | from_entries;

def tokens:
    gsub("\\("; " ( ") | gsub("\\)"; " ) ") | [splits("\\s+")] | map(select(length > 0));

def operator: test("^(\\(|\\)|OR|AND|WITH)$"; "i");

# Each parser takes [tokens, index] and returns [value, index], or null when
# the input does not parse. `value` is true/false: allowed under $al.
def parse_expr($al):
    def atom:
        . as [$t, $i]
        | if $t[$i] == "(" then
              ([$t, $i + 1] | parse_expr($al)) as $r
              | if $r == null or $t[$r[1]] != ")" then null else [$r[0], $r[1] + 1] end
          elif $t[$i] == null or ($t[$i] | operator) then null
          # deps.dev's placeholders for "could not tell": not licences, so an
          # allowlist cannot name them into existence.
          elif ($t[$i] | ascii_downcase) == "unknown" or ($t[$i] | ascii_downcase) == "non-standard" then [false, $i + 1]
          # A legacy id normalises to `base with exc`: allowed as its base or as
          # the exact compound, the same as a spelled-out WITH.
          else ($t[$i] | normalise) as $n
               | [ (($al[$n | split(" ")[0]] // false) or ($al[$n] // false)), $i + 1 ] end;
    def with_:
        atom as $a
        | if $a == null then null
          else . as [$t, $i]
            # WITH's left side is a simple expression: an identifier, never a
            # bracketed group (annex D). `(MIT) WITH x` is malformed.
            | if ($t[$a[1]] // "" | ascii_downcase) == "with" and $t[$i] == "(" then null
              elif ($t[$a[1]] // "" | ascii_downcase) == "with" then
                  # The exception has to be an identifier: `MIT WITH (` is broken,
                  # and a broken expression grants nothing, allowed base or not.
                  if $t[$a[1] + 1] == null or ($t[$a[1] + 1] | operator) then null
                  else ([$t[$i], "with", $t[$a[1] + 1]] | map(normalise) | join(" ")) as $compound
                       | [ ($a[0] or ($al[$compound] // false)), $a[1] + 2 ] end
              else $a end
          end;
    def and_:
        with_ as $l
        | if $l == null then null
          else . as [$t, $i]
            | if ($t[$l[1]] // "" | ascii_downcase) == "and" then
                  ([$t, $l[1] + 1] | and_) as $r
                  | if $r == null then null else [($l[0] and $r[0]), $r[1]] end
              else $l end
          end;
    and_ as $l
    | if $l == null then null
      else . as [$t, $i]
        | if ($t[$l[1]] // "" | ascii_downcase) == "or" then
              ([$t, $l[1] + 1] | parse_expr($al)) as $r
              | if $r == null then null else [($l[0] or $r[0]), $r[1]] end
          else $l end
      end;

# expression string -> true/false
def allowed_by($al):
    (tokens) as $t
    | if ($t | length) == 0 then false
      else ([$t, 0] | parse_expr($al)) as $r
        | $r != null and $r[1] == ($t | length) and $r[0]
      end;

# ["expr", ...] -> true/false; deps.dev lists several when it found several,
# and every one has to be satisfied. No licence at all is not allowed.
def package_allowed($al):
    if length == 0 then false else all(.[]; allowed_by($al)) end;
