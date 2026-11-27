# osv-scanner JSON -> SARIF, with the gate's severities stamped on.
#
#   jq -L scripts -f osv.jq [--slurpfile packages cargo-lock-packages.json] \
#       [--slurpfile npm npm-lock-packages.json] [--arg version 2.7.0] \
#       [--rawfile osv_log osv-scanner-stderr.log] \
#       [--arg licenses "MIT,Apache-2.0,..." | --arg licenses default \
#        --rawfile default_licenses license-allowlist.txt] osv.json
#
# Why not osv-scanner's own `--format sarif`: it drops a deprecated package that
# has no vulnerability (google/osv-scanner#3164), and a yanked crate with no
# advisory is exactly the case worth reporting. Its JSON report keeps every
# package, with everything the SARIF writer used - advisory groups with a
# numeric `max_severity`, aliases, summaries, details, fixed ranges - so one
# scan produces one JSON and this file produces the SARIF. The licence data
# (--licenses --all-packages) is in the same JSON.
#
# Shape follows upstream's SARIF so existing code-scanning alerts keep their
# identity: one rule per advisory group, named by its display id (CVE before
# an ecosystem id before GHSA, lexical within a class - identifiers.IDSortFunc);
# one result per package per lockfile, at the lockfile with no line (osv gives
# none) - upstream emits that result once per matched id, so a RUSTSEC+GHSA
# pair appears twice there and once here; the message `Package 'name@version'
# is vulnerable to 'ID' (also known as ...)` (upstream names a git package by
# its short commit; messages are cosmetic, the fingerprint matches). Paths come
# out as /src/... because the scan runs in the container's /src; stripped so
# they read as they do in the repo.
#
# Severity is policy, and it lives here (see AGENTS.md):
#   MAL-*       CRITICAL. OSV's malicious-packages feed: malware, not a flaw,
#               binary like a leaked secret. No score, by design.
#   CVSS        the group's max_severity, banded the way the Security tab bands
#               it: 9.0 CRITICAL, 7.0 HIGH, 4.0 MEDIUM, else LOW.
#   deprecated  one `deprecated-package` result per package - yanked on
#               crates.io or PyPI, deprecated or unpublished on npm - MEDIUM,
#               through the same banding (the rule carries 5.0). A crate the
#               Cargo.lock index says did not come from crates.io (git, path,
#               another registry) is skipped, and so is an npm package a
#               package-lock resolved from outside the public registry:
#               deps.dev matches on name and version alone, so a fork is
#               "yanked" whenever crates.io yanked the same release.
#   licences    with --arg licenses (an SPDX allowlist, or `default` for
#               scripts/license-allowlist.txt passed as --rawfile
#               default_licenses; `none` or no --arg turns this off, an empty
#               list is an error) every package's expressions, as deps.dev
#               reports them under --licenses --all-packages, go through
#               spdx.jq. One that fails whatever its placeholders stand for is
#               a `license-violation`, HIGH, whatever else sits beside it;
#               one deps.dev could not tell (UNKNOWN, non-standard) is a
#               `license-unknown`, LOW, and only for a package deps.dev
#               answers for: one of its seven ecosystems, from the public
#               registry. A namesake - a path or other-registry crate, an
#               npm package a package-lock resolved from outside the public
#               registry - is never judged: deps.dev looked up a public
#               package with the same name (yarn, pnpm and bun lockfiles
#               record no source, so theirs are judged). An excused package
#               (no licences field) is a suppressed `license-excused` NOTE; a
#               package-lock with no public install at all, one
#               `license-unchecked` NOTE. Dev-only packages are skipped where
#               the lockfile marks them: nobody ships them. Optional ones ship. With
#               the package-lock.json index the lockfile's own flags
#               decide, since osv-scanner's groups cannot tell an optional
#               dependency of a dev dependency (not shipped) from a
#               devOptional one (shipped).
#   neither     no score on the rule: the plain `warning` reading applies.

include "spdx";

def band:
    if   . >= 9 then "CRITICAL"
    elif . >= 7 then "HIGH"
    elif . >= 4 then "MEDIUM"
    else "LOW" end;

def relpath: sub("^(file://)?/src/"; "");

# Upstream's partialFingerprints.primaryLocationLineHash is
# sha256("<rule id>:<artifact uri>:<package>") over the uri it wrote - an
# absolute path as file:///src/... - and results.PkgToString: name@version, or
# name@<8-char commit> for a git package. jq has no sha256, so the preimage rides
# in properties.fingerprint_input and scripts/sarif-fingerprints.sh hashes it.
# Same preimage, same hash: alerts raised from upstream's SARIF keep their
# identity.
#
# Go's net/url path escaping, which upstream's file URI went through: @uri
# (unreserved kept, UTF-8 bytes as %XX) except that $&+,/:;=@ stay literal.
def go_path_escape: explode | map([.] | implode | if test("^[$&+,/:;=@]$") then . else @uri end) | join("");
def upstream_uri: sub("^/github/workspace/"; "") | if startswith("/") then "file://" + go_path_escape else . end;
# A location uri: escaped as upstream's was, then made repo-relative.
def location_uri: go_path_escape | relpath;
def pkg_string:
    if (.commit // "") != ""
    then (if (.name // "") != "" then "\(.name)@\(.commit[:8])" else .commit end)
    else "\(.name)@\(.version)" end;
def fingerprint_input($id; $source_path; $pkg): "\($id):\($source_path | upstream_uri):\($pkg | pkg_string)";

# Lockfile indexes (cargo-lock-packages.sh, npm-lock-packages.sh) hold every
# entry, keyed on path|name|version with raw repo-relative paths. A key can
# repeat - a crates.io crate and its git twin, a package installed twice - so
# each key maps to every entry, and callers decide with any().
def lock_key: "\(.path)|\(.name)|\(.version)";
def lock_index: group_by(lock_key) | map({key: (.[0] | lock_key), value: .}) | from_entries;
# The first crates.io entry of a package, by line; null when there is none.
def crates_io_entry($entries): [$entries[]? | select(.source == "crates.io")] | min_by(.line);
def indexed_paths: map({key: .path, value: true}) | from_entries;

# A package's Cargo.lock entries: null when its lockfile was never indexed (no
# Cargo.lock, another ecosystem). osv-scanner and cargo-lock-packages.sh read
# the same [[package]] list, so an indexed lockfile without the crate means the
# index misread the file: an error, never a silent skip of both rules.
def lock_entries($index; $indexed; $path; $key):
    $index[$key] // (if $indexed[$path]
        then error("\($path) is indexed but has no [[package]] entry for \($key | split("|") | "\(.[1])@\(.[2])"): "
            + "scripts/cargo-lock-packages.sh misread the lockfile. Please report it with the lockfile's entry.")
        else null end);

def osv_link: "[\(.)](https://osv.dev/\(.))";

# identifiers.prefixOrder: higher sorts first.
def id_rank:
    (split("-")[0]) as $p
    | if $p == "DSA" or $p == "USN" then 3
      elif $p == "CVE" then 2
      elif $p == "GHSA" then 0
      else 1 end;
def sort_ids: unique | sort_by([-(id_rank), .]);

def quote_block: (. // "") | split("\n") | map("> " + .) | join("\n");

# Help markdown, after upstream's SARIFTemplate.
def help_md($id; $aliases; $vulns; $hits):
    "**Your dependency is vulnerable to \($id | osv_link)**"
    + (if ($aliases | length) > 1
       then "\n(Also published as: \([$aliases[] | select(. != $id) | osv_link] | join(", ")))"
       else "" end)
    + ".\n\n"
    + ([$vulns[] | "## \(.id | osv_link)\n\n<details>\n<summary>Details</summary>\n\n"
                   + (.details // .summary | quote_block) + "\n\n</details>\n"] | join("\n"))
    + "\n---\n\n### Affected Packages\n\n| Source | Package Name | Package Version |\n| --- | --- | --- |\n"
    + ([$hits[] | "| \(.path) | \(.name) | \(.version) |"] | join("\n"))
    + "\n\n### Fixed Versions\n\n| Vulnerability ID | Package Name | Fixed Version |\n| --- | --- | --- |\n"
    + ([$vulns[] | .id as $vid
        | (.affected // [])[] | .package.name as $pn
        | [(.ranges // [])[] | (.events // [])[] | .fixed // empty] | select(length > 0)
        | "| \($vid) | \($pn) | \(join(", ")) |"] | unique | join("\n"))
    + "\n";

# --- flatten the report -------------------------------------------------------

# One record per (lockfile, package, advisory group).
def hits:
    [ (.results // [])[]
      | (.source.path // "") as $raw | ($raw | location_uri) as $path
      | (.packages // [])[]
      | .package as $pkg | (.vulnerabilities // []) as $vulns
      | (.groups // [])[]
      | (.ids // []) as $ids
      | [$vulns[] | select(.id as $v | $ids | index($v))] as $mine
      # The group's own `aliases` may be null; upstream unions each
      # matched advisory's id and aliases, so do the same.
      | (($ids + (.aliases // []) + [$mine[] | .id, (.aliases // [])[]]) | sort_ids) as $aliases
      | { id: $aliases[0], aliases: $aliases, ids: $ids,
          max: (.max_severity // "" | if . == "" then null else . end),
          path: $path, raw_path: $raw, pkg: $pkg,
          name: $pkg.name, version: $pkg.version, ecosystem: $pkg.ecosystem,
          vulns: $mine } ];

# One rule per display id, across every package it hits. osv-scanner scores each
# package's group separately, so one CVE can be 5.0 on one package and 9.8 on
# another; the rule carries the worst, as upstream's does.
def vuln_rule($group):
    ($group[0]) as $h
    | ([$group[].max | select(. != null)] | max_by(tonumber)) as $max
    | ([$group[].vulns[]] | unique_by(.id)) as $vulns
    | ([$vulns[] | select(.id == $h.id)] + $vulns | .[0]) as $lead
    | { id: $h.id,
        name: ($h.id | gsub("-"; "")),
        shortDescription: {text: "\($h.id): \($lead.summary // $lead.details // "" | split("\n")[0])"},
        fullDescription: {text: ($lead.details // $lead.summary // "")},
        helpUri: "https://osv.dev/\($h.id)",
        help: {text: ($lead.details // $lead.summary // ""),
               markdown: help_md($h.id; $h.aliases; $vulns; $group)},
        deprecatedIds: $h.aliases }
      + (if $max != null then {properties: {"security-severity": $max}} else {} end);

def vuln_result:
    { ruleId: .id, level: "warning",
      message: {text: ("Package '\(.name)@\(.version)' is vulnerable to '\(.id)'"
          + (if (.aliases | length) > 1
             then " (also known as '\(.aliases[1:] | join("', '"))')" else "" end) + ".")},
      locations: [{physicalLocation: {artifactLocation: {uri: .path}}}],
      properties: {fingerprint_input: fingerprint_input(.id; .raw_path; .pkg)} }
    | if (.ruleId | startswith("MAL-")) then .properties.severity = "CRITICAL" else . end;

# --- licences -----------------------------------------------------------------

# Without the package-lock index only osv-scanner's groups are left. npm
# installs an optional dependency whenever it can, so it ships (fsevents,
# detect-libc); `dev` alone does not. `dev` + `optional` is either devOptional
# (ships) or an optional dependency of a dev dependency (esbuild's platform
# binaries, does not): the groups cannot tell them apart, so it counts as
# shipping, and only the index (ships, below) gets it right.
def dev_only: (.dependency_groups // []) | (index("dev") != null) and (index("optional") == null);

# With the lockfile's flags (scripts/npm-lock-packages.sh) the answer is exact:
# `dev` is set for the dev-only and the dev+optional states, and for neither of
# the two that ship (optional, devOptional). One name@version can be installed
# more than once in a lockfile - at the root for production and again under a
# dev tool's node_modules - and osv-scanner reports it once, so $entries is
# every install of it: the package ships if any of them does.
def ships($entries): if $entries != null then any($entries[]; .dev != true) else (dev_only | not) end;
def shipping_line($entries): [$entries[]? | select(.dev != true) | .line][0];

# The ecosystems deps.dev answers for; scalibr's licence enricher writes
# ["UNKNOWN"] for any other without asking. Go's `stdlib` is the toolchain:
# deps.dev is asked about it, but judging it is not this action's business.
def deps_dev_package:
    IN(.ecosystem; "npm", "NuGet", "crates.io", "Go", "Maven", "PyPI", "RubyGems")
    and (.ecosystem != "Go" or .name != "stdlib");

# deps.dev looks a package up by name and version on the public registry. For
# a path or other-registry crate, or an npm package from anywhere
# but the public registry, that is a namesake: its licence says nothing about
# this package. A Cargo git fork keeps its upstream's licence, so the
# crates.io answer stands for it.
#
# npm: the package-lock index's `source` (where the lockfile resolved each
# install; scripts/npm-lock-packages.sh) decides when there is one: npmjs and
# default (no resolved URL) are the public registry, other and local are not.
# Only installs that ship count: a dev-only public copy says nothing about a
# private one that ships. With no index entry - yarn.lock, pnpm-lock.yaml and
# bun.lock are not indexed - the purl decides, and scalibr writes a `source`
# qualifier for package-lock packages only: an unqualified npm purl is judged.
def npm_sources($installs): [$installs[]? | select(.dev != true) | .source // empty];
def npm_public: . == "npmjs" or . == "default";
def namesake($entries; $installs):
    npm_sources($installs) as $src
    | if .ecosystem == "crates.io" and $entries != null
      then any($entries[]; .source == "crates.io" or .source == "git") | not
      elif ($src | length) > 0 then any($src[]; npm_public) | not
      else (.purl // "") | test("[?&]source=(LOCAL|OTHER)(&|$)") end;

# deps.dev with nothing to say: unknown, LOW, and only where deps.dev is the
# authority - crates.io itself for a Cargo crate (not a git twin), the public
# registry for the rest.
def public_registry($entries; $installs):
    npm_sources($installs) as $src
    | deps_dev_package
    and (if .ecosystem == "crates.io" then $entries == null or any($entries[]; .source == "crates.io")
         elif ($src | length) > 0 then any($src[]; npm_public)
         else (.purl // "") | (test("[?&]source=") | not) or test("[?&]source=PUBLIC_REGISTRY(&|$)") end);

# --- deprecated packages ------------------------------------------------------

# crates.io and PyPI yank; npm deprecates. Say what the registry says.
def registry_word: if . == "crates.io" or . == "PyPI" then "yanked" else "deprecated" end;

def deprecated_rule: {
    id: "deprecated-package",
    name: "DeprecatedPackage",
    shortDescription: {text: "Package version is deprecated or yanked upstream"},
    fullDescription: {text: ("The registry no longer serves or supports this version. "
        + "A yank usually follows a defect found before any advisory was filed, so no "
        + "vulnerability id will ever name it. Update to a version that is still "
        + "published; a deliberate pin is excluded in osv-scanner.toml with a reason.")},
    helpUri: "https://google.github.io/osv-scanner/experimental/flag-deprecated-packages/",
    properties: {tags: ["security"], "security-severity": "5.0"}
};

# The index holds every lockfile entry per path|name|version: one Cargo.lock can
# carry a crates.io crate and a git or path twin of the same name and version.
# Report when any entry is crates.io, at the first such line; a lockfile never
# indexed (no Cargo.lock, another ecosystem) reports on its package-lock line
# or line 1. An npm namesake is skipped, as for licences.
def deprecated_results($packages; $npm):
    ($packages | lock_index) as $index
    | ($packages | indexed_paths) as $indexed
    | ($npm | lock_index) as $nindex
    | [ (.results // [])[]
        | (.source.path // "") as $raw | ($raw | location_uri) as $path
        | (.packages // [])[] | .package | select(.deprecated == true)
        | ({path: ($raw | relpath), name, version} | lock_key) as $key
        | lock_entries($index; $indexed; $raw | relpath; $key) as $entries
        | $nindex[$key] as $installs
        | select($entries == null or any($entries[]; .source == "crates.io"))
        | select(.ecosystem != "npm" or (namesake(null; $installs) | not))
        | (crates_io_entry($entries)
           // (shipping_line($installs) | if . == null then null else {line: .} end)) as $known
        | {key: $key, pkg: ., path: $path, raw: $raw, known: $known} ]
    | unique_by(.key)
    | [ .[] | .known as $known | .path as $path | .raw as $raw | .pkg
        | { ruleId: "deprecated-package", level: "warning",
            message: {text: ("Package '\(.name)@\(.version)' (\(.ecosystem)) is "
                + "\(.ecosystem | registry_word) upstream: the registry no longer serves "
                + "this version. Update to one that is still published.")},
            locations: [{physicalLocation: {
                artifactLocation: {uri: $path},
                region: {startLine: ($known.line // 1)}}}],
            properties: {fingerprint_input: fingerprint_input("deprecated-package"; $raw; .)} } ];

def licence_rules($items):
    ($items | join(", ")) as $shown
    | [ { id: "license-violation",
          name: "LicenseViolation",
          shortDescription: {text: "Package licence is outside the allowlist"},
          fullDescription: {text: ("The package's licence expression is not satisfied by the "
              + "allowlist. Replace the dependency, or excuse this one package in osv-scanner.toml "
              + "with [[PackageOverrides]] license.ignore = true and a reason.")},
          help: {text: "Allowed: \($shown)"},
          helpUri: "https://spdx.org/licenses/" },
        { id: "license-unknown",
          name: "LicenseUnknown",
          shortDescription: {text: "Package licence could not be determined"},
          fullDescription: {text: ("deps.dev reports no usable licence for this version (UNKNOWN or "
              + "non-standard text). Read the package's own LICENSE and record the result in "
              + "osv-scanner.toml with [[PackageOverrides]] license.override = [\"<SPDX id>\"].")},
          help: {text: "Allowed: \($shown)"},
          helpUri: "https://docs.deps.dev/faq/#how-are-licenses-determined" },
        { id: "license-excused",
          name: "LicenseExcused",
          shortDescription: {text: "Package licence check excused in osv-scanner.toml"},
          fullDescription: {text: ("[[PackageOverrides]] license.ignore = true removed this package's "
              + "licence before it was judged. Listed so the excuse stays visible; it never fails the "
              + "gate. The reason belongs beside it in osv-scanner.toml.")},
          help: {text: "Allowed: \($shown)"},
          helpUri: "https://google.github.io/osv-scanner/configuration/" } ];

# $items: the allowlist as SPDX ids, or [] for off. Per package, in order:
#   - no `licenses` key: excused (osv-scanner drops the field for
#     [[PackageOverrides]] license.ignore) - listed as `license-excused`,
#     suppressed, never gated; a field that is there but empty is "could not
#     tell";
#   - a namesake (path or other-registry crate, an npm package from outside
#     the public registry): deps.dev's licence is another package's - nothing
#     to report;
#   - any expression that fails whatever its placeholders stand for: violation;
#   - otherwise any placeholder (UNKNOWN, non-standard, or no licence at all),
#     from a registry deps.dev answers for: unknown.
# A licence entry that is not a string is a report format change: an error,
# never read as UNKNOWN, which would turn every violation into a LOW.
# The package's licence expressions: an array of strings by schema. [] and
# blanks are "could not tell" (UNKNOWN), not an excuse; a bare string is one
# item; any non-string entry is a format change and an error.
def licence_exprs($pk):
    .licenses | if type == "array" then . elif . == null then [] else [.] end
    | map(if type == "string" then trim
          else error("osv-scanner gave \($pk.name)@\($pk.version) a licence entry that is \(type), "
              + "not a string: \(tojson). The report format changed; update scripts/osv.jq to read it.") end
          | select(length > 0))
    | if length == 0 then ["UNKNOWN"] else . end;

def licence_results($items; $packages; $npm):
    if ($items | length) == 0 then [] else
    ($items | join(",") | allowlist) as $al
    | ($packages | lock_index) as $index
    | ($packages | indexed_paths) as $indexed
    | ($npm | lock_index) as $nindex
    | [ (.results // [])[]
        | (.source.path // "") as $raw
        | {path: ($raw | relpath)} as $at
        | (.packages // [])[]
        | .package as $pk
        | ($at + {name: $pk.name, version: $pk.version} | lock_key) as $key
        | $nindex[$key] as $installs
        | select(ships($installs))
        | lock_entries($index; $indexed; $at.path; $key) as $entries
        | select($pk | namesake($entries; $installs) | not)
        | if has("licenses") | not then
            # osv-enrichers.sh has already failed the scan on a failed lookup,
            # so a missing key here is license.ignore: listed, never hidden.
            { ruleId: "license-excused", level: "note",
              suppressions: [{kind: "external", status: "accepted",
                  justification: "[[PackageOverrides]] license.ignore in osv-scanner.toml"}],
              message: {text: ("Package '\($pk.name)@\($pk.version)' (\($pk.ecosystem)): licence check "
                  + "excused by license.ignore in osv-scanner.toml, so its licence was not judged.")},
              locations: [{physicalLocation: {artifactLocation: {uri: ($raw | location_uri)},
                  region: {startLine: ((crates_io_entry($entries) // $entries[0]?).line
                                       // shipping_line($installs) // 1)}}}],
              properties: {severity: "NOTE", fingerprint_input: fingerprint_input("license-excused"; $raw; $pk)} }
          else .
        | licence_exprs($pk) as $lic
        | ( if any($lic[]; allowed_if_known($al) | not) then
                { ruleId: "license-violation", level: "error", properties: {severity: "HIGH"},
                  message: {text: ("Package '\($pk.name)@\($pk.version)' (\($pk.ecosystem)) is licensed "
                      + "'\($lic | join("; "))', which the allowlist does not permit.")} }
            elif any($lic[]; allowed_by($al) | not) and ($pk | public_registry($entries; $installs)) then
                { ruleId: "license-unknown", level: "note", properties: {severity: "LOW"},
                  message: {text: ("Package '\($pk.name)@\($pk.version)' (\($pk.ecosystem)): "
                      + "deps.dev reports no usable licence (\($lic | join(", "))). "
                      + "Check the package's own LICENSE and record it in osv-scanner.toml.")} }
            else empty end )
        | .locations = [{physicalLocation: {artifactLocation: {uri: ($raw | location_uri)},
                                            region: {startLine: ((crates_io_entry($entries) // $entries[0]?).line
                                                                 // shipping_line($installs) // 1)}}}]
        | .properties.fingerprint_input = fingerprint_input(.ruleId; $raw; $pk)
          end ]
    | unique_by(.properties.fingerprint_input)
    end;

# A package-lock whose shipping installs all resolve outside the public
# registry has every licence skipped as a namesake - and a registry proxy of
# the public registry reads exactly like that. Say so once per lockfile, at
# NOTE: listed in the summary, never gated. A lockfile with any public install
# is the ordinary mix of public and private packages and stays quiet.
def unchecked_results($items; $npm):
    if ($items | length) == 0 then [] else
    [ $npm | group_by(.path)[]
      | [.[] | select(.dev != true and .source != null)] as $ship
      | select(($ship | length) > 0 and (any($ship[]; .source | npm_public) | not))
      | ($ship | map("\(.name)@\(.version)") | unique) as $pk
      | { ruleId: "license-unchecked", level: "note", properties: {severity: "NOTE",
            fingerprint_input: "license-unchecked:\("/src/" + .[0].path | upstream_uri)"},
          message: {text: ("\($pk | length) shipping npm package(s) in \(.[0].path) resolve from outside "
              + "registry.npmjs.org (\($pk[:5] | join(", "))\(if ($pk | length) > 5 then ", ..." else "" end)), "
              + "so none had its licence checked: deps.dev only knows the public registry. "
              + "If that registry mirrors npmjs, check these licences another way.")},
          locations: [{physicalLocation: {artifactLocation: {uri: (.[0].path | go_path_escape)},
                                          region: {startLine: 1}}}] } ]
    end;

def unchecked_rule: {
    id: "license-unchecked",
    name: "LicenseUnchecked",
    shortDescription: {text: "npm lockfile's licences could not be checked"},
    fullDescription: {text: ("Every shipping package in this lockfile resolves outside the public npm "
        + "registry, so deps.dev's licence data (keyed on the public name) does not apply and none was "
        + "checked. Informational; never fails the gate.")},
    helpUri: "https://docs.deps.dev/faq/#how-are-licenses-determined"
};

# --- unreadable lockfiles -----------------------------------------------------

# osv-scanner logs a lockfile it cannot parse - `Error during extraction:
# (extracting as <extractor>) <path>: <error>`, or the header alone and one
# tab-indented `<path>: <error>` line per file when there are several
# (pkg/osvscanner/scan.go logPluginStatus) - and scans the rest. Its exit code
# is 1 whenever anything else was found, so without this the lockfile drops
# out unseen: none of its packages checked for anything. MEDIUM, at the
# lockfile. Enricher failures (network) are osv-enrichers.sh's and fail the
# scan; annotator lines are not lockfiles. Paths are relative to / (src/...).
def unreadable_results($log):
    if $log == null then [] else
    [ foreach ($log | split("\n")[]) as $l ({ext: null, out: null};
          ([$l | capture("^Error during extraction: \\(extracting as (?<ext>[^)]+)\\) ?(?<rest>.*)$")] | .[0]) as $h
          | if $h != null then {ext: $h.ext, out: (if ($h.rest | length) > 0 then $h else null end)}
            elif ($l | startswith("\t")) and .ext != null then {ext: .ext, out: {ext: .ext, rest: ($l | ltrimstr("\t"))}}
            else {ext: null, out: null} end;
          .out // empty)
      | select(.ext | test("^(vulnmatch|license|packagedeprecation|misc)/") | not)
      | . as {$ext} | (.rest | capture("^(?<path>.+?): (?<err>.*)$")) // empty
      | (.path | sub("^/?src/"; "")) as $rel
      | { ruleId: "lockfile-unreadable", level: "warning",
          message: {text: ("osv-scanner could not read \($rel) (\($ext)): \(.err). None of its packages "
              + "was checked for advisories, malware, licences or deprecation. Fix the lockfile, or "
              + "remove it if it is a broken test fixture.")},
          locations: [{physicalLocation: {artifactLocation: {uri: ($rel | go_path_escape)},
                                          region: {startLine: 1}}}],
          properties: {severity: "MEDIUM",
                       fingerprint_input: "lockfile-unreadable:\("/src/" + $rel | upstream_uri)"} } ]
    | unique_by(.properties.fingerprint_input)
    end;

def unreadable_rule: {
    id: "lockfile-unreadable",
    name: "LockfileUnreadable",
    shortDescription: {text: "osv-scanner could not read a lockfile"},
    fullDescription: {text: ("The lockfile could not be parsed, so none of its packages was checked. "
        + "osv-scanner logs this and carries on, so it would otherwise go unseen.")},
    helpUri: "https://google.github.io/osv-scanner/supported-languages-and-lockfiles/"
};

# --- assemble -----------------------------------------------------------------

# Licences: off when --arg licenses is absent or `none`; `default` reads the
# --rawfile default_licenses list. Anything that would leave the list empty is
# a configuration error, not a quiet off switch.
def licence_allowlist($arg):
    ($arg // "" | trim | ascii_downcase) as $mode
    | if $arg == null or $mode == "none" then []
      elif $mode == "default" then
          ($ARGS.named.default_licenses // error("licenses_allowlist is default but no --rawfile default_licenses was given")
           | split("\n") | map(sub("#.*"; "") | trim | select(length > 0))
           | if length == 0 then error("licenses_allowlist is default but default_licenses lists nothing") else . end)
      else ($arg | list_items
            | if length == 0 then error("licenses_allowlist is empty: pass none to turn licence checks off") else . end
            | if any(.[]; ascii_downcase | . == "default" or . == "none")
              then error("licenses_allowlist \"\($arg)\" mixes ids with default or none: those name the whole list, so pass one of them alone, or spell out every id")
              else . end)
      end;


($ARGS.named.packages // [] | .[0] // []) as $packages
| ($ARGS.named.npm // [] | .[0] // []) as $npm
| licence_allowlist($ARGS.named.licenses) as $licences
| hits as $hits
| deprecated_results($packages; $npm) as $deprecated
| licence_results($licences; $packages; $npm) as $licence
| unchecked_results($licences; $npm) as $unchecked
| unreadable_results($ARGS.named.osv_log) as $unreadable
| ($hits | group_by(.id) | map(vuln_rule(.))) as $vuln_rules
| ($vuln_rules
   + (if ($deprecated | length) > 0 then [deprecated_rule] else [] end)
   + (if ($licence | length) > 0 then licence_rules($licences) else [] end)
   + (if ($unchecked | length) > 0 then [unchecked_rule] else [] end)
   + (if ($unreadable | length) > 0 then [unreadable_rule] else [] end)) as $rules
| ( [ $rules[] | select(.properties["security-severity"] != null)
      | { key: .id, value: (.properties["security-severity"] | tonumber) } ]
    | from_entries ) as $cvss
| { "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: {driver: ({ name: "osv-scanner",
                        informationUri: "https://github.com/google/osv-scanner",
                        rules: $rules }
                      + (if ($ARGS.named.version // "") != "" then {version: $ARGS.named.version} else {} end))},
      results: ( [ $hits[] | vuln_result ] + $deprecated + $licence + $unchecked + $unreadable
                 | map( $cvss[.ruleId] as $score
                      | if .properties.severity == null and $score != null
                        then .properties.severity = ($score | band) else . end ) )
    }] }
