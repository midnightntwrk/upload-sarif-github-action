# osv-scanner JSON -> SARIF, with the gate's severities stamped on.
#
#   jq -L scripts -f osv.jq [--slurpfile packages cargo-lock-packages.json] \
#       [--slurpfile npm npm-lock-packages.json] [--arg version 2.7.0] \
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
# is vulnerable to 'ID' (also known as ...)`. Paths come out as /src/... because the scan runs in the
# container's /src; stripped so they read as they do in the repo.
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
#               another registry) is skipped: deps.dev matches on name and
#               version alone, so a fork is "yanked" whenever crates.io yanked
#               the same release.
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
#               registry. A namesake - a path or other-registry crate, a
#               local or private npm package - is never judged: deps.dev
#               looked up a public package with the same name. An excused
#               package (no licences field) is never reported, but no
#               licence data at all is an error. Dev-only packages
#               are skipped: nobody ships them. Optional ones ship. With
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
def indexed_paths: map({key: .path, value: true}) | from_entries;

# A package's Cargo.lock entries: null when its lockfile was never indexed (no
# Cargo.lock, another ecosystem); [] when the lockfile was but the crate is not
# in it - provenance unknown, so never taken for crates.io's.
def lock_entries($index; $indexed; $path; $key): $index[$key] // (if $indexed[$path] then [] else null end);

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
      # The group's own `aliases` is not always present; upstream unions each
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
# Report when any entry is crates.io, at the first such line. Not in the index
# (no Cargo.lock, or another ecosystem): report, on line 1.
def deprecated_results($packages):
    ($packages | lock_index) as $index
    | ($packages | indexed_paths) as $indexed
    | [ (.results // [])[]
        | (.source.path // "") as $raw | ($raw | location_uri) as $path
        | (.packages // [])[] | .package | select(.deprecated == true)
        | ({path: ($raw | relpath), name, version} | lock_key) as $key
        | lock_entries($index; $indexed; $raw | relpath; $key) as $entries
        | select($entries == null or any($entries[]; .source == "crates.io"))
        | ($entries // [] | map(select(.source == "crates.io")) | min_by(.line)) as $known
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

# --- licences -----------------------------------------------------------------

# npm installs an optional dependency whenever it can, so it ships (fsevents,
# detect-libc); only a package reached through dev dependencies alone does not
# (esbuild's platform binaries, an optional dependency of a dev dependency). package-lock.json's `devOptional` - on a dev
# path and an optional path, never a plain production one - arrives as both
# groups and ships with the optional path.
def dev_only: (.dependency_groups // []) | (index("dev") != null) and (index("optional") == null);

# With the lockfile's flags (scripts/npm-lock-packages.sh) the answer is exact:
# `dev` is set for the dev-only and the dev+optional states, and for neither of
# the two that ship (optional, devOptional). One name@version can be installed
# more than once in a lockfile - at the root for production and again under a
# dev tool's node_modules - and osv-scanner reports it once, so $entries is
# every install of it: the package ships if any of them does.
def ships($entries): if $entries != null then any($entries[]; .dev != true) else (dev_only | not) end;
def shipping_line($entries): [$entries[]? | select(.dev != true) | .line][0];

# The ecosystems deps.dev answers for. osv-scanner writes ["UNKNOWN"] for any
# other without asking, and Go's `stdlib` is the toolchain, not a package.
def deps_dev_package:
    IN(.ecosystem; "npm", "NuGet", "crates.io", "Go", "Maven", "PyPI", "RubyGems")
    and (.ecosystem != "Go" or .name != "stdlib");

# deps.dev looks a package up by name and version on the public registry. For
# a path, other-registry or unindexed crate, or a local or private-registry npm
# package, that is a namesake: its licence says nothing about this package. A
# git fork keeps its upstream's licence, so the crates.io answer stands for it.
def namesake($entries):
    if .ecosystem == "crates.io" and $entries != null
    then any($entries[]; .source == "crates.io" or .source == "git") | not
    else (.purl // "") | test("[?&]source=(LOCAL|PRIVATE_REGISTRY)(&|$)") end;

# deps.dev with nothing to say: unknown, LOW, and only where deps.dev is the
# authority - crates.io itself for a Cargo crate (not a git twin), the public
# registry for the rest.
def public_registry($entries):
    deps_dev_package
    and (if .ecosystem == "crates.io" then $entries == null or any($entries[]; .source == "crates.io")
         else (.purl // "") | (test("[?&]source=") | not) or test("[?&]source=PUBLIC_REGISTRY(&|$)") end);

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
          helpUri: "https://docs.deps.dev/faq/#how-are-licenses-determined" } ];

# $items: the allowlist as SPDX ids, or [] for off. Per package, in order:
#   - no `licenses` key: excused (osv-scanner drops the field for
#     [[PackageOverrides]] license.ignore) - nothing to report; a field that
#     is there but empty is "could not tell";
#   - a namesake (path or other-registry crate, local or private npm
#     package): deps.dev's licence is another package's - nothing to report;
#   - any expression that fails whatever its placeholders stand for: violation;
#   - otherwise any placeholder (UNKNOWN, non-standard, null), from a registry
#     deps.dev answers for: unknown.
# A licence entry that is neither a string nor null is a report format change:
# an error, never read as UNKNOWN, which would turn every violation into a LOW.
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
        | select(has("licenses"))
        | .package as $pk
        | ($at + {name: $pk.name, version: $pk.version} | lock_key) as $key
        | $nindex[$key] as $installs
        | select(ships($installs))
        | lock_entries($index; $indexed; $at.path; $key) as $entries
        | select($pk | namesake($entries) | not)
        # An array of strings by schema. null, [] and blanks are "could not
        # tell", not an excuse; an object or array is a format change.
        | (.licenses | if type == "array" then . elif . == null then [] else [.] end
           | map(if type == "string" then trim
                 elif . == null then "UNKNOWN"
                 else error("osv-scanner gave \($pk.name)@\($pk.version) a licence entry that is \(type), "
                     + "not a string: \(tojson). The report format changed; update scripts/osv.jq to read it.") end
                 | select(length > 0))
           | if length == 0 then ["UNKNOWN"] else . end) as $lic
        | ([$entries[]? | select(.source == "crates.io")] | min_by(.line) // $entries[0]?) as $known
        | ( if any($lic[]; allowed_if_known($al) | not) then
                { ruleId: "license-violation", level: "error", properties: {severity: "HIGH"},
                  message: {text: ("Package '\($pk.name)@\($pk.version)' (\($pk.ecosystem)) is licensed "
                      + "'\($lic | join("; "))', which the allowlist does not permit.")} }
            elif any($lic[]; allowed_by($al) | not) and ($pk | public_registry($entries)) then
                { ruleId: "license-unknown", level: "note", properties: {severity: "LOW"},
                  message: {text: ("Package '\($pk.name)@\($pk.version)' (\($pk.ecosystem)): "
                      + "deps.dev reports no usable licence (\($lic | join(", "))). "
                      + "Check the package's own LICENSE and record it in osv-scanner.toml.")} }
            else empty end )
        | .locations = [{physicalLocation: {artifactLocation: {uri: ($raw | location_uri)},
                                            region: {startLine: ($known.line // shipping_line($installs) // 1)}}}]
        | .properties.fingerprint_input = fingerprint_input(.ruleId; $raw; $pk) ]
    | unique_by(.properties.fingerprint_input)
    end;

# --- assemble -----------------------------------------------------------------

($ARGS.named.packages // [] | .[0] // []) as $packages
| ($ARGS.named.npm // [] | .[0] // []) as $npm
# Licences: off when --arg licenses is absent or `none`; `default` reads the
# --rawfile default_licenses list. Anything that would leave the list empty is
# a configuration error, not a quiet off switch.
| ( $ARGS.named.licenses as $arg
    | if $arg == null or ($arg | trim | ascii_downcase) == "none" then []
      elif ($arg | trim | ascii_downcase) == "default" then
          ($ARGS.named.default_licenses // error("licenses_allowlist is default but no --rawfile default_licenses was given")
           | split("\n") | map(sub("#.*"; "") | trim | select(length > 0))
           | if length == 0 then error("licenses_allowlist is default but default_licenses lists nothing") else . end)
      else ($arg | list_items
            | if length == 0 then error("licenses_allowlist is empty: pass none to turn licence checks off") else . end)
      end ) as $licences
| hits as $hits
| deprecated_results($packages) as $deprecated
| licence_results($licences; $packages; $npm) as $licence
# Licences on, packages deps.dev answers for, and not one with a licences
# field. osv-scanner's enricher returns before writing any licence when its
# deps.dev request fails, so an outage reads exactly like "all excused": fail,
# never pass the licence gate on no data.
| ( [.results[]?.packages[]? | select(.package | deps_dev_package)] as $asked
    | if ($licences | length) > 0 and ($asked | length) > 0 and (any($asked[]; has("licenses")) | not)
      then error("licenses_allowlist is set, but osv-scanner reported no licence data for any of "
          + "\($asked | length) packages deps.dev covers. Its deps.dev lookup failed (re-run the scan), "
          + "the scan ran without --licenses, or every package is excused with license.ignore "
          + "(then set licenses_allowlist: none).")
      else . end ) as $_
| ($hits | group_by(.id) | map(vuln_rule(.))) as $vuln_rules
| ($vuln_rules
   + (if ($deprecated | length) > 0 then [deprecated_rule] else [] end)
   + (if ($licence | length) > 0 then licence_rules($licences) else [] end)) as $rules
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
      results: ( [ $hits[] | vuln_result ] + $deprecated + $licence
                 | map( (.ruleId) as $id
                      | if .properties.severity != null then .
                        elif $cvss[$id] != null then .properties.severity = ($cvss[$id] | band)
                        else . end ) )
    }] }
