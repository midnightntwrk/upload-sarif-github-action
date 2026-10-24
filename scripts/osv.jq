# osv-scanner JSON -> SARIF, with the gate's severities stamped on.
#
#   jq -L scripts -f osv.jq [--slurpfile packages cargo-lock-packages.json] \
#       [--arg version 2.7.0] [--arg licenses "MIT,Apache-2.0,..."] osv.json
#
# Why not osv-scanner's own `--format sarif`: it drops a deprecated package that
# has no vulnerability (google/osv-scanner#3164), and a yanked crate with no
# advisory is exactly the case worth reporting. Its JSON report keeps every
# package, with everything the SARIF writer used - advisory groups with a
# numeric `max_severity`, aliases, summaries, details, fixed ranges - so one
# scan produces one JSON and this file produces the SARIF. The licence report,
# when it comes, is in the same JSON.
#
# Shape follows upstream's SARIF so existing code-scanning alerts keep their
# identity: one rule per advisory group, named by its display id (CVE before
# an ecosystem id before GHSA, lexical within a class - identifiers.IDSortFunc);
# one result per package per lockfile, at the lockfile with no line (osv gives
# none) - upstream emits that result once per matched id, so a RUSTSEC+GHSA
# pair appears twice there and once here; the message `Package 'name@version' is vulnerable to 'ID' (also known
# as ...)`. Paths come out as /src/... because the scan runs in the
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
#               Cargo.lock index says came from git is skipped: deps.dev
#               matches on name and version alone, so a fork is "yanked"
#               whenever crates.io yanked the same release.
#   licences    with --arg licenses (an SPDX allowlist, or `default` for
#               scripts/license-allowlist.txt passed as --rawfile
#               default_licenses; "" or "none" turns this off) every
#               package's expressions, as deps.dev reports
#               them under --licenses --all-packages, go through spdx.jq.
#               One that fails is a `license-violation`, HIGH; one deps.dev
#               could not tell (UNKNOWN, non-standard, nothing) is a
#               `license-unknown`, LOW, and only for a package from a public
#               registry - deps.dev knows nothing of a workspace member, a
#               git dependency or a local npm package. Dev and optional
#               packages are skipped: nobody ships them.
#   neither     no score on the rule: the plain `warning` reading applies.

include "spdx";

def band:
    if   . >= 9 then "CRITICAL"
    elif . >= 7 then "HIGH"
    elif . >= 4 then "MEDIUM"
    else "LOW" end;

def relpath: sub("^(file://)?/src/"; "");

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
      | (.source.path // "" | relpath) as $path
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
          path: $path, name: $pkg.name, version: $pkg.version, ecosystem: $pkg.ecosystem,
          vulns: $mine } ];

def vuln_rule($group):
    ($group[0]) as $h
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
      + (if $h.max != null then {properties: {"security-severity": $h.max}} else {} end);

def vuln_result:
    { ruleId: .id, level: "warning",
      message: {text: ("Package '\(.name)@\(.version)' is vulnerable to '\(.id)'"
          + (if (.aliases | length) > 1
             then " (also known as '\(.aliases[1:] | join("', '"))')" else "" end) + ".")},
      locations: [{physicalLocation: {artifactLocation: {uri: .path}}}] }
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

def deprecated_results($packages):
    ( $packages | map({key: "\(.path)|\(.name)|\(.version)", value: .}) | from_entries ) as $index
    | [ (.results // [])[]
        | (.source.path // "" | relpath) as $path
        | (.packages // [])[] | .package | select(.deprecated == true)
        | $index["\($path)|\(.name)|\(.version)"] as $known
        | select(($known.source // "") != "git")
        | { ruleId: "deprecated-package", level: "warning",
            message: {text: ("Package '\(.name)@\(.version)' (\(.ecosystem)) is "
                + "\(.ecosystem | registry_word) upstream: the registry no longer serves "
                + "this version. Update to one that is still published.")},
            locations: [{physicalLocation: {
                artifactLocation: {uri: $path},
                region: {startLine: ($known.line // 1)}}}] } ];

# --- licences -----------------------------------------------------------------

def dev_or_optional: (.dependency_groups // []) | any(. == "dev" or . == "optional");

# deps.dev's "could not tell", as a whole-expression placeholder.
def licence_unknown: length == 0 or any(.[]; ascii_downcase | . == "unknown" or . == "non-standard");

def licence_rules($list):
    ($list | split(",") | map(gsub("^\\s+|\\s+$"; "") | select(length > 0)) | join(", ")) as $shown
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

def licence_results($list; $packages):
    if $list == "" or $list == "none" then [] else
    ($list | allowlist) as $al
    | ( $packages | map({key: "\(.path)|\(.name)|\(.version)", value: .}) | from_entries ) as $index
    | [ (.results // [])[]
        | (.source.path // "" | relpath) as $path
        | (.packages // [])[] | select(dev_or_optional | not)
        | .package as $pk | (.licenses // []) as $lic
        | $index["\($path)|\($pk.name)|\($pk.version)"] as $known
        # Unindexed crates (no Cargo.lock index given) count as registry.
        | (if $pk.ecosystem == "crates.io" then ($known.source // "registry") == "registry"
           else $pk.ecosystem != "GIT" and (($pk.purl // "") | test("source=LOCAL") | not) end) as $registry
        | { ruleId: null, level: null, properties: {},
            locations: [{physicalLocation: {artifactLocation: {uri: $path},
                                            region: {startLine: ($known.line // 1)}}}] }
          + ( if ($lic | licence_unknown) then
                  if $registry then
                      { ruleId: "license-unknown", level: "note", properties: {severity: "LOW"},
                        message: {text: ("Package '\($pk.name)@\($pk.version)' (\($pk.ecosystem)): "
                            + "deps.dev reports no usable licence (\($lic | join(", ") | if . == "" then "none" else . end)). "
                            + "Check the package's own LICENSE and record it in osv-scanner.toml.")} }
                  else empty end
              elif ($lic | package_allowed($al)) then empty
              else
                  { ruleId: "license-violation", level: "error", properties: {severity: "HIGH"},
                    message: {text: ("Package '\($pk.name)@\($pk.version)' (\($pk.ecosystem)) is licensed "
                        + "'\($lic | join("; "))', which the allowlist does not permit.")} }
              end ) ]
    end;

# --- assemble -----------------------------------------------------------------

($ARGS.named.packages // [] | .[0] // []) as $packages
| ($ARGS.named.licenses // ""
   | if . == "default" then
         ($ARGS.named.default_licenses // "" | split("\n")
          | map(sub("#.*"; "") | gsub("^\\s+|\\s+$"; "") | select(length > 0)) | join(","))
     else . end) as $licences
| hits as $hits
| deprecated_results($packages) as $deprecated
| licence_results($licences; $packages) as $licence
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
