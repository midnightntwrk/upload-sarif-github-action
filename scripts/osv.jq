# osv-scanner JSON -> SARIF, with the gate's severities stamped on.
#
#   jq -f osv.jq [--slurpfile packages cargo-lock-packages.json] [--arg version 2.7.0] osv.json
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
#               Cargo.lock index says did not come from crates.io (git, path,
#               another registry) is skipped: deps.dev matches on name and
#               version alone, so a fork is "yanked" whenever crates.io yanked
#               the same release.
#   neither     no score on the rule: the plain `warning` reading applies.

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
    ( $packages | group_by("\(.path)|\(.name)|\(.version)")
      | map({key: "\(.[0].path)|\(.[0].name)|\(.[0].version)", value: .}) | from_entries ) as $index
    | [ (.results // [])[]
        | (.source.path // "") as $raw | ($raw | location_uri) as $path
        | (.packages // [])[] | .package | select(.deprecated == true)
        | "\($path)|\(.name)|\(.version)" as $key
        | ($index[$key] // null) as $entries
        | select($entries == null or any($entries[]; .crates_io == true))
        | ($entries // [] | map(select(.crates_io == true)) | min_by(.line)) as $known
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

# --- assemble -----------------------------------------------------------------

hits as $hits
| deprecated_results($ARGS.named.packages // [] | .[0] // []) as $deprecated
| ($hits | group_by(.id) | map(vuln_rule(.))) as $vuln_rules
| ($vuln_rules + (if ($deprecated | length) > 0 then [deprecated_rule] else [] end)) as $rules
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
      results: ( [ $hits[] | vuln_result ] + $deprecated
                 | map( (.ruleId) as $id
                      | if .properties.severity != null then .
                        elif $cvss[$id] != null then .properties.severity = ($cvss[$id] | band)
                        else . end ) )
    }] }
