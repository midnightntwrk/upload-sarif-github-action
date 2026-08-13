#!/usr/bin/env python3
"""Merge a scanned repo's .checkov.yml onto the action's defaults.

    merge-checkov-config.py <defaults.yml> <consumer.yml> [> merged.yml]

The split is transport vs policy.

The action owns transport - where findings go and that a finding never aborts
the run. `soft-fail` matters most: the severity gate downstream decides pass or
fail, so a repo flipping it would kill the scan job before the other scanners
had reported, turning "I have a finding" into "the build broke". `output` is
load-bearing for the same reason (the Earthfile saves a SARIF artifact by
name), and `download-external-modules` is a network control that is not a
consumer's to relax. Those three are pinned; everything else scalar is the
repo's to set.

The repo owns policy - which checks and which paths apply to its own tree.
Turning every rule off is a legitimate thing for a repo to do; the PR review
that lands the .checkov.yml is the control on that, not this script.

List-valued keys union rather than replace, so the action's entries survive a
repo that sets the same key - notably `skip-framework: [secrets]`, since
secrets are gitleaks' job (it honours the repo's own .gitleaks.toml, which
checkov has no equivalent of).

Output is YAML, same as both inputs. Keys are sorted and flow style is off, so
the same two inputs always produce a byte-identical file. It carries no
comments: the reasoning lives in the action's own .checkov.yml, which is the
file a human edits.
"""

import sys

import yaml

# Transport. A consumer value for these is dropped, not merged.
PINNED = ("output", "soft-fail", "download-external-modules")


def load(path, *, required):
    """Parse a YAML mapping, or return {} when it is absent or empty."""
    try:
        with open(path, encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        if required:
            sys.exit(f"merge-checkov-config: no such config file: {path}")
        return {}

    try:
        parsed = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        sys.exit(f"merge-checkov-config: {path} is not valid .checkov.yml: {exc}")

    if parsed is None:
        return {}
    if not isinstance(parsed, dict):
        sys.exit(
            f"merge-checkov-config: {path} must be a .checkov.yml mapping of "
            f"setting to value, found {type(parsed).__name__}"
        )
    return parsed


def merge(defaults, consumer):
    merged = dict(defaults)
    for key, value in consumer.items():
        if key in PINNED:
            continue
        base = merged.get(key)
        if isinstance(base, list) and isinstance(value, list):
            # dict.fromkeys de-duplicates while keeping first-seen order, so the
            # same two inputs always produce the same file.
            merged[key] = list(dict.fromkeys(base + value))
        else:
            merged[key] = value
    return merged


def main(argv):
    if len(argv) != 3:
        sys.exit(f"usage: {argv[0]} <defaults.yml> <consumer.yml>")
    defaults = load(argv[1], required=True)
    consumer = load(argv[2], required=False)
    yaml.safe_dump(
        merge(defaults, consumer),
        sys.stdout,
        default_flow_style=False,
        sort_keys=True,
    )


if __name__ == "__main__":
    main(sys.argv)
