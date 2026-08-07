#!/usr/bin/env bash
# Recompute the sha256 literals that sit next to the version pins.
#
# Renovate can bump `ARG TRIVY_VERSION=0.72.0` but has no idea the line below it
# carries a hash of the 0.72.0 tarball, so its PRs land red at `sha256sum -c`.
# Run this on the Renovate branch and commit the result.
#
# Reads each version straight out of the pinned file, so it can only ever
# re-derive hashes for versions someone already chose - it never bumps.
set -euo pipefail

cd "$(dirname "$0")/.."

sha256() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
    else shasum -a 256 "$1" | cut -d' ' -f1
    fi
}

# file | ARG name | url template ... ; {V} is the pinned version. Hashes are
# rewritten in the order the URLs are listed, matching source order in the file.
TARGETS=(
  "Earthfile|BATS_VERSION|https://github.com/bats-core/bats-core/archive/refs/tags/{V}.tar.gz"
  "Earthfile|OPENGREP_VERSION|https://github.com/opengrep/opengrep/releases/download/{V}/opengrep_manylinux_aarch64|https://github.com/opengrep/opengrep/releases/download/{V}/opengrep_manylinux_x86"
  "Earthfile|SCORECARD_VERSION|https://github.com/ossf/scorecard/releases/download/v{V}/scorecard_{V}_linux_arm64.tar.gz|https://github.com/ossf/scorecard/releases/download/v{V}/scorecard_{V}_linux_amd64.tar.gz"
  "Earthfile|TRIVY_VERSION|https://github.com/aquasecurity/trivy/releases/download/v{V}/trivy_{V}_Linux-ARM64.tar.gz|https://github.com/aquasecurity/trivy/releases/download/v{V}/trivy_{V}_Linux-64bit.tar.gz"
  "Earthfile|GITLEAKS_VERSION|https://github.com/gitleaks/gitleaks/releases/download/v{V}/gitleaks_{V}_linux_arm64.tar.gz|https://github.com/gitleaks/gitleaks/releases/download/v{V}/gitleaks_{V}_linux_x64.tar.gz"
  "Earthfile|ZIZMOR_VERSION|https://github.com/zizmorcore/zizmor/releases/download/{V}/zizmor-aarch64-unknown-linux-gnu.tar.gz|https://github.com/zizmorcore/zizmor/releases/download/{V}/zizmor-x86_64-unknown-linux-gnu.tar.gz"
  "action.yml|earthbuild_version|https://github.com/EarthBuild/earthbuild/releases/download/{V}/earth-linux-amd64"
)

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
changed=0

for target in "${TARGETS[@]}"; do
    IFS='|' read -r -a parts <<<"$target"
    file="${parts[0]}"
    arg="${parts[1]}"
    urls=("${parts[@]:2}")

    # ERE only: BSD sed has no \? in a BRE, so don't reach for sed -n here.
    version="$(grep -oE "${arg}=[\"']?[^\"' ]+" "$file" | head -1 | sed -e "s/^${arg}=//" -e "s/[\"']//g")"
    if [ -z "$version" ]; then
        echo "✗ ${file}: no pin named ${arg} - did the variable get renamed?" >&2
        exit 1
    fi

    # Existing hashes, in source order, from the pin line onwards. One per URL.
    mapfile -t old < <(
        awk -v pat="${arg}=" -v want="${#urls[@]}" '
            index($0, pat) { seen = 1 }
            seen && match($0, /[0-9a-f]{64}/) {
                print substr($0, RSTART, 64)
                if (++n == want) exit
            }' "$file"
    )
    if [ "${#old[@]}" -ne "${#urls[@]}" ]; then
        echo "✗ ${file}: found ${#old[@]} sha256 literal(s) after ${arg}, expected ${#urls[@]}." >&2
        echo "  The script pairs hashes with URLs by source order; that pairing has drifted." >&2
        exit 1
    fi

    for i in "${!urls[@]}"; do
        url="${urls[$i]//\{V\}/$version}"
        curl -fsSL --retry 3 --retry-delay 5 -o "$work/dl" "$url"
        new="$(sha256 "$work/dl")"
        if [ "$new" = "${old[$i]}" ]; then
            printf '  ok   %-20s %s\n' "$arg" "$url"
            continue
        fi
        printf '  bump %-20s %s\n     %s -> %s\n' "$arg" "$url" "${old[$i]}" "$new"
        # Hashes are 64 hex chars, so a plain substitution cannot collide.
        sed -i.bak "s/${old[$i]}/${new}/g" "$file" && rm -f "${file}.bak"
        changed=1
    done
done

if [ "$changed" -eq 0 ]; then
    echo "◈ all hashes already match their pinned versions"
else
    echo "◈ hashes refreshed - review the diff, then rebuild before committing"
fi
