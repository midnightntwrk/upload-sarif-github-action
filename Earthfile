VERSION 0.8

# Directory whose contents get scanned. LOCALLY runs in the Earthfile's own
# directory (this action's checkout), NOT the caller's cwd — so when consumers
# invoke us via "$GITHUB_ACTION_PATH+scan" this must be set to the caller's
# workspace or the scanners see this action's source instead of the consumer
# repo. Defaults to "." (this directory) for self-scans and local dev.
ARG --global USER_SOURCE_DIR=.

# Update + install retried together, once: a mirror mid-sync fails either
# step (size mismatch at update, 404 at install), and one failure fails +scan.
APT_INSTALL:
    FUNCTION
    ARG --required PACKAGES
    RUN i() { apt-get -qq update && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends $PACKAGES; }; \
        { i || { sleep 15; i; }; } && rm -rf /var/lib/apt/lists/*

# Scanner images install nothing from apt: an apt install is whatever the
# mirror serves that day - unpinned, so not reproducible - and it was the
# slowest step in most targets (41s of scorecard's 53s on a CI runner). What
# they needed from it comes from pinned sources instead.

# The CA bundle from the digest-pinned curl image: Renovate bumps that digest,
# so the bundle refreshes with it. Go binaries (trivy, osv-scanner, scorecard)
# read this path for TLS.
ca-certs:
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777
    SAVE ARTIFACT /etc/ssl/certs/ca-certificates.crt

# Static jq, the same binary in every scanner image and in +test, so the
# severity ladder is tested on the jq that ships. 1.8.x carries GitHub build
# attestations (ci.yml at the release tag); 1.7.1 did not.
jq-bin:
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777
    # renovate: datasource=github-releases packageName=jqlang/jq extractVersion=^jq-(?<version>.+)$
    ARG JQ_VERSION=1.8.2
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="jq-linux-arm64"; \
            HASH="8b85c817833814ddca00a144c33705546355afccf0cf39b188f3cdb48b852309"; \
        else \
            DIST="jq-linux-amd64"; \
            HASH="b1c22172dd303f3be49e935aa56aa48a8b7a46e0bc838b4997d3bb451495870f"; \
        fi && \
        curl -fsSL --retry 3 --retry-delay 5 -o jq \
            "https://github.com/jqlang/jq/releases/download/jq-${JQ_VERSION}/${DIST}" && \
        echo "${HASH}  jq" | sha256sum -c && \
        chmod 0755 jq
    SAVE ARTIFACT /tmp/jq /jq

user-source:
    LOCALLY
    # Stage via tar so we can exclude scan noise (mirrors .earthlyignore) and
    # avoid recursive self-copy when USER_SOURCE_DIR is this directory.
    RUN rm -rf .user-src && mkdir .user-src && \
        tar -C "$USER_SOURCE_DIR" -cf - \
            --exclude='.user-src' --exclude='.git' --exclude='node_modules' \
            --exclude='dist' --exclude='build' --exclude='scan_reports' \
            --exclude='.env' --exclude='.env.*' . \
        | tar -C .user-src -xf -
    SAVE ARTIFACT .user-src /src

scan:
    LOCALLY
    ARG SCORECARD_CHECKS
    ARG SKIP_OPENGREP_SCAN=false
    ARG SKIP_SCORECARD_SCAN=false
    ARG SKIP_CHECKOV_SCAN=false
    ARG SKIP_ZIZMOR_SCAN=false
    ARG SKIP_TRIVY_SCAN=false
    ARG SKIP_GITLEAKS_SCAN=false
    ARG SKIP_OSV_SCAN=false
    IF [ "$SKIP_OPENGREP_SCAN" != "true" ]
        BUILD +opengrep
    END
    IF [ "$SKIP_SCORECARD_SCAN" != "true" ]
        BUILD +scorecard --SCORECARD_CHECKS="$SCORECARD_CHECKS"
    END
    IF [ "$SKIP_CHECKOV_SCAN" != "true" ]
        BUILD +checkov
    END
    IF [ "$SKIP_ZIZMOR_SCAN" != "true" ]
        BUILD +zizmor
    END
    IF [ "$SKIP_TRIVY_SCAN" != "true" ]
        BUILD +trivy
    END
    IF [ "$SKIP_GITLEAKS_SCAN" != "true" ]
        BUILD +gitleaks
    END
    IF [ "$SKIP_OSV_SCAN" != "true" ]
        BUILD +osv
    END

bats-bin:
    # Hash-pinned like every other tool here; the tarball is the trust anchor.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777
    # renovate: datasource=github-releases packageName=bats-core/bats-core
    ARG BATS_VERSION=v1.14.0
    WORKDIR /tmp
    RUN curl -fsSL --retry 3 --retry-delay 5 -o bats.tar.gz \
            "https://github.com/bats-core/bats-core/archive/refs/tags/${BATS_VERSION}.tar.gz" && \
        echo "bb537b70b15b732f6d8827dd6578e3d8ce166636ce1f18ea9a074184fcce9177  bats.tar.gz" \
            | sha256sum -c && \
        mkdir -p /tmp/bats && tar -xf bats.tar.gz -C /tmp/bats --strip-components=1
    SAVE ARTIFACT /tmp/bats /bats

test:
    # Unit tests for the gate scripts. No network, no scanners, no docker, so
    # `earth +test` is the whole suite bar the integration test. Hermetic, so the
    # jq and bats versions are pinned - the severity ladder lives in jq now.
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    DO +APT_INSTALL --PACKAGES="git python3 python3-yaml"
    COPY +jq-bin/jq /usr/local/bin/jq
    COPY +bats-bin/bats /opt/bats
    WORKDIR /work
    COPY scripts /work/scripts
    COPY tests /work/tests
    # The merge script reads the action's own defaults, so the suite asserts
    # against the file the checkov stage actually ships.
    COPY .checkov.yml /work/.checkov.yml
    # A test input, not documentation: the suite asserts that the anchor printed
    # in a build failure resolves to a heading that actually exists.
    COPY README.md /work/README.md
    RUN /opt/bats/bin/bats --print-output-on-failure tests/

opengrep-bin:
    # Tiny downloader stage; hash check is the trust anchor.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777

    # renovate: datasource=github-releases packageName=opengrep/opengrep
    ARG OPENGREP_VERSION=v1.32.0
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="opengrep_manylinux_aarch64"; \
            HASH="dc6229319c0d68948733053786a5614873947e5ec1d4669cc0e94ae9038cb99d"; \
        else \
            DIST="opengrep_manylinux_x86"; \
            HASH="7360d60174880bd9214f2dfbe439b7bce82b7a3d44cfe945ba833c85cc8bda75"; \
        fi && \
        curl -kfsSL --retry 3 --retry-delay 5 -o opengrep \
            "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${DIST}" && \
        echo "${HASH}  opengrep" | sha256sum -c
    SAVE ARTIFACT /tmp/opengrep /opengrep

opengrep:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    # No apt at runtime: opengrep is a PyInstaller bundle that ships its
    # own certifi, so it can validate TLS to the rule registry without
    # the system ca-certificates package.
    WORKDIR /src

    COPY +opengrep-bin/opengrep /usr/local/bin/opengrep
    RUN chmod 0755 /usr/local/bin/opengrep

    RUN useradd -m -r -s /usr/sbin/nologin scanner
    COPY +user-source/src /src
    RUN mkdir -p /output && chown -R scanner:scanner /output /src /home/scanner
    USER scanner

    RUN opengrep scan --config auto --taint-intrafile --dataflow-traces --sarif-output=/output/opengrep.sarif; \
        rc=$?; [ $rc -le 1 ] || exit $rc

    SAVE ARTIFACT /output/opengrep.sarif AS LOCAL scan_reports/opengrep.sarif

scorecard-bin:
    # Tiny downloader stage; hash check is the trust anchor.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777
    # renovate: datasource=github-releases packageName=ossf/scorecard
    ARG SCORECARD_VERSION=5.6.0
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            ARCH="arm64"; \
            HASH="3eacaceb3fdee6d0ba5df6ede45d1ada73321949029921bb63633802e8ec5951"; \
        else \
            ARCH="amd64"; \
            HASH="19bde07129450cb65a95c6e3b9f34e034341579e6f0e241546ec3ae6efb2dd9a"; \
        fi && \
        curl -fsSL --retry 3 --retry-delay 5 -o scorecard.tar.gz \
            "https://github.com/ossf/scorecard/releases/download/v${SCORECARD_VERSION}/scorecard_${SCORECARD_VERSION}_linux_${ARCH}.tar.gz" && \
        echo "${HASH}  scorecard.tar.gz" | sha256sum -c && \
        tar -xf scorecard.tar.gz scorecard && \
        rm scorecard.tar.gz
    SAVE ARTIFACT /tmp/scorecard /scorecard

scorecard:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    # CA bundle: the Vulnerabilities check queries api.osv.dev.
    COPY +ca-certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
    COPY +jq-bin/jq /usr/local/bin/jq
    COPY +scorecard-bin/scorecard /usr/local/bin/scorecard
    RUN chmod 0755 /usr/local/bin/scorecard
    WORKDIR /src

    ARG SCORECARD_CHECKS
    # `--checks` is an allowlist with no exclude counterpart, so declining one
    # means naming the rest. Everything scorecard answers from --local, less
    # SAST (this action is the analyser), Fuzzing (unobservable) and Packaging
    # (greps for known publish commands; a tag-only action release reads as a
    # miss). A check added upstream is opt-in. Named in the README too.
    ARG DEFAULT_CHECKS="Binary-Artifacts,Dangerous-Workflow,Dependency-Update-Tool,License,Pinned-Dependencies,Security-Policy,Token-Permissions,Vulnerabilities"

    RUN useradd -r -s /usr/sbin/nologin scanner
    COPY +user-source/src /src
    COPY scripts/scorecard.jq /scripts/scorecard.jq
    RUN mkdir -p /output && chown scanner:scanner /output /src
    USER scanner

    RUN mkdir -p /output && \
        scorecard --local . --format json --output /output/scorecard-results.json \
            --checks "${SCORECARD_CHECKS:-$DEFAULT_CHECKS}"; \
        rc=$?; [ $rc -le 1 ] || exit $rc

    RUN jq -f /scripts/scorecard.jq /output/scorecard-results.json > /output/scorecard-results.sarif

    SAVE ARTIFACT /output/scorecard-results.sarif AS LOCAL scan_reports/scorecard-results.sarif

pip-tools-requirements:
    # Bootstrap-the-bootstrap: the only unhashed pip install in this file, and it
    # never reaches a scanner image - its sole output is the hash-pinned closure
    # committed as pip-tools-requirements.txt, which is what +checkov-requirements
    # actually installs. Maintainer-run; review the diff before committing.
    # renovate: datasource=docker packageName=python
    FROM python:3.13-slim@sha256:bf503bb2243c5aad0aa951544dd60d165f992646441d35dea90893703fc26251
    # renovate: datasource=pypi packageName=pip-tools
    ARG PIP_TOOLS_VERSION=7.6.2
    RUN pip install --no-cache-dir pip-tools==${PIP_TOOLS_VERSION}
    # --allow-unsafe pins pip and setuptools too: python:3.13-slim no longer
    # ships setuptools, so without it the closure is short a package.
    # pip-tools reaches into pip internals, so a pip bump can break it (7.6.0
    # died on 26.2: make_requirement_preparer() gained a required
    # allow_editables kwarg). Bump pip-tools and pip together, then check that
    # +checkov-requirements still runs.
    RUN printf 'pip-tools==%s\n' "${PIP_TOOLS_VERSION}" > /tmp/pip-tools.in && \
        pip-compile --generate-hashes --strip-extras --allow-unsafe \
            --output-file=/tmp/pip-tools-requirements.txt /tmp/pip-tools.in
    SAVE ARTIFACT /tmp/pip-tools-requirements.txt AS LOCAL pip-tools-requirements.txt

checkov-requirements:
    # renovate: datasource=docker packageName=python
    FROM python:3.13-slim@sha256:bf503bb2243c5aad0aa951544dd60d165f992646441d35dea90893703fc26251
    # pip-tools needs its own deps (click, build, ...) to run at all, and
    # --require-hashes forbids resolving them on the fly - hence the committed
    # closure. Regenerate it with +pip-tools-requirements.
    COPY pip-tools-requirements.txt /tmp/pip-tools-requirements.txt
    RUN pip install --no-cache-dir --require-hashes -r /tmp/pip-tools-requirements.txt
    # Never take 3.2.532-3.3.9: they cap aiohttp at <3.14.0, and every fix for
    # aiohttp's 14 CVEs landed in 3.14.x only. 3.3.10 widened it to <3.15.0.
    # asteval is pinned ==1.0.6 by checkov itself, so its bumps (sandbox-escape
    # GHSAs fixed in 1.0.9) cannot land here until checkov moves that pin.
    # renovate: datasource=pypi packageName=checkov
    ARG CHECKOV_VERSION=3.3.30
    # Floor the transitive GitPython at its latest CVE fix (CVE-2026-114145,
    # fixed in 3.2.1), so a checkov cap fails the resolve instead of regressing.
    RUN printf 'checkov==%s\ngitpython>=3.2.1\n' "${CHECKOV_VERSION}" > /tmp/requirements.in && \
        pip-compile --generate-hashes --strip-extras --output-file=/tmp/requirements.txt /tmp/requirements.in
    SAVE ARTIFACT /tmp/requirements.txt AS LOCAL requirements.txt

checkov:
    # renovate: datasource=docker packageName=python
    FROM python:3.13-slim@sha256:bf503bb2243c5aad0aa951544dd60d165f992646441d35dea90893703fc26251
    WORKDIR /src

    COPY requirements.txt /tmp/requirements.txt
    RUN pip install --no-cache-dir --require-hashes -r /tmp/requirements.txt

    RUN useradd -r -s /usr/sbin/nologin scanner
    COPY +user-source/src /src
    # Defaults live outside /src: copying them to /src/.checkov.yml would
    # overwrite the scanned repo's own file, which is how a consumer ended up
    # with no way to suppress a false positive in a JSON file (no comment
    # syntax, so `# checkov:skip=` is unavailable there too).
    COPY .checkov.yml /action/checkov-defaults.yml
    COPY scripts/merge-checkov-config.py /action/merge-checkov-config.py
    RUN python3 /action/merge-checkov-config.py \
            /action/checkov-defaults.yml /src/.checkov.yml > /action/checkov.yml
    RUN mkdir -p /output && chown scanner:scanner /output /src
    USER scanner

    RUN mkdir -p /output && \
        checkov -d /src \
            --config-file /action/checkov.yml \
            --output-file-path /output \
            --skip-download

    SAVE ARTIFACT /output/results_sarif.sarif AS LOCAL scan_reports/checkov.sarif

trivy-bin:
    # Tiny downloader stage; hash check is the trust anchor.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777

    # renovate: datasource=github-releases packageName=aquasecurity/trivy
    ARG TRIVY_VERSION=0.76.1
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz"; \
            HASH="e174dff2a6dba5e3ae41f8d0537a6324405bd08132497340304c6b20e0f16a1f"; \
        else \
            DIST="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
            HASH="c7cbe3137fb8a48a17574bede3dd6beb16742d1e9772929940fc90082c39d9c0"; \
        fi && \
        curl -kfsSL --retry 3 --retry-delay 5 -o trivy.tar.gz \
            "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/${DIST}" && \
        echo "${HASH}  trivy.tar.gz" | sha256sum -c && \
        tar -xf trivy.tar.gz trivy && \
        rm trivy.tar.gz
    SAVE ARTIFACT /tmp/trivy /trivy

trivy:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    # CA bundle: trivy fetches its vulnerability DB over TLS at scan time.
    COPY +ca-certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
    WORKDIR /src

    COPY +trivy-bin/trivy /usr/local/bin/trivy
    RUN chmod 0755 /usr/local/bin/trivy

    RUN useradd -m -r -s /usr/sbin/nologin scanner
    COPY +user-source/src /src
    RUN mkdir -p /output && chown -R scanner:scanner /output /src /home/scanner
    USER scanner

    # vuln only: secrets are gitleaks' job, IaC misconfig is checkov's.
    # Without --exit-code trivy exits 0 on findings; non-zero is a real
    # error (e.g. DB fetch failure) and should fail the target.
    #
    # --no-progress, not --quiet: the DB download is a ~100 MiB carriage-return
    # progress bar, and earth turns every \r into a log line, so one fetch
    # becomes thousands. --quiet would also swallow the log lines that say which
    # DB version was used, which is the first thing you want when a finding
    # appears or vanishes between runs.
    RUN trivy fs --no-progress --scanners vuln --format sarif --output /output/trivy.sarif /src

    SAVE ARTIFACT /output/trivy.sarif AS LOCAL scan_reports/trivy.sarif

osv-bin:
    # Tiny downloader stage; hash check is the trust anchor. The release ships a
    # bare binary, no tarball.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777

    # renovate: datasource=github-releases packageName=google/osv-scanner
    ARG OSV_SCANNER_VERSION=v2.7.0
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="osv-scanner_linux_arm64"; \
            HASH="4061ef4c021ed3c47f203b818f337e351336cc5cd67c0274fc36bd1dfc728dd7"; \
        else \
            DIST="osv-scanner_linux_amd64"; \
            HASH="160c6253e2922e9e0a6a9771c5c4c40a4b3c6090b34a3cdd5e80c96cc2e4218b"; \
        fi && \
        curl -kfsSL --retry 3 --retry-delay 5 -o osv-scanner \
            "https://github.com/google/osv-scanner/releases/download/${OSV_SCANNER_VERSION}/${DIST}" && \
        echo "${HASH}  osv-scanner" | sha256sum -c
    SAVE ARTIFACT /tmp/osv-scanner /osv-scanner

osv:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    # CA bundle: osv-scanner queries api.osv.dev over TLS at scan time.
    COPY +ca-certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
    COPY +jq-bin/jq /usr/local/bin/jq
    WORKDIR /src

    COPY +osv-bin/osv-scanner /usr/local/bin/osv-scanner
    RUN chmod 0755 /usr/local/bin/osv-scanner

    RUN useradd -m -r -s /usr/sbin/nologin scanner
    COPY +user-source/src /src
    COPY scripts/osv.jq /scripts/osv.jq
    RUN mkdir -p /output && chown -R scanner:scanner /output /src /home/scanner
    USER scanner

    # Overlaps trivy on CVEs (different advisory sources); the reason it is here
    # is OSV's MAL-* malicious-packages feed, which trivy does not carry.
    #
    # --no-call-analysis=all: rust call analysis runs the scanned repo's build
    # scripts, i.e. untrusted code. Off explicitly, not by default.
    # --no-resolve: otherwise a bare `requests==2.32.5` has its transitive deps
    # guessed via deps.dev at scan time - not what pip installs, and not stable
    # run to run (it flagged a stale certifi the repo never pinned). Only what
    # the repo actually pins is scanned.
    # --allow-no-lockfiles: otherwise a repo with no manifests exits 128 and
    # writes no SARIF. Exit 1 = vulnerabilities found (gated downstream); any
    # other non-zero is a real error. A repo's osv-scanner.toml is honoured.
    RUN osv-scanner scan source -r --allow-no-lockfiles --no-resolve --no-call-analysis=all \
            --format sarif --output-file /output/osv-raw.sarif . ; \
        rc=$?; [ $rc -le 1 ] || exit $rc

    # Malware is CRITICAL, CVEs banded by CVSS - see scripts/osv.jq.
    RUN jq -f /scripts/osv.jq /output/osv-raw.sarif > /output/osv-scanner.sarif

    SAVE ARTIFACT /output/osv-scanner.sarif AS LOCAL scan_reports/osv-scanner.sarif

gitleaks-bin:
    # Tiny downloader stage; hash check is the trust anchor.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777

    # renovate: datasource=github-releases packageName=gitleaks/gitleaks
    ARG GITLEAKS_VERSION=8.30.1
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="gitleaks_${GITLEAKS_VERSION}_linux_arm64.tar.gz"; \
            HASH="e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080"; \
        else \
            DIST="gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz"; \
            HASH="551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb"; \
        fi && \
        curl -kfsSL --retry 3 --retry-delay 5 -o gitleaks.tar.gz \
            "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/${DIST}" && \
        echo "${HASH}  gitleaks.tar.gz" | sha256sum -c && \
        tar -xf gitleaks.tar.gz gitleaks && \
        rm gitleaks.tar.gz
    SAVE ARTIFACT /tmp/gitleaks /gitleaks

gitleaks:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    WORKDIR /src

    COPY +jq-bin/jq /usr/local/bin/jq

    COPY +gitleaks-bin/gitleaks /usr/local/bin/gitleaks
    RUN chmod 0755 /usr/local/bin/gitleaks

    RUN useradd -m -r -s /usr/sbin/nologin scanner
    COPY +user-source/src /src
    COPY scripts/secrets-severity.jq /scripts/secrets-severity.jq
    RUN mkdir -p /output && chown -R scanner:scanner /output /src /home/scanner
    USER scanner

    # `dir` mode scans the working tree — .earthlyignore strips .git so
    # history isn't available in-container (and CI checkouts are shallow
    # anyway). Exit 1 = leaks found (report, gate downstream via
    # fail-on-severity); >1 = real error.
    #
    # The target is `.`, not `/src`, and that is load-bearing three times over.
    # With an absolute target gitleaks does not pick up the repo's own
    # `.gitleaks.toml`, so path allowlists are silently ignored; reported paths
    # and `.gitleaksignore` fingerprints come out as `/src/...`, which no
    # contributor could guess; and the SARIF `uri` is an absolute container path,
    # which GitHub's Security tab cannot map back to a file in the repo.
    RUN gitleaks dir . --report-format sarif --report-path /output/gitleaks.sarif --no-banner; \
        rc=$?; [ $rc -le 1 ] || exit $rc

    # Secrets are critical by policy - see scripts/secrets-severity.jq.
    RUN jq -f /scripts/secrets-severity.jq /output/gitleaks.sarif > /output/stamped.sarif \
        && mv /output/stamped.sarif /output/gitleaks.sarif

    SAVE ARTIFACT /output/gitleaks.sarif AS LOCAL scan_reports/gitleaks.sarif

zizmor-bin:
    # Tiny downloader stage so the runtime image stays apt-free.
    # Hash check is the trust anchor; TLS validation is redundant
    # (curl -k), and zizmor itself runs --offline at scan time.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.22.0@sha256:58adaa4e8dca9c988bae2aba4ab3434a0bb2da16bbe3f92dec39ec7785166777

    # renovate: datasource=github-releases packageName=zizmorcore/zizmor
    ARG ZIZMOR_VERSION=v1.31.1
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="zizmor-aarch64-unknown-linux-gnu.tar.gz"; \
            HASH="37eebbd5762a44f262d94875431b14a6d2402991e90a685113ea97b8b41be833"; \
        else \
            DIST="zizmor-x86_64-unknown-linux-gnu.tar.gz"; \
            HASH="d185f726bdaf92df78273217dfdd24ebcd6b0ef48cf3ce776ff5762b6e138c99"; \
        fi && \
        curl -kfsSL --retry 3 --retry-delay 5 -o zizmor.tar.gz \
            "https://github.com/zizmorcore/zizmor/releases/download/${ZIZMOR_VERSION}/${DIST}" && \
        echo "${HASH}  zizmor.tar.gz" | sha256sum -c && \
        tar -xf zizmor.tar.gz zizmor && \
        rm zizmor.tar.gz
    SAVE ARTIFACT /tmp/zizmor /zizmor

zizmor:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    WORKDIR /src

    # CA bundle: online audits call api.github.com. Without it zizmor does not
    # error, it panics with a crash report and no message.
    COPY +ca-certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
    COPY +zizmor-bin/zizmor /usr/local/bin/zizmor
    RUN chmod 0755 /usr/local/bin/zizmor

    RUN useradd -m -r -s /usr/sbin/nologin scanner
    COPY +user-source/src /src
    RUN mkdir -p /output && chown -R scanner:scanner /output /src /home/scanner
    USER scanner

    # Online, always. known-vulnerable-actions, impostor-commit and
    # ref-confusion need the GitHub API, and nothing else here checks the
    # actions a workflow `uses:` - tj-actions/changed-files@v35 passes every
    # other scanner. The token is a secret, not an ARG: it reaches this RUN
    # only, is in no layer, and no other scanner sees it. A missing token is
    # an error, not a quiet --offline: that fallback is an opt-out nobody chose.
    # --format=sarif suppresses zizmor's finding-severity exit codes (11+),
    # so non-zero indicates a real error.
    # Empty-SARIF fallback covers repos with no workflows/composite action.
    RUN --secret GH_TOKEN set -e; \
        if [ -d /src/.github/workflows ] || [ -f /src/action.yml ] || [ -f /src/action.yaml ] || [ -f /src/.github/dependabot.yml ] || [ -f /src/.github/dependabot.yaml ]; then \
            if [ -z "${GH_TOKEN:-}" ]; then \
                echo "error: zizmor runs online and needs a GitHub token, but GH_TOKEN is empty." >&2; \
                echo "  In the action it is inputs.github_token, else github.token." >&2; \
                echo "  Locally: GH_TOKEN=\"\$(gh auth token)\" earth --secret GH_TOKEN +scan" >&2; \
                exit 2; \
            fi; \
            zizmor --format=sarif /src > /output/zizmor.sarif; \
        else \
            echo "No GitHub workflows, composite action or dependabot config found — emitting empty SARIF"; \
            printf '%s' '{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","runs":[{"tool":{"driver":{"name":"zizmor","informationUri":"https://github.com/zizmorcore/zizmor"}},"results":[]}]}' > /output/zizmor.sarif; \
        fi

    SAVE ARTIFACT /output/zizmor.sarif AS LOCAL scan_reports/zizmor.sarif
