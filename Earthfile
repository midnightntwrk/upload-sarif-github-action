VERSION 0.8

# Directory whose contents get scanned. LOCALLY runs in the Earthfile's own
# directory (this action's checkout), NOT the caller's cwd — so when consumers
# invoke us via "$GITHUB_ACTION_PATH+scan" this must be set to the caller's
# workspace or the scanners see this action's source instead of the consumer
# repo. Defaults to "." (this directory) for self-scans and local dev.
ARG --global USER_SOURCE_DIR=.

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

bats-bin:
    # Hash-pinned like every other tool here; the tarball is the trust anchor.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13
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
    RUN for i in 1 2 3 4 5; do apt-get -o Acquire::Retries=3 update && break || { echo "apt-get update failed (attempt $i/5), retrying in 15s..."; sleep 15; }; done \
        && apt-get install -y --no-install-recommends jq git && rm -rf /var/lib/apt/lists/*
    COPY +bats-bin/bats /opt/bats
    WORKDIR /work
    COPY scripts /work/scripts
    COPY tests /work/tests
    # A test input, not documentation: the suite asserts that the anchor printed
    # in a build failure resolves to a heading that actually exists.
    COPY README.md /work/README.md
    RUN /opt/bats/bin/bats --print-output-on-failure tests/

opengrep-bin:
    # Tiny downloader stage; hash check is the trust anchor.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13

    # renovate: datasource=github-releases packageName=opengrep/opengrep
    ARG OPENGREP_VERSION=v1.26.0
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="opengrep_manylinux_aarch64"; \
            HASH="3042a3b1aa98fa93407b9d66a45ab1f179b5b367e76965f56afdbd2c038fb1fa"; \
        else \
            DIST="opengrep_manylinux_x86"; \
            HASH="40c21299eeddabf743b856daa843d24f9d4a027130671cd45b3b21776fd9ab26"; \
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

scorecard:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:561618e2c15bf2397621dd04f96926663a3b5616c189cf7e38db7e82f5c538ea
    # Retry apt-get update: the Ubuntu mirrors intermittently serve a
    # mid-sync package index ("File has unexpected size ... Mirror sync in
    # progress?"), which fails the whole build (exit 100). Acquire::Retries
    # re-fetches individual files within an attempt; the loop rides out a
    # mirror-sync window across attempts.
    RUN for i in 1 2 3 4 5; do apt-get -o Acquire::Retries=3 update && break || { echo "apt-get update failed (attempt $i/5), retrying in 15s..."; sleep 15; }; done \
        && apt-get install -y --no-install-recommends curl ca-certificates jq git && rm -rf /var/lib/apt/lists/*
    WORKDIR /src

    # renovate: datasource=github-releases packageName=ossf/scorecard
    ARG SCORECARD_VERSION=5.5.0
    ARG SCORECARD_CHECKS
    ARG TARGETARCH
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            ARCH="arm64"; \
            HASH="3ce59d20c1d53e540c4a14e0da1e0d96b3b294e8ddc96a3c5a7b8a637b32991e"; \
        else \
            ARCH="amd64"; \
            HASH="83b90a05c1540ef1390db1cd5711e5fd04be9c1d8537fb84d39d02092d6a8dff"; \
        fi && \
        curl -fsSL --retry 3 --retry-delay 5 -o /tmp/scorecard.tar.gz \
            "https://github.com/ossf/scorecard/releases/download/v${SCORECARD_VERSION}/scorecard_${SCORECARD_VERSION}_linux_${ARCH}.tar.gz" && \
        echo "${HASH}  /tmp/scorecard.tar.gz" | sha256sum -c --strict && \
        tar -xf /tmp/scorecard.tar.gz -C /usr/local/bin scorecard && \
        chmod 0755 /usr/local/bin/scorecard && \
        rm /tmp/scorecard.tar.gz

    RUN useradd -r -s /usr/sbin/nologin scanner
    COPY +user-source/src /src
    COPY scripts/scorecard.jq /scripts/scorecard.jq
    RUN mkdir -p /output && chown scanner:scanner /output /src
    USER scanner

    RUN mkdir -p /output && \
        CHECKS_ARG="" && \
        if [ -n "$SCORECARD_CHECKS" ]; then \
            CHECKS_ARG="--checks $SCORECARD_CHECKS"; \
        fi && \
        scorecard --local . --format json --output /output/scorecard-results.json $CHECKS_ARG; \
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
    ARG PIP_TOOLS_VERSION=7.6.0
    RUN pip install --no-cache-dir pip-tools==${PIP_TOOLS_VERSION}
    # --allow-unsafe pins pip and setuptools too: python:3.13-slim no longer
    # ships setuptools, so without it the closure is short a package.
    # pip is constrained to the base image's own version rather than resolved:
    # pip-tools reaches into pip internals and 7.6.0 dies on pip 26.2
    # (make_requirement_preparer() gained a required allow_editables kwarg).
    RUN printf 'pip-tools==%s\npip==%s\n' \
            "${PIP_TOOLS_VERSION}" "$(pip --version | awk '{print $2}')" > /tmp/pip-tools.in && \
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
    # Held below 3.2.532, which is where checkov started capping aiohttp at
    # <3.14.0. Every fix for aiohttp's 14 open CVEs landed in 3.14.x and none
    # was backported, so accepting that cap pins a security scanner to a dead
    # dependency line - trivy and scorecard both flag it. Lift the cap when
    # checkov widens the constraint; +checkov-requirements will then resolve.
    # renovate: datasource=pypi packageName=checkov
    ARG CHECKOV_VERSION=3.2.531
    # Force the transitive GitPython up off 3.1.50 (HIGH CVEs GHSA-rwj8-pgh3-r573,
    # GHSA-2f96-g7mh-g2hx, GHSA-956x-8gvw-wg5v, GHSA-v396-v7q4-x2qj; fixed in 3.1.52).
    RUN printf 'checkov==%s\ngitpython>=3.1.52\n' "${CHECKOV_VERSION}" > /tmp/requirements.in && \
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
    COPY .checkov.yml /src/.checkov.yml
    RUN mkdir -p /output && chown scanner:scanner /output /src
    USER scanner

    RUN mkdir -p /output && \
        checkov -d /src \
            --config-file /src/.checkov.yml \
            --output-file-path /output \
            --skip-download

    SAVE ARTIFACT /output/results_sarif.sarif AS LOCAL scan_reports/checkov.sarif

trivy-bin:
    # Tiny downloader stage; hash check is the trust anchor.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13

    # renovate: datasource=github-releases packageName=aquasecurity/trivy
    ARG TRIVY_VERSION=0.73.0
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="trivy_${TRIVY_VERSION}_Linux-ARM64.tar.gz"; \
            HASH="13833d97e8a1a5367471c372a173180157f593bece570e20d5d925fef552f5dd"; \
        else \
            DIST="trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz"; \
            HASH="2edd39da482bb4e9831962487b68f68e3928ec3137794757f54d00383d79547b"; \
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
    # ca-certificates: trivy (Go) uses the system cert pool for TLS to
    # ghcr.io when fetching the vulnerability DB at scan time.
    # Retry apt-get update (see the scorecard target) — rides out a mirror sync.
    RUN for i in 1 2 3 4 5; do apt-get -o Acquire::Retries=3 update && break || { echo "apt-get update failed (attempt $i/5), retrying in 15s..."; sleep 15; }; done \
        && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
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
    RUN trivy fs --scanners vuln --format sarif --output /output/trivy.sarif /src

    SAVE ARTIFACT /output/trivy.sarif AS LOCAL scan_reports/trivy.sarif

gitleaks-bin:
    # Tiny downloader stage; hash check is the trust anchor.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13

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

    RUN for i in 1 2 3 4 5; do apt-get -o Acquire::Retries=3 update && break || { echo "apt-get update failed (attempt $i/5), retrying in 15s..."; sleep 15; }; done \
        && apt-get install -y --no-install-recommends jq && rm -rf /var/lib/apt/lists/*

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
    FROM curlimages/curl:8.21.0@sha256:7c12af72ceb38b7432ab85e1a265cff6ae58e06f95539d539b654f2cfa64bb13

    # renovate: datasource=github-releases packageName=zizmorcore/zizmor
    ARG ZIZMOR_VERSION=v1.29.0
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="zizmor-aarch64-unknown-linux-gnu.tar.gz"; \
            HASH="415eaa7c0a06479a701b8e44a3e812c1047decc848ec4bede7bd6bbf49f22d20"; \
        else \
            DIST="zizmor-x86_64-unknown-linux-gnu.tar.gz"; \
            HASH="dd96df044a6e8538d5f423790f453bdd03d49e5b2bcc38214acc41a2f1297839"; \
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

    COPY +zizmor-bin/zizmor /usr/local/bin/zizmor
    RUN chmod 0755 /usr/local/bin/zizmor

    RUN useradd -m -r -s /usr/sbin/nologin scanner
    COPY +user-source/src /src
    RUN mkdir -p /output && chown -R scanner:scanner /output /src /home/scanner
    USER scanner

    # Offline mode: keeps scanner off the runner's GITHUB_TOKEN.
    # --format=sarif suppresses zizmor's finding-severity exit codes (11+),
    # so non-zero indicates a real error.
    # Empty-SARIF fallback covers repos with no workflows/composite action.
    RUN set -e; \
        if [ -d /src/.github/workflows ] || [ -f /src/action.yml ] || [ -f /src/action.yaml ] || [ -f /src/.github/dependabot.yml ] || [ -f /src/.github/dependabot.yaml ]; then \
            zizmor --offline --format=sarif /src > /output/zizmor.sarif; \
        else \
            echo "No GitHub workflows, composite action or dependabot config found — emitting empty SARIF"; \
            printf '%s' '{"version":"2.1.0","$schema":"https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json","runs":[{"tool":{"driver":{"name":"zizmor","informationUri":"https://github.com/zizmorcore/zizmor"}},"results":[]}]}' > /output/zizmor.sarif; \
        fi

    SAVE ARTIFACT /output/zizmor.sarif AS LOCAL scan_reports/zizmor.sarif
