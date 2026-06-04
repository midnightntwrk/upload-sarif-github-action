VERSION 0.8

user-source:
    LOCALLY
    SAVE ARTIFACT . /src

scan:
    LOCALLY
    ARG SCORECARD_CHECKS
    BUILD +opengrep
    BUILD +scorecard --SCORECARD_CHECKS="$SCORECARD_CHECKS"
    BUILD +checkov
    BUILD +zizmor

opengrep-bin:
    # Tiny downloader stage; hash check is the trust anchor.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.20.0@sha256:b3f1fb2a51d923260350d21b8654bbc607164a987e2f7c84a0ac199a67df812a

    # renovate: datasource=github-releases packageName=opengrep/opengrep
    ARG OPENGREP_VERSION=v1.16.5
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="opengrep_manylinux_aarch64"; \
            HASH="6b9efb7b82dbd947be472ef9623bb55c920c447a03010f2d7a1db3a9e5f96024"; \
        else \
            DIST="opengrep_manylinux_x86"; \
            HASH="feb9983a339b0f8ed4d38979e75a3d5828d3a44993f5db9d1ad9c3bacb328d57"; \
        fi && \
        curl -kfsSL --retry 3 --retry-delay 5 -o opengrep \
            "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${DIST}" && \
        echo "${HASH}  opengrep" | sha256sum -c
    SAVE ARTIFACT /tmp/opengrep /opengrep

opengrep:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c
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
    FROM ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c
    RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates jq git && rm -rf /var/lib/apt/lists/*
    WORKDIR /src

    # renovate: datasource=github-releases packageName=ossf/scorecard
    ARG SCORECARD_VERSION=5.4.0
    ARG SCORECARD_CHECKS
    ARG TARGETARCH
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            ARCH="arm64"; \
            HASH="3f8b6354c62ec0287a8e9694481d834e16bff8451cf5b5dca435e8400ce5adaf"; \
        else \
            ARCH="amd64"; \
            HASH="e5183aeaa5aa548fbb7318a6deb3e1038be0ef9aca24e655422ae88dfbe67502"; \
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

checkov-requirements:
    # renovate: datasource=docker packageName=python
    FROM python:3.13-slim@sha256:739e7213785e88c0f702dcdc12c0973afcbd606dbf021a589cab77d6b00b579d
    # renovate: datasource=pypi packageName=pip-tools
    ARG PIP_TOOLS_VERSION=7.4.1
    RUN pip install --no-cache-dir --require-hashes --no-deps pip-tools==${PIP_TOOLS_VERSION} \
        --hash=sha256:4c690e5fbae2f21e87843e89c26191f0d9454f362d8acdbd695716493ec8b3a9
    # renovate: datasource=pypi packageName=checkov
    ARG CHECKOV_VERSION=3.2.510
    RUN echo "checkov==${CHECKOV_VERSION}" > /tmp/requirements.in && \
        pip-compile --generate-hashes --strip-extras --output-file=/tmp/requirements.txt /tmp/requirements.in
    SAVE ARTIFACT /tmp/requirements.txt AS LOCAL requirements.txt

checkov:
    # renovate: datasource=docker packageName=python
    FROM python:3.13-slim@sha256:739e7213785e88c0f702dcdc12c0973afcbd606dbf021a589cab77d6b00b579d
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

zizmor-bin:
    # Tiny downloader stage so the runtime image stays apt-free.
    # Hash check is the trust anchor; TLS validation is redundant
    # (curl -k), and zizmor itself runs --offline at scan time.
    # renovate: datasource=docker packageName=curlimages/curl
    FROM curlimages/curl:8.20.0@sha256:b3f1fb2a51d923260350d21b8654bbc607164a987e2f7c84a0ac199a67df812a

    # renovate: datasource=github-releases packageName=zizmorcore/zizmor
    ARG ZIZMOR_VERSION=v1.24.1
    ARG TARGETARCH
    WORKDIR /tmp
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="zizmor-aarch64-unknown-linux-gnu.tar.gz"; \
            HASH="d66e37ef8a375fb07939c630ebf9709a6e0f20242bdc3faf672a7ed97e0b768d"; \
        else \
            DIST="zizmor-x86_64-unknown-linux-gnu.tar.gz"; \
            HASH="a8000f3c683319a523d3b20df0e75457ba591f049cfcbfa98966631b56733c03"; \
        fi && \
        curl -kfsSL --retry 3 --retry-delay 5 -o zizmor.tar.gz \
            "https://github.com/zizmorcore/zizmor/releases/download/${ZIZMOR_VERSION}/${DIST}" && \
        echo "${HASH}  zizmor.tar.gz" | sha256sum -c && \
        tar -xf zizmor.tar.gz zizmor && \
        rm zizmor.tar.gz
    SAVE ARTIFACT /tmp/zizmor /zizmor

zizmor:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c
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
