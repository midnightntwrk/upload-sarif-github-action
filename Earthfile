VERSION 0.8

user-source:
    LOCALLY
    SAVE ARTIFACT . /src

scan:
    LOCALLY
    BUILD +opengrep
    BUILD +scorecard
    BUILD +checkov

opengrep:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c
    RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
    WORKDIR /src

    # renovate: datasource=github-releases packageName=opengrep/opengrep
    ARG OPENGREP_VERSION=v1.16.5
    ARG TARGETARCH
    RUN if [ "$TARGETARCH" = "arm64" ]; then \
            DIST="opengrep_manylinux_aarch64"; \
            HASH="6b9efb7b82dbd947be472ef9623bb55c920c447a03010f2d7a1db3a9e5f96024"; \
        else \
            DIST="opengrep_manylinux_x86"; \
            HASH="feb9983a339b0f8ed4d38979e75a3d5828d3a44993f5db9d1ad9c3bacb328d57"; \
        fi && \
        curl -fsSL --retry 3 --retry-delay 5 -o /usr/local/bin/opengrep \
            "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${DIST}" && \
        echo "${HASH}  /usr/local/bin/opengrep" | sha256sum -c --strict && \
        chmod 0755 /usr/local/bin/opengrep

    RUN useradd -m -r -s /usr/sbin/nologin scanner
    COPY +user-source/src /src
    RUN mkdir -p /output && chown -R scanner:scanner /output /src /home/scanner
    USER scanner

    RUN opengrep scan --config auto --taint-intrafile --dataflow-traces --sarif-output=/output/opengrep.sarif \
        || true

    SAVE ARTIFACT /output/opengrep.sarif AS LOCAL scan_reports/opengrep.sarif

scorecard:
    # renovate: datasource=docker packageName=ubuntu
    FROM ubuntu:24.04@sha256:186072bba1b2f436cbb91ef2567abca677337cfc786c86e107d25b7072feef0c
    RUN apt-get update && apt-get install -y --no-install-recommends curl ca-certificates jq git && rm -rf /var/lib/apt/lists/*
    WORKDIR /src

    # renovate: datasource=github-releases packageName=ossf/scorecard
    ARG SCORECARD_VERSION=5.4.0
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
        scorecard --local . --format json --output /output/scorecard-results.json \
            --checks "Vulnerabilities,Binary-Artifacts,Dangerous-Workflow,Security-Policy,License,Pinned-Dependencies,Token-Permissions" \
        || true

    RUN jq -f /scripts/scorecard.jq /output/scorecard-results.json > /output/scorecard-results.sarif

    SAVE ARTIFACT /output/scorecard-results.sarif AS LOCAL scan_reports/scorecard-results.sarif

checkov-requirements:
    # renovate: datasource=docker packageName=python
    FROM python:3.13-slim@sha256:739e7213785e88c0f702dcdc12c0973afcbd606dbf021a589cab77d6b00b579d
    RUN pip install --no-cache-dir pip-tools
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
