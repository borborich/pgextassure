# syntax=docker/dockerfile:1@sha256:87999aa3d42bdc6bea60565083ee17e86d1f3339802f543c0d03998580f9cb89

# Update only after independently verifying the replacement multi-arch digest.
ARG PYTHON_IMAGE=python:3.13-slim-bookworm@sha256:9d7f287598e1a5a978c015ee176d8216435aaf335ed69ac3c38dd1bbb10e8d64

FROM ${PYTHON_IMAGE} AS runtime

ARG VCS_REF=unknown

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore \
    PGEXTASSURE_STATE_DIR=/var/lib/pgextassure/private

LABEL org.opencontainers.image.title="PgExtAssure Admission Gateway" \
    org.opencontainers.image.description="Offline enterprise admission verifier for PostgreSQL extension evidence" \
    org.opencontainers.image.source="https://github.com/borborich/pgextassure" \
    org.opencontainers.image.licenses="Apache-2.0" \
    org.opencontainers.image.revision="${VCS_REF}"

RUN openssl version >/dev/null \
    && groupadd --gid 65532 pgextassure \
    && useradd \
        --uid 65532 \
        --gid 65532 \
        --no-create-home \
        --home-dir /nonexistent \
        --shell /usr/sbin/nologin \
        pgextassure \
    && install --directory --owner=65532 --group=65532 --mode=0700 \
        /var/lib/pgextassure \
    && install --directory --owner=65532 --group=65532 --mode=0755 \
        /opt/pgextassure

COPY . /opt/pgextassure/source

RUN python -m pip install \
        --no-cache-dir \
        --no-deps \
        /opt/pgextassure/source \
    && install \
        --owner=0 \
        --group=0 \
        --mode=0755 \
        /opt/pgextassure/source/docker/gateway-entrypoint.sh \
        /usr/local/bin/pgextassure-gateway-entrypoint \
    && rm -rf /opt/pgextassure/source

USER 65532:65532
WORKDIR /nonexistent

EXPOSE 8080
VOLUME ["/var/lib/pgextassure"]

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import os, urllib.request; port = os.environ.get('PGEXTASSURE_PORT', '8080'); urllib.request.urlopen(f'http://127.0.0.1:{port}/readyz', timeout=2).read()"]

ENTRYPOINT ["pgextassure-gateway-entrypoint"]
