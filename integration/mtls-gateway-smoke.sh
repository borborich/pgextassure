#!/bin/sh
set -eu

if [ "$#" -ne 1 ]; then
    echo "usage: mtls-gateway-smoke.sh GATEWAY_IMAGE" >&2
    exit 2
fi

gateway_image="$1"
envoy_image="envoyproxy/envoy@sha256:7877ad87afd7459e1bd2a077ff601fec7c93aeecd62e71664560d96328c62cf4"
temporary="$(mktemp -d)"
suffix="${GITHUB_RUN_ID:-local}-$$"
gateway_container="pgextassure-mtls-gateway-${suffix}"
envoy_container="pgextassure-mtls-envoy-${suffix}"
state_volume="pgextassure-mtls-state-${suffix}"
listen_port="${PGEXTASSURE_MTLS_SMOKE_PORT:-18443}"

cleanup() {
    docker rm --force "${envoy_container}" >/dev/null 2>&1 || true
    docker rm --force "${gateway_container}" >/dev/null 2>&1 || true
    docker volume rm "${state_volume}" >/dev/null 2>&1 || true
    rm -r -- "${temporary}"
}
trap cleanup EXIT INT TERM

openssl req -x509 -newkey rsa:3072 -nodes \
    -keyout "${temporary}/ca.key" \
    -out "${temporary}/ca.crt" \
    -days 1 \
    -subj "/CN=PgExtAssure smoke CA" >/dev/null 2>&1

openssl req -newkey rsa:3072 -nodes \
    -keyout "${temporary}/tls.key" \
    -out "${temporary}/server.csr" \
    -subj "/CN=localhost" >/dev/null 2>&1
printf '%s\n' \
    "subjectAltName=DNS:localhost" \
    "extendedKeyUsage=serverAuth" \
    > "${temporary}/server.ext"
openssl x509 -req \
    -in "${temporary}/server.csr" \
    -CA "${temporary}/ca.crt" \
    -CAkey "${temporary}/ca.key" \
    -CAcreateserial \
    -out "${temporary}/tls.crt" \
    -days 1 \
    -extfile "${temporary}/server.ext" >/dev/null 2>&1

openssl req -newkey rsa:3072 -nodes \
    -keyout "${temporary}/client.key" \
    -out "${temporary}/client.csr" \
    -subj "/CN=authorized-smoke-client" >/dev/null 2>&1
printf '%s\n' "extendedKeyUsage=clientAuth" > "${temporary}/client.ext"
openssl x509 -req \
    -in "${temporary}/client.csr" \
    -CA "${temporary}/ca.crt" \
    -CAkey "${temporary}/ca.key" \
    -CAcreateserial \
    -out "${temporary}/client.crt" \
    -days 1 \
    -extfile "${temporary}/client.ext" >/dev/null 2>&1

openssl req -x509 -newkey rsa:3072 -nodes \
    -keyout "${temporary}/rogue.key" \
    -out "${temporary}/rogue.crt" \
    -days 1 \
    -subj "/CN=untrusted-smoke-client" >/dev/null 2>&1

cp deploy/helm/pgextassure/files/envoy.yaml "${temporary}/envoy.yaml"
mkdir -m 0700 "${temporary}/envoy-certs"
cp \
    "${temporary}/ca.crt" \
    "${temporary}/tls.crt" \
    "${temporary}/tls.key" \
    "${temporary}/envoy-certs/"
chmod 0600 "${temporary}"/*.key
chmod 0600 "${temporary}/envoy-certs/tls.key"
chmod 0644 "${temporary}"/*.crt "${temporary}/envoy.yaml"
chmod 0644 \
    "${temporary}/envoy-certs/ca.crt" \
    "${temporary}/envoy-certs/tls.crt"

docker run --rm \
    --user "$(id -u):$(id -g)" \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --mount "type=bind,source=${temporary}/envoy.yaml,target=/etc/envoy/envoy.yaml,readonly" \
    --mount "type=bind,source=${temporary}/envoy-certs,target=/etc/pgextassure-mtls,readonly" \
    "${envoy_image}" \
    -c /etc/envoy/envoy.yaml \
    --mode validate \
    --disable-hot-restart >/dev/null

docker volume create "${state_volume}" >/dev/null
docker run \
    --detach \
    --name "${gateway_container}" \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=300m \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --env PGEXTASSURE_HOST=127.0.0.1 \
    --publish "127.0.0.1:${listen_port}:8443" \
    --mount "source=${state_volume},target=/var/lib/pgextassure" \
    "${gateway_image}" >/dev/null

docker run \
    --detach \
    --name "${envoy_container}" \
    --network "container:${gateway_container}" \
    --user "$(id -u):$(id -g)" \
    --read-only \
    --tmpfs /tmp:rw,noexec,nosuid,nodev,size=16m \
    --cap-drop ALL \
    --security-opt no-new-privileges:true \
    --pids-limit 128 \
    --memory 256m \
    --cpus 0.5 \
    --mount "type=bind,source=${temporary}/envoy.yaml,target=/etc/envoy/envoy.yaml,readonly" \
    --mount "type=bind,source=${temporary}/envoy-certs,target=/etc/pgextassure-mtls,readonly" \
    "${envoy_image}" \
    -c /etc/envoy/envoy.yaml \
    --log-level warning \
    --disable-hot-restart >/dev/null

ready=false
attempt=1
while [ "${attempt}" -le 30 ]; do
    if curl --fail --silent --show-error \
        --tlsv1.3 \
        --cacert "${temporary}/ca.crt" \
        --cert "${temporary}/client.crt" \
        --key "${temporary}/client.key" \
        "https://localhost:${listen_port}/healthz" \
        | grep -q '"status": "ok"'; then
        ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 1
done
test "${ready}" = true

if curl --fail --silent \
    --tlsv1.3 \
    --cacert "${temporary}/ca.crt" \
    "https://localhost:${listen_port}/healthz" >/dev/null 2>&1; then
    echo "mTLS ingress accepted a client without a certificate" >&2
    exit 1
fi

if curl --fail --silent \
    --tlsv1.3 \
    --cacert "${temporary}/ca.crt" \
    --cert "${temporary}/rogue.crt" \
    --key "${temporary}/rogue.key" \
    "https://localhost:${listen_port}/healthz" >/dev/null 2>&1; then
    echo "mTLS ingress accepted an untrusted client certificate" >&2
    exit 1
fi

if curl --fail --silent \
    --tls-max 1.2 \
    --cacert "${temporary}/ca.crt" \
    --cert "${temporary}/client.crt" \
    --key "${temporary}/client.key" \
    "https://localhost:${listen_port}/healthz" >/dev/null 2>&1; then
    echo "mTLS ingress accepted TLS below 1.3" >&2
    exit 1
fi

echo "PgExtAssure mTLS ingress smoke test: valid"
