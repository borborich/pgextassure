"""Self-service acceptance of a TLS 1.3/mTLS enterprise pilot deployment."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import ssl
import stat
import tempfile
from typing import Any
from urllib.parse import SplitResult, urlsplit

from .enterprise import AdmissionEnforcementError, enforce_pilot_package
from .gateway import GATEWAY_MEDIA_TYPE, MAX_GATEWAY_HEADER_BYTES
from .pilot import MAX_PILOT_PACKAGE_BYTES
from .signing import _write_private_temporary


ACCEPTANCE_REPORT_SCHEMA_VERSION = "1.0"
ACCEPTANCE_REPORT_TYPE = "pgextassure.pilot-acceptance-report"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_IDEMPOTENCY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_CHECK_IDS = (
    "offline-enforcement",
    "tls13-mtls-readiness",
    "reject-missing-client-certificate",
    "reject-tls12",
    "first-admission",
    "exact-replay",
)
_MAX_TLS_MATERIAL_BYTES = 4 * 1024 * 1024
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024


class PilotAcceptanceConfigurationError(ValueError):
    """The acceptance runner configuration is unsafe or malformed."""


@dataclass(frozen=True, slots=True)
class PilotAcceptance:
    """A complete, canonical customer acceptance result."""

    report: bytes
    document: dict[str, Any]
    accepted: bool


@dataclass(frozen=True, slots=True)
class _Origin:
    value: str
    host: str
    port: int


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    body: bytes
    headers: tuple[tuple[str, str], ...]
    tls_version: str
    peer_certificate_sha256: str


def _json_bytes(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            indent=2,
        )
        + "\n"
    ).encode("utf-8")


def _digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _validate_digest(value: str, *, label: str) -> str:
    if not _DIGEST_PATTERN.fullmatch(value):
        raise PilotAcceptanceConfigurationError(
            f"{label} must use sha256:<64 lowercase hex>"
        )
    return value


def _header_value(value: str, *, label: str, maximum: int) -> str:
    if not value:
        raise PilotAcceptanceConfigurationError(f"{label} must not be empty")
    try:
        raw = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise PilotAcceptanceConfigurationError(
            f"{label} must be ASCII"
        ) from error
    if len(raw) > maximum:
        raise PilotAcceptanceConfigurationError(
            f"{label} exceeds the safe size limit"
        )
    if any(byte < 0x20 or byte == 0x7F for byte in raw):
        raise PilotAcceptanceConfigurationError(
            f"{label} contains control characters"
        )
    return value


def _origin(value: str) -> _Origin:
    if not 1 <= len(value) <= 2048:
        raise PilotAcceptanceConfigurationError(
            "gateway URL exceeds the safe size limit"
        )
    try:
        parsed: SplitResult = urlsplit(value)
        port = 443 if parsed.port is None else parsed.port
    except ValueError as error:
        raise PilotAcceptanceConfigurationError(
            "gateway URL is invalid"
        ) from error
    if parsed.scheme != "https":
        raise PilotAcceptanceConfigurationError(
            "gateway URL must use https"
        )
    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise PilotAcceptanceConfigurationError(
            "gateway URL must be an HTTPS origin without credentials, "
            "path, query, or fragment"
        )
    try:
        parsed.hostname.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise PilotAcceptanceConfigurationError(
            "gateway hostname must be ASCII"
        ) from error
    if any(
        character.isspace() or ord(character) < 0x20
        for character in parsed.hostname
    ):
        raise PilotAcceptanceConfigurationError(
            "gateway hostname is invalid"
        )
    if not 1 <= port <= 65535:
        raise PilotAcceptanceConfigurationError("gateway port is invalid")
    host = parsed.hostname.lower()
    rendered_host = f"[{host}]" if ":" in host else host
    rendered_port = "" if port == 443 else f":{port}"
    return _Origin(
        value=f"https://{rendered_host}{rendered_port}",
        host=host,
        port=port,
    )


def _read_regular_file(
    path: str | os.PathLike[str],
    *,
    label: str,
    maximum: int,
    private: bool = False,
) -> bytes:
    target = Path(path)
    try:
        inspected = target.lstat()
    except OSError as error:
        raise PilotAcceptanceConfigurationError(
            f"cannot inspect {label}: {error}"
        ) from error
    if stat.S_ISLNK(inspected.st_mode) or not stat.S_ISREG(
        inspected.st_mode
    ):
        raise PilotAcceptanceConfigurationError(
            f"{label} must be a regular non-symlink file"
        )
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(target, flags)
    except OSError as error:
        raise PilotAcceptanceConfigurationError(
            f"cannot open {label}: {error}"
        ) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_dev, metadata.st_ino)
            != (inspected.st_dev, inspected.st_ino)
        ):
            raise PilotAcceptanceConfigurationError(
                f"{label} changed while it was being opened"
            )
        if private and metadata.st_mode & 0o077:
            raise PilotAcceptanceConfigurationError(
                f"{label} permissions must not grant group or other access"
            )
        if not 1 <= metadata.st_size <= maximum:
            raise PilotAcceptanceConfigurationError(
                f"{label} exceeds the safe size boundary"
            )
        chunks: list[bytes] = []
        remaining = maximum + 1
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        raw = b"".join(chunks)
        if not 1 <= len(raw) <= maximum:
            raise PilotAcceptanceConfigurationError(
                f"{label} exceeds the safe size boundary"
            )
        if len(raw) != metadata.st_size:
            raise PilotAcceptanceConfigurationError(
                f"{label} changed while it was being read"
            )
        return raw
    finally:
        os.close(descriptor)


def _ssl_context(
    *,
    ca_certificate: Path,
    client_certificate: Path | None,
    client_key: Path | None,
    version: ssl.TLSVersion,
) -> ssl.SSLContext:
    context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=str(ca_certificate),
    )
    context.minimum_version = version
    context.maximum_version = version
    if client_certificate is not None and client_key is not None:
        context.load_cert_chain(
            certfile=str(client_certificate),
            keyfile=str(client_key),
        )
    return context


def _request(
    origin: _Origin,
    context: ssl.SSLContext,
    *,
    method: str,
    path: str,
    timeout_seconds: int,
    body: bytes | None = None,
    headers: dict[str, str] | None = None,
) -> _Response:
    connection = http.client.HTTPSConnection(
        origin.host,
        origin.port,
        timeout=timeout_seconds,
        context=context,
    )
    try:
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        tls_version = (
            connection.sock.version()
            if connection.sock is not None
            else ""
        )
        peer_certificate = (
            connection.sock.getpeercert(binary_form=True)
            if connection.sock is not None
            else None
        )
        raw = response.read(_MAX_RESPONSE_BYTES + 1)
        if len(raw) > _MAX_RESPONSE_BYTES:
            raise http.client.HTTPException(
                "gateway response exceeds the safe size boundary"
            )
        return _Response(
            status=response.status,
            body=raw,
            headers=tuple(response.getheaders()),
            tls_version=tls_version,
            peer_certificate_sha256=(
                _digest(peer_certificate) if peer_certificate else ""
            ),
        )
    finally:
        connection.close()


def _single_header(response: _Response, name: str) -> str | None:
    values = [
        value
        for header_name, value in response.headers
        if header_name.casefold() == name.casefold()
    ]
    return values[0] if len(values) == 1 else None


def _ready(response: _Response) -> bool:
    if (
        response.status != 200
        or response.tls_version != "TLSv1.3"
        or not _DIGEST_PATTERN.fullmatch(
            response.peer_certificate_sha256
        )
        or _single_header(response, "Cache-Control") != "no-store"
        or _single_header(response, "Content-Type")
        != "application/json; charset=utf-8"
    ):
        return False
    return response.body == _json_bytes({"status": "ready"})


def _admission_response(
    response: _Response,
    *,
    event: bytes,
    replayed: str,
    peer_certificate_sha256: str,
) -> bool:
    return (
        response.status == 200
        and response.tls_version == "TLSv1.3"
        and _single_header(response, "Cache-Control") == "no-store"
        and _single_header(response, "Content-Type")
        == "application/json; charset=utf-8"
        and _single_header(response, "X-PgExtAssure-Replayed") == replayed
        and response.peer_certificate_sha256 == peer_certificate_sha256
        and response.body == event
    )


def _check(identifier: str, status_value: str, code: str) -> dict[str, str]:
    return {"id": identifier, "status": status_value, "code": code}


def _finish(document: dict[str, Any]) -> PilotAcceptance:
    accepted = all(
        check["status"] == "pass" for check in document["checks"]
    )
    document["accepted"] = accepted
    return PilotAcceptance(
        report=_json_bytes(document),
        document=document,
        accepted=accepted,
    )


def run_pilot_acceptance(
    package_path: str | os.PathLike[str],
    *,
    gateway_url: str,
    ca_certificate_path: str | os.PathLike[str],
    client_certificate_path: str | os.PathLike[str],
    client_key_path: str | os.PathLike[str],
    expected_package_sha256: str,
    expected_public_key_sha256: str,
    expected_trust_policy_sha256: str,
    expected_request_id: str,
    expected_target: str,
    expected_evaluated_on: date,
    verified_on: date,
    idempotency_key: str,
    timeout_seconds: int = 10,
    openssl_path: str | os.PathLike[str] | None = None,
) -> PilotAcceptance:
    """Run the complete offline, transport, admission, and replay contract."""

    endpoint = _origin(gateway_url)
    expected_package_sha256 = _validate_digest(
        expected_package_sha256,
        label="expected package SHA-256",
    )
    expected_public_key_sha256 = _validate_digest(
        expected_public_key_sha256,
        label="expected public-key SHA-256",
    )
    expected_trust_policy_sha256 = _validate_digest(
        expected_trust_policy_sha256,
        label="expected trust-policy SHA-256",
    )
    expected_request_id = _header_value(
        expected_request_id,
        label="expected request ID",
        maximum=MAX_GATEWAY_HEADER_BYTES,
    )
    expected_target = _header_value(
        expected_target,
        label="expected target",
        maximum=MAX_GATEWAY_HEADER_BYTES,
    )
    _header_value(
        idempotency_key,
        label="idempotency key",
        maximum=128,
    )
    if not _IDEMPOTENCY_PATTERN.fullmatch(idempotency_key):
        raise PilotAcceptanceConfigurationError(
            "idempotency key is invalid"
        )
    if type(expected_evaluated_on) is not date:
        raise PilotAcceptanceConfigurationError(
            "expected_evaluated_on must be a date"
        )
    if type(verified_on) is not date:
        raise PilotAcceptanceConfigurationError("verified_on must be a date")
    if type(timeout_seconds) is not int or not 1 <= timeout_seconds <= 60:
        raise PilotAcceptanceConfigurationError(
            "timeout_seconds must be an integer from 1 through 60"
        )

    package_raw = _read_regular_file(
        package_path,
        label="pilot package",
        maximum=MAX_PILOT_PACKAGE_BYTES,
    )
    ca_raw = _read_regular_file(
        ca_certificate_path,
        label="CA certificate",
        maximum=_MAX_TLS_MATERIAL_BYTES,
    )
    certificate_raw = _read_regular_file(
        client_certificate_path,
        label="client certificate",
        maximum=_MAX_TLS_MATERIAL_BYTES,
    )
    key_raw = _read_regular_file(
        client_key_path,
        label="client private key",
        maximum=_MAX_TLS_MATERIAL_BYTES,
        private=True,
    )
    document: dict[str, Any] = {
        "schema_version": ACCEPTANCE_REPORT_SCHEMA_VERSION,
        "report_type": ACCEPTANCE_REPORT_TYPE,
        "accepted": False,
        "observed_on": verified_on.isoformat(),
        "profile": "tls13-mtls-gateway",
        "gateway": {"origin": endpoint.value},
        "transport": {
            "protocol": "TLSv1.3",
            "ca_certificate_sha256": _digest(ca_raw),
            "client_certificate_sha256": _digest(certificate_raw),
            "server_certificate_sha256": None,
        },
        "package": {"digest": expected_package_sha256},
        "request": {
            "id": expected_request_id,
            "target": expected_target,
            "evaluated_on": expected_evaluated_on.isoformat(),
            "idempotency_key_sha256": _digest(
                idempotency_key.encode("ascii")
            ),
        },
        "event": None,
        "checks": [
            _check(identifier, "not-run", "not-run")
            for identifier in _CHECK_IDS
        ],
    }

    with tempfile.TemporaryDirectory(
        prefix="pgextassure-acceptance-"
    ) as directory:
        root = Path(directory)
        package_copy = root / "pilot-package.zip"
        ca_copy = root / "ca.pem"
        certificate_copy = root / "client.pem"
        key_copy = root / "client-key.pem"
        for destination, raw in (
            (package_copy, package_raw),
            (ca_copy, ca_raw),
            (certificate_copy, certificate_raw),
            (key_copy, key_raw),
        ):
            _write_private_temporary(destination, raw)

        try:
            enforcement = enforce_pilot_package(
                package_copy,
                expected_package_sha256=expected_package_sha256,
                expected_public_key_sha256=expected_public_key_sha256,
                expected_trust_policy_sha256=(
                    expected_trust_policy_sha256
                ),
                expected_request_id=expected_request_id,
                expected_target=expected_target,
                expected_evaluated_on=expected_evaluated_on,
                verified_on=verified_on,
                openssl_path=openssl_path,
            )
        except AdmissionEnforcementError:
            document["checks"][0] = _check(
                _CHECK_IDS[0],
                "fail",
                "offline-verification-failed",
            )
            return _finish(document)
        document["event"] = {
            "id": enforcement.document["id"],
            "digest": _digest(enforcement.event),
            "outcome": enforcement.document["outcome"],
        }
        if not enforcement.active:
            document["checks"][0] = _check(
                _CHECK_IDS[0],
                "fail",
                "offline-admission-denied",
            )
            return _finish(document)
        document["checks"][0] = _check(_CHECK_IDS[0], "pass", "passed")

        try:
            authorized = _ssl_context(
                ca_certificate=ca_copy,
                client_certificate=certificate_copy,
                client_key=key_copy,
                version=ssl.TLSVersion.TLSv1_3,
            )
            readiness = _request(
                endpoint,
                authorized,
                method="GET",
                path="/readyz",
                timeout_seconds=timeout_seconds,
            )
        except (OSError, ssl.SSLError, ValueError, http.client.HTTPException):
            document["checks"][1] = _check(
                _CHECK_IDS[1], "fail", "readiness-failed"
            )
            return _finish(document)
        if not _ready(readiness):
            document["checks"][1] = _check(
                _CHECK_IDS[1], "fail", "readiness-failed"
            )
            return _finish(document)
        document["transport"]["server_certificate_sha256"] = (
            readiness.peer_certificate_sha256
        )
        document["checks"][1] = _check(_CHECK_IDS[1], "pass", "passed")

        try:
            unauthorized = _ssl_context(
                ca_certificate=ca_copy,
                client_certificate=None,
                client_key=None,
                version=ssl.TLSVersion.TLSv1_3,
            )
            _request(
                endpoint,
                unauthorized,
                method="GET",
                path="/readyz",
                timeout_seconds=timeout_seconds,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException):
            document["checks"][2] = _check(_CHECK_IDS[2], "pass", "passed")
        else:
            document["checks"][2] = _check(
                _CHECK_IDS[2],
                "fail",
                "missing-client-certificate-accepted",
            )
            return _finish(document)

        try:
            tls12 = _ssl_context(
                ca_certificate=ca_copy,
                client_certificate=certificate_copy,
                client_key=key_copy,
                version=ssl.TLSVersion.TLSv1_2,
            )
        except (OSError, ssl.SSLError, ValueError):
            document["checks"][3] = _check(
                _CHECK_IDS[3], "fail", "tls12-probe-unavailable"
            )
            return _finish(document)
        try:
            _request(
                endpoint,
                tls12,
                method="GET",
                path="/readyz",
                timeout_seconds=timeout_seconds,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException):
            document["checks"][3] = _check(_CHECK_IDS[3], "pass", "passed")
        else:
            document["checks"][3] = _check(
                _CHECK_IDS[3], "fail", "tls12-accepted"
            )
            return _finish(document)

        headers = {
            "Content-Type": GATEWAY_MEDIA_TYPE,
            "X-PgExtAssure-Package-SHA256": expected_package_sha256,
            "X-PgExtAssure-Key-SHA256": expected_public_key_sha256,
            "X-PgExtAssure-Trust-Policy-SHA256": (
                expected_trust_policy_sha256
            ),
            "X-PgExtAssure-Request-ID": expected_request_id,
            "X-PgExtAssure-Target": expected_target,
            "X-PgExtAssure-Evaluated-On": expected_evaluated_on.isoformat(),
            "X-PgExtAssure-Verified-On": verified_on.isoformat(),
            "Idempotency-Key": idempotency_key,
        }
        try:
            first = _request(
                endpoint,
                authorized,
                method="POST",
                path="/v1/admissions",
                timeout_seconds=timeout_seconds,
                body=package_raw,
                headers=headers,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException):
            document["checks"][4] = _check(
                _CHECK_IDS[4], "fail", "first-admission-failed"
            )
            return _finish(document)
        if not _admission_response(
            first,
            event=enforcement.event,
            replayed="false",
            peer_certificate_sha256=readiness.peer_certificate_sha256,
        ):
            document["checks"][4] = _check(
                _CHECK_IDS[4], "fail", "first-admission-failed"
            )
            return _finish(document)
        document["checks"][4] = _check(_CHECK_IDS[4], "pass", "passed")

        try:
            replay = _request(
                endpoint,
                authorized,
                method="POST",
                path="/v1/admissions",
                timeout_seconds=timeout_seconds,
                body=package_raw,
                headers=headers,
            )
        except (OSError, ssl.SSLError, http.client.HTTPException):
            document["checks"][5] = _check(
                _CHECK_IDS[5], "fail", "replay-failed"
            )
            return _finish(document)
        if not _admission_response(
            replay,
            event=enforcement.event,
            replayed="true",
            peer_certificate_sha256=readiness.peer_certificate_sha256,
        ):
            document["checks"][5] = _check(
                _CHECK_IDS[5], "fail", "replay-failed"
            )
            return _finish(document)
        document["checks"][5] = _check(_CHECK_IDS[5], "pass", "passed")
        return _finish(document)
