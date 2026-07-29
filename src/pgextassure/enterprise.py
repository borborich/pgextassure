"""One-shot enforcement of portable enterprise pilot packages."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from .pilot import PilotPackageError, verify_pilot_package
from .signing import SigningError, _write_private_temporary, verify_evidence_signature
from .trust import (
    TrustPolicyError,
    TrustVerificationError,
    verify_admission_receipt,
)


ADMISSION_EVENT_SCHEMA_VERSION = "1.0"
ADMISSION_EVENT_TYPE = "pgextassure.enterprise-admission-event"
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_PAYLOAD_PATHS = {
    "bundle": "pgextassure-evidence.zip",
    "statement": "pgextassure-signature.json",
    "signature": "pgextassure-signature.bin",
    "public_key": "pgextassure-public-key.pem",
    "trust_policy": "enterprise-trust-policy.json",
    "receipt": "pgextassure-admission-receipt.json",
}


class AdmissionEnforcementError(ValueError):
    """A package cannot be admitted against trusted external anchors."""


@dataclass(frozen=True, slots=True)
class AdmissionEnforcement:
    event: bytes
    document: dict[str, Any]
    active: bool


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


def _expected_digest(value: str, *, label: str) -> str:
    if not _DIGEST_PATTERN.fullmatch(value):
        raise AdmissionEnforcementError(
            f"{label} must use sha256:<64 lowercase hex>"
        )
    return value


def _event_id(document: dict[str, Any]) -> str:
    return "sha256:" + hashlib.sha256(_json_bytes(document)).hexdigest()


def enforce_pilot_package(
    package_path: str | os.PathLike[str],
    *,
    expected_package_sha256: str,
    expected_public_key_sha256: str,
    expected_trust_policy_sha256: str,
    expected_request_id: str,
    expected_target: str,
    expected_evaluated_on: date,
    verified_on: date,
    openssl_path: str | os.PathLike[str] | None = None,
) -> AdmissionEnforcement:
    """Recompute all admission claims in a package against external anchors."""

    expected_package_sha256 = _expected_digest(
        expected_package_sha256,
        label="expected package SHA-256",
    )
    expected_public_key_sha256 = _expected_digest(
        expected_public_key_sha256,
        label="expected public-key SHA-256",
    )
    expected_trust_policy_sha256 = _expected_digest(
        expected_trust_policy_sha256,
        label="expected trust-policy SHA-256",
    )
    if type(expected_evaluated_on) is not date:
        raise AdmissionEnforcementError("expected_evaluated_on must be a date")
    if type(verified_on) is not date:
        raise AdmissionEnforcementError("verified_on must be a date")

    try:
        package = verify_pilot_package(package_path)
    except PilotPackageError as error:
        raise AdmissionEnforcementError(
            f"pilot package verification failed: {error}"
        ) from error
    if package.summary["archive_sha256"] != expected_package_sha256:
        raise AdmissionEnforcementError(
            "pilot package does not match the trusted expected digest"
        )

    manifest_digest = "sha256:" + hashlib.sha256(
        _json_bytes(package.manifest)
    ).hexdigest()
    with tempfile.TemporaryDirectory(
        prefix="pgextassure-admission-"
    ) as directory:
        root = Path(directory)
        paths: dict[str, Path] = {}
        try:
            for label, payload_name in _PAYLOAD_PATHS.items():
                destination = root / payload_name
                _write_private_temporary(
                    destination,
                    package.payloads[payload_name],
                )
                paths[label] = destination
            signature = verify_evidence_signature(
                paths["bundle"],
                statement_path=paths["statement"],
                signature_path=paths["signature"],
                public_key_path=paths["public_key"],
                expected_public_key_sha256=expected_public_key_sha256,
                openssl_path=openssl_path,
            )
            receipt = verify_admission_receipt(
                paths["receipt"],
                paths["bundle"],
                statement_path=paths["statement"],
                signature_path=paths["signature"],
                public_key_path=paths["public_key"],
                trust_policy_path=paths["trust_policy"],
                verified_on=verified_on,
                expected_request_id=expected_request_id,
                expected_target=expected_target,
                expected_evaluated_on=expected_evaluated_on,
                expected_trust_policy_sha256=expected_trust_policy_sha256,
                openssl_path=openssl_path,
            )
        except (SigningError, TrustPolicyError, TrustVerificationError) as error:
            raise AdmissionEnforcementError(
                f"embedded admission verification failed: {error}"
            ) from error

    source = receipt.document
    core = {
        "schema_version": ADMISSION_EVENT_SCHEMA_VERSION,
        "event_type": ADMISSION_EVENT_TYPE,
        "observed_on": verified_on.isoformat(),
        "outcome": "allow" if receipt.summary["active"] else "deny",
        "active": receipt.summary["active"],
        "request": {
            "id": source["request"]["id"],
            "target": source["request"]["target"],
            "evaluated_on": source["validity"]["evaluated_on"],
        },
        "package": {
            "digest": package.summary["archive_sha256"],
            "manifest_digest": manifest_digest,
            "files": package.summary["files"],
        },
        "decision": {
            "result": source["decision"]["result"],
            "reasons": source["decision"]["reasons"],
            "valid_until": source["validity"]["valid_until"],
        },
        "trust": {
            "policy_id": source["trust_policy"]["id"],
            "policy_digest": source["trust_policy"]["digest"],
        },
        "subject": {
            "digest": source["subject"]["digest"],
            "gate": source["subject"]["gate"],
            "component": source["subject"]["component"],
            "tool": source["subject"]["tool"],
        },
        "signature": {
            "signer_id": signature.summary["signer_id"],
            "public_key_sha256": signature.summary["public_key_sha256"],
            "created_on": signature.summary["created_on"],
        },
    }
    document = {**core, "id": _event_id(core)}
    return AdmissionEnforcement(
        event=_json_bytes(document),
        document=document,
        active=receipt.summary["active"],
    )
