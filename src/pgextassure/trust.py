"""Offline enterprise trust evaluation and deterministic admission receipts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile
from typing import Any

from ._version import RELEASE_VERSION
from .evidence import (
    MAX_BUNDLE_BYTES,
    EvidenceError,
    EvidenceVerification,
    verify_evidence_bundle,
)
from .signing import (
    MAX_STATEMENT_BYTES,
    SigningError,
    _read_regular,
    _write_private_temporary,
    verify_evidence_signature,
)


TRUST_POLICY_SCHEMA_VERSION = "1.0"
TRUST_POLICY_TYPE = "pgextassure.enterprise-trust-policy"
RECEIPT_SCHEMA_VERSION = "1.0"
RECEIPT_TYPE = "pgextassure.admission-receipt"
MAX_TRUST_FILE_BYTES = 1024 * 1024
MAX_TRUST_LIST_ENTRIES = 256
MAX_SIGNERS = 256
MAX_TEXT_BYTES = 512
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_VERSION_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+-]{0,127}\Z")
_POLICY_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}\Z")
_BIDI_CONTROLS = frozenset(
    {
        0x061C,
        0x200E,
        0x200F,
        0x202A,
        0x202B,
        0x202C,
        0x202D,
        0x202E,
        0x2066,
        0x2067,
        0x2068,
        0x2069,
    }
)


class TrustError(ValueError):
    """Base error for the enterprise trust layer."""


class TrustPolicyError(TrustError):
    """A trust policy or evaluation request is malformed."""


class TrustVerificationError(TrustError):
    """Cryptographic evidence or a receipt cannot be verified."""


@dataclass(frozen=True, slots=True)
class TrustedSigner:
    signer_id: str
    public_key_sha256: str
    valid_from: date
    valid_until: date | None
    revoked_on: date | None


@dataclass(frozen=True, slots=True)
class TrustRequirements:
    allowed_gates: tuple[str, ...]
    allowed_tool_versions: tuple[str, ...]
    allowed_ruleset_versions: tuple[str, ...]
    allowed_evidence_schema_versions: tuple[str, ...]
    allowed_policy_digests: tuple[str, ...]
    maximum_evidence_age_days: int
    maximum_signature_age_days: int
    receipt_valid_days: int


@dataclass(frozen=True, slots=True)
class EnterpriseTrustPolicy:
    digest: str
    policy_id: str
    effective_from: date
    expires_on: date | None
    requirements: TrustRequirements
    signers: tuple[TrustedSigner, ...]


@dataclass(frozen=True, slots=True)
class AdmissionReceipt:
    receipt: bytes
    document: dict[str, Any]
    summary: dict[str, Any]


@dataclass(frozen=True, slots=True)
class AdmissionReceiptVerification:
    document: dict[str, Any]
    summary: dict[str, Any]


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


def _pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise TrustPolicyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _object(
    value: object,
    *,
    label: str,
    fields: frozenset[str],
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TrustPolicyError(f"{label} must be an object")
    keys = frozenset(value)
    unknown = keys - fields
    missing = fields - keys
    if unknown:
        raise TrustPolicyError(
            f"{label} contains unknown field {sorted(unknown)[0]!r}"
        )
    if missing:
        raise TrustPolicyError(
            f"{label} is missing field {sorted(missing)[0]!r}"
        )
    return value


def _date(value: object, *, label: str) -> date:
    if not isinstance(value, str):
        raise TrustPolicyError(f"{label} must use YYYY-MM-DD")
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise TrustPolicyError(f"{label} must use YYYY-MM-DD") from error
    if parsed.isoformat() != value:
        raise TrustPolicyError(f"{label} must use YYYY-MM-DD")
    return parsed


def _optional_date(value: object, *, label: str) -> date | None:
    return None if value is None else _date(value, label=label)


def _bounded_text(value: object, *, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TrustPolicyError(f"{label} must be a non-empty string")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as error:
        raise TrustPolicyError(f"{label} must be valid UTF-8") from error
    if len(encoded) > MAX_TEXT_BYTES:
        raise TrustPolicyError(
            f"{label} exceeds the {MAX_TEXT_BYTES}-byte limit"
        )
    if any(
        ord(character) < 0x20
        or 0x7F <= ord(character) <= 0x9F
        or ord(character) in _BIDI_CONTROLS
        for character in value
    ):
        raise TrustPolicyError(f"{label} contains control characters")
    return value


def _closed_list(
    value: object,
    *,
    label: str,
    pattern: re.Pattern[str] | None = None,
    allowed: frozenset[str] | None = None,
) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise TrustPolicyError(f"{label} must be a non-empty list")
    if len(value) > MAX_TRUST_LIST_ENTRIES:
        raise TrustPolicyError(
            f"{label} exceeds the {MAX_TRUST_LIST_ENTRIES}-entry limit"
        )
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if (
            not isinstance(item, str)
            or (pattern is not None and not pattern.fullmatch(item))
            or (allowed is not None and item not in allowed)
        ):
            raise TrustPolicyError(f"{label} entry {index} is invalid")
        if item in seen:
            raise TrustPolicyError(f"{label} repeats {item!r}")
        seen.add(item)
        result.append(item)
    return tuple(result)


def _bounded_days(value: object, *, label: str, maximum: int) -> int:
    if type(value) is not int or not 0 <= value <= maximum:
        raise TrustPolicyError(
            f"{label} must be an integer between 0 and {maximum}"
        )
    return value


def _read_trust_file(
    path: str | os.PathLike[str],
    *,
    label: str,
) -> bytes:
    try:
        raw = _read_regular(
            path,
            label=label,
            maximum=MAX_TRUST_FILE_BYTES,
        )
    except SigningError as error:
        raise TrustPolicyError(str(error)) from error
    if b"\x00" in raw:
        raise TrustPolicyError(f"{label} contains binary data")
    return raw


def load_trust_policy(
    path: str | os.PathLike[str],
) -> EnterpriseTrustPolicy:
    """Load an exact, closed-schema enterprise trust policy."""

    raw = _read_trust_file(path, label="enterprise trust policy")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except TrustPolicyError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise TrustPolicyError(f"invalid enterprise trust policy: {error}") from error
    document = _object(
        parsed,
        label="enterprise trust policy",
        fields=frozenset(
            {
                "schema_version",
                "policy_type",
                "policy_id",
                "effective_from",
                "expires_on",
                "requirements",
                "signers",
            }
        ),
    )
    if (
        document["schema_version"] != TRUST_POLICY_SCHEMA_VERSION
        or document["policy_type"] != TRUST_POLICY_TYPE
    ):
        raise TrustPolicyError("unsupported enterprise trust policy")
    policy_id = document["policy_id"]
    if not isinstance(policy_id, str) or not _POLICY_ID_PATTERN.fullmatch(
        policy_id
    ):
        raise TrustPolicyError("enterprise trust policy_id is invalid")
    effective_from = _date(
        document["effective_from"],
        label="enterprise trust policy effective_from",
    )
    expires_on = _optional_date(
        document["expires_on"],
        label="enterprise trust policy expires_on",
    )
    if expires_on is not None and expires_on < effective_from:
        raise TrustPolicyError(
            "enterprise trust policy expires before it becomes effective"
        )
    requirements = _object(
        document["requirements"],
        label="enterprise trust policy requirements",
        fields=frozenset(
            {
                "allowed_gates",
                "allowed_tool_versions",
                "allowed_ruleset_versions",
                "allowed_evidence_schema_versions",
                "allowed_policy_digests",
                "maximum_evidence_age_days",
                "maximum_signature_age_days",
                "receipt_valid_days",
            }
        ),
    )
    allowed_policy_digests = _closed_list(
        requirements["allowed_policy_digests"],
        label="allowed_policy_digests",
        pattern=_DIGEST_PATTERN,
    )
    parsed_requirements = TrustRequirements(
        allowed_gates=_closed_list(
            requirements["allowed_gates"],
            label="allowed_gates",
            allowed=frozenset({"pass", "blocked"}),
        ),
        allowed_tool_versions=_closed_list(
            requirements["allowed_tool_versions"],
            label="allowed_tool_versions",
            pattern=_VERSION_PATTERN,
        ),
        allowed_ruleset_versions=_closed_list(
            requirements["allowed_ruleset_versions"],
            label="allowed_ruleset_versions",
            pattern=_VERSION_PATTERN,
        ),
        allowed_evidence_schema_versions=_closed_list(
            requirements["allowed_evidence_schema_versions"],
            label="allowed_evidence_schema_versions",
            pattern=_VERSION_PATTERN,
        ),
        allowed_policy_digests=allowed_policy_digests,
        maximum_evidence_age_days=_bounded_days(
            requirements["maximum_evidence_age_days"],
            label="maximum_evidence_age_days",
            maximum=3650,
        ),
        maximum_signature_age_days=_bounded_days(
            requirements["maximum_signature_age_days"],
            label="maximum_signature_age_days",
            maximum=3650,
        ),
        receipt_valid_days=_bounded_days(
            requirements["receipt_valid_days"],
            label="receipt_valid_days",
            maximum=365,
        ),
    )
    values = document["signers"]
    if not isinstance(values, list) or not 1 <= len(values) <= MAX_SIGNERS:
        raise TrustPolicyError(
            "enterprise trust policy signers must contain "
            f"1..{MAX_SIGNERS} entries"
        )
    signers: list[TrustedSigner] = []
    identities: set[tuple[str, str, date]] = set()
    for index, value in enumerate(values):
        item = _object(
            value,
            label=f"enterprise trust policy signer {index}",
            fields=frozenset(
                {
                    "id",
                    "public_key_sha256",
                    "valid_from",
                    "valid_until",
                    "revoked_on",
                }
            ),
        )
        signer_id = _bounded_text(
            item["id"],
            label=f"enterprise trust policy signer {index} ID",
        )
        key_digest = item["public_key_sha256"]
        if (
            not isinstance(key_digest, str)
            or not _DIGEST_PATTERN.fullmatch(key_digest)
        ):
            raise TrustPolicyError(
                f"enterprise trust policy signer {index} fingerprint is invalid"
            )
        valid_from = _date(
            item["valid_from"],
            label=f"enterprise trust policy signer {index} valid_from",
        )
        valid_until = _optional_date(
            item["valid_until"],
            label=f"enterprise trust policy signer {index} valid_until",
        )
        revoked_on = _optional_date(
            item["revoked_on"],
            label=f"enterprise trust policy signer {index} revoked_on",
        )
        if valid_until is not None and valid_until < valid_from:
            raise TrustPolicyError(
                f"enterprise trust policy signer {index} validity is inverted"
            )
        identity = (signer_id, key_digest, valid_from)
        if identity in identities:
            raise TrustPolicyError(
                f"enterprise trust policy repeats signer entry {index}"
            )
        identities.add(identity)
        signers.append(
            TrustedSigner(
                signer_id=signer_id,
                public_key_sha256=key_digest,
                valid_from=valid_from,
                valid_until=valid_until,
                revoked_on=revoked_on,
            )
        )
    return EnterpriseTrustPolicy(
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        policy_id=policy_id,
        effective_from=effective_from,
        expires_on=expires_on,
        requirements=parsed_requirements,
        signers=tuple(signers),
    )


def _append_reason(reasons: list[str], reason: str) -> None:
    if reason not in reasons:
        reasons.append(reason)


def _matching_signer(
    policy: EnterpriseTrustPolicy,
    *,
    signer_id: str,
    key_digest: str,
    signed_on: date,
    evaluated_on: date,
    reasons: list[str],
) -> TrustedSigner | None:
    candidates = tuple(
        signer
        for signer in policy.signers
        if signer.signer_id == signer_id
        and signer.public_key_sha256 == key_digest
    )
    if not candidates:
        _append_reason(reasons, "untrusted-signer")
        return None
    active = tuple(
        signer
        for signer in candidates
        if signed_on >= signer.valid_from
        and (
            signer.valid_until is None
            or (
                signed_on <= signer.valid_until
                and evaluated_on <= signer.valid_until
            )
        )
        and (signer.revoked_on is None or evaluated_on < signer.revoked_on)
    )
    if active:
        return sorted(
            active,
            key=lambda signer: (
                signer.valid_from,
                signer.valid_until or date.max,
            ),
            reverse=True,
        )[0]
    if all(signed_on < signer.valid_from for signer in candidates):
        _append_reason(reasons, "signer-not-yet-valid")
    elif all(
        signer.revoked_on is not None and evaluated_on >= signer.revoked_on
        for signer in candidates
    ):
        _append_reason(reasons, "signer-revoked")
    else:
        _append_reason(reasons, "signer-expired")
    return None


def _minimum_date(values: list[date]) -> date:
    return min(values) if values else date.max


def _evaluate_with_policy(
    bundle_path: str | os.PathLike[str],
    *,
    statement_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    policy: EnterpriseTrustPolicy,
    evaluated_on: date,
    request_id: str,
    target: str,
    openssl_path: str | os.PathLike[str] | None,
) -> AdmissionReceipt:
    if type(evaluated_on) is not date:
        raise TrustPolicyError("evaluated_on must be a date")
    request_id = _bounded_text(request_id, label="request ID")
    target = _bounded_text(target, label="request target")
    try:
        bundle_raw = _read_regular(
            bundle_path,
            label="Evidence Bundle",
            maximum=MAX_BUNDLE_BYTES,
        )
    except SigningError as error:
        raise TrustVerificationError(str(error)) from error
    with tempfile.TemporaryDirectory(prefix="pgextassure-trust-") as directory:
        stable_bundle = Path(directory) / "evidence.zip"
        _write_private_temporary(stable_bundle, bundle_raw)
        try:
            evidence = verify_evidence_bundle(stable_bundle)
            signed = verify_evidence_signature(
                stable_bundle,
                statement_path=statement_path,
                signature_path=signature_path,
                public_key_path=public_key_path,
                openssl_path=openssl_path,
            )
        except (EvidenceError, SigningError) as error:
            raise TrustVerificationError(
                f"signed Evidence Bundle verification failed: {error}"
            ) from error
    predicate = evidence.predicate
    statement = signed.statement
    evidence_created_on = _date(
        predicate["created_on"],
        label="Evidence Bundle created_on",
    )
    signature_created_on = _date(
        statement["created_on"],
        label="signature created_on",
    )
    requirements = policy.requirements
    reasons: list[str] = []
    if evaluated_on < policy.effective_from:
        _append_reason(reasons, "trust-policy-not-effective")
    if policy.expires_on is not None and evaluated_on > policy.expires_on:
        _append_reason(reasons, "trust-policy-expired")
    if evidence.summary["gate"] not in requirements.allowed_gates:
        _append_reason(reasons, "gate-not-allowed")
    if predicate["tool"]["version"] not in requirements.allowed_tool_versions:
        _append_reason(reasons, "tool-version-not-allowed")
    if (
        predicate["tool"]["ruleset_version"]
        not in requirements.allowed_ruleset_versions
    ):
        _append_reason(reasons, "ruleset-version-not-allowed")
    if (
        evidence.summary["schema_version"]
        not in requirements.allowed_evidence_schema_versions
    ):
        _append_reason(reasons, "evidence-schema-not-allowed")
    if (
        evidence.summary["policy_digest"]
        not in requirements.allowed_policy_digests
    ):
        _append_reason(reasons, "evidence-policy-not-allowed")
    if evidence_created_on > evaluated_on:
        _append_reason(reasons, "evidence-from-future")
    elif (
        evaluated_on - evidence_created_on
    ).days > requirements.maximum_evidence_age_days:
        _append_reason(reasons, "evidence-too-old")
    if signature_created_on < evidence_created_on:
        _append_reason(reasons, "signature-before-evidence")
    if signature_created_on > evaluated_on:
        _append_reason(reasons, "signature-from-future")
    elif (
        evaluated_on - signature_created_on
    ).days > requirements.maximum_signature_age_days:
        _append_reason(reasons, "signature-too-old")
    matched_signer = _matching_signer(
        policy,
        signer_id=statement["signer"]["id"],
        key_digest=statement["signature"]["public_key"]["sha256"],
        signed_on=signature_created_on,
        evaluated_on=evaluated_on,
        reasons=reasons,
    )
    result = "admit" if not reasons else "deny"
    valid_until = evaluated_on
    if result == "admit":
        limits = [
            evaluated_on + timedelta(days=requirements.receipt_valid_days),
            evidence_created_on
            + timedelta(days=requirements.maximum_evidence_age_days),
            signature_created_on
            + timedelta(days=requirements.maximum_signature_age_days),
        ]
        if policy.expires_on is not None:
            limits.append(policy.expires_on)
        if matched_signer is not None:
            if matched_signer.valid_until is not None:
                limits.append(matched_signer.valid_until)
            if matched_signer.revoked_on is not None:
                limits.append(matched_signer.revoked_on - timedelta(days=1))
        valid_until = _minimum_date(limits)
    document = {
        "schema_version": RECEIPT_SCHEMA_VERSION,
        "receipt_type": RECEIPT_TYPE,
        "evaluator": {
            "name": "pgextassure",
            "version": RELEASE_VERSION,
        },
        "request": {
            "id": request_id,
            "target": target,
        },
        "validity": {
            "evaluated_on": evaluated_on.isoformat(),
            "valid_until": valid_until.isoformat(),
        },
        "decision": {
            "result": result,
            "reasons": reasons,
        },
        "trust_policy": {
            "id": policy.policy_id,
            "digest": policy.digest,
        },
        "subject": {
            "media_type": "application/vnd.pgextassure.evidence+zip",
            "digest": signed.summary["subject_digest"],
            "gate": evidence.summary["gate"],
            "evidence_created_on": evidence_created_on.isoformat(),
            "manifest_digest": evidence.summary["manifest_digest"],
            "coverage_digest": evidence.summary["coverage_digest"],
            "policy_digest": evidence.summary["policy_digest"],
            "component": evidence.summary["component"],
            "tool": predicate["tool"],
        },
        "signature": {
            "profile": signed.summary["profile"],
            "created_on": signature_created_on.isoformat(),
            "signer_id": signed.summary["signer_id"],
            "public_key_sha256": signed.summary["public_key_sha256"],
        },
    }
    rendered = _json_bytes(document)
    return AdmissionReceipt(
        receipt=rendered,
        document=document,
        summary={
            "schema_version": RECEIPT_SCHEMA_VERSION,
            "valid": True,
            "decision": result,
            "reasons": list(reasons),
            "request_id": request_id,
            "target": target,
            "evaluated_on": evaluated_on.isoformat(),
            "valid_until": valid_until.isoformat(),
            "trust_policy_digest": policy.digest,
            "subject_digest": signed.summary["subject_digest"],
            "signer_id": signed.summary["signer_id"],
        },
    )


def evaluate_admission(
    bundle_path: str | os.PathLike[str],
    *,
    statement_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    trust_policy_path: str | os.PathLike[str],
    evaluated_on: date,
    request_id: str,
    target: str,
    openssl_path: str | os.PathLike[str] | None = None,
) -> AdmissionReceipt:
    """Evaluate signed evidence against one exact enterprise trust policy."""

    policy = load_trust_policy(trust_policy_path)
    return _evaluate_with_policy(
        bundle_path,
        statement_path=statement_path,
        signature_path=signature_path,
        public_key_path=public_key_path,
        policy=policy,
        evaluated_on=evaluated_on,
        request_id=request_id,
        target=target,
        openssl_path=openssl_path,
    )


def _parse_receipt_request(raw: bytes) -> tuple[dict[str, Any], date, str, str]:
    if len(raw) > MAX_STATEMENT_BYTES or b"\x00" in raw:
        raise TrustVerificationError("admission receipt exceeds its safe boundary")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except TrustPolicyError as error:
        raise TrustVerificationError(str(error)) from error
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise TrustVerificationError(f"invalid admission receipt: {error}") from error
    try:
        document = _object(
            parsed,
            label="admission receipt",
            fields=frozenset(
                {
                    "schema_version",
                    "receipt_type",
                    "evaluator",
                    "request",
                    "validity",
                    "decision",
                    "trust_policy",
                    "subject",
                    "signature",
                }
            ),
        )
        if (
            document["schema_version"] != RECEIPT_SCHEMA_VERSION
            or document["receipt_type"] != RECEIPT_TYPE
        ):
            raise TrustPolicyError("unsupported admission receipt")
        if raw != _json_bytes(document):
            raise TrustPolicyError("admission receipt is not canonically rendered")
        request = _object(
            document["request"],
            label="admission receipt request",
            fields=frozenset({"id", "target"}),
        )
        validity = _object(
            document["validity"],
            label="admission receipt validity",
            fields=frozenset({"evaluated_on", "valid_until"}),
        )
        evaluated_on = _date(
            validity["evaluated_on"],
            label="admission receipt evaluated_on",
        )
        request_id = _bounded_text(
            request["id"],
            label="admission receipt request ID",
        )
        target = _bounded_text(
            request["target"],
            label="admission receipt target",
        )
    except TrustPolicyError as error:
        raise TrustVerificationError(str(error)) from error
    return document, evaluated_on, request_id, target


def verify_admission_receipt(
    receipt_path: str | os.PathLike[str],
    bundle_path: str | os.PathLike[str],
    *,
    statement_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    trust_policy_path: str | os.PathLike[str],
    verified_on: date,
    expected_request_id: str,
    expected_target: str,
    expected_evaluated_on: date,
    expected_trust_policy_sha256: str | None = None,
    openssl_path: str | os.PathLike[str] | None = None,
) -> AdmissionReceiptVerification:
    """Recompute a receipt and report whether its admission remains active."""

    if type(verified_on) is not date:
        raise TrustPolicyError("verified_on must be a date")
    if type(expected_evaluated_on) is not date:
        raise TrustPolicyError("expected_evaluated_on must be a date")
    expected_request_id = _bounded_text(
        expected_request_id,
        label="expected request ID",
    )
    expected_target = _bounded_text(
        expected_target,
        label="expected request target",
    )
    try:
        receipt_raw = _read_regular(
            receipt_path,
            label="admission receipt",
            maximum=MAX_STATEMENT_BYTES,
        )
    except SigningError as error:
        raise TrustVerificationError(str(error)) from error
    document, evaluated_on, request_id, target = _parse_receipt_request(
        receipt_raw
    )
    if (
        request_id != expected_request_id
        or target != expected_target
        or evaluated_on != expected_evaluated_on
    ):
        raise TrustVerificationError(
            "admission receipt does not match the trusted request context"
        )
    policy = load_trust_policy(trust_policy_path)
    if expected_trust_policy_sha256 is not None:
        if not _DIGEST_PATTERN.fullmatch(expected_trust_policy_sha256):
            raise TrustPolicyError(
                "expected trust-policy SHA-256 must use "
                "sha256:<64 lowercase hex>"
            )
        if policy.digest != expected_trust_policy_sha256:
            raise TrustVerificationError(
                "enterprise trust policy does not match the trusted digest"
            )
    recomputed = _evaluate_with_policy(
        bundle_path,
        statement_path=statement_path,
        signature_path=signature_path,
        public_key_path=public_key_path,
        policy=policy,
        evaluated_on=evaluated_on,
        request_id=request_id,
        target=target,
        openssl_path=openssl_path,
    )
    if receipt_raw != recomputed.receipt:
        raise TrustVerificationError(
            "admission receipt does not match the supplied trust inputs"
        )
    valid_until = _date(
        document["validity"]["valid_until"],
        label="admission receipt valid_until",
    )
    active = (
        document["decision"]["result"] == "admit"
        and evaluated_on <= verified_on <= valid_until
    )
    return AdmissionReceiptVerification(
        document=document,
        summary={
            **recomputed.summary,
            "verified_on": verified_on.isoformat(),
            "active": active,
        },
    )
