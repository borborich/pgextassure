"""Offline corporate signatures for already-verified Evidence Bundles."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tempfile
from typing import Any

from .evidence import MAX_BUNDLE_BYTES, EvidenceError, verify_evidence_bundle


SIGNATURE_SCHEMA_VERSION = "1.0"
STATEMENT_TYPE = "pgextassure.corporate-evidence-signature"
SIGNATURE_PROFILE = "rsa-pss-sha256"
MINIMUM_RSA_BITS = 3072
MAX_KEY_BYTES = 1024 * 1024
MAX_STATEMENT_BYTES = 1024 * 1024
MAX_SIGNATURE_BYTES = 16 * 1024
MAX_SIGNER_ID_BYTES = 256
OPENSSL_TIMEOUT_SECONDS = 30
_DIGEST_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
_DATE_PATTERN = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}\Z")
_RSA_BITS_PATTERN = re.compile(r"Public-Key:\s*\((\d+) bit\)")


class SigningError(ValueError):
    """A corporate signing input or cryptographic verification is invalid."""


@dataclass(frozen=True, slots=True)
class CorporateSignature:
    statement: bytes
    signature: bytes
    public_key: bytes
    summary: dict[str, Any]


@dataclass(frozen=True, slots=True)
class CorporateSignatureVerification:
    statement: dict[str, Any]
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
            raise SigningError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _object(
    value: object,
    *,
    label: str,
    fields: frozenset[str],
) -> dict[str, Any]:
    if not isinstance(value, dict) or frozenset(value) != fields:
        raise SigningError(f"{label} must contain exactly {sorted(fields)}")
    return value


def _read_regular(
    path: str | os.PathLike[str],
    *,
    label: str,
    maximum: int,
) -> bytes:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise SigningError(f"cannot inspect {label}: {error}") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise SigningError(f"{label} must be a regular non-symlink file")
    if metadata.st_size > maximum:
        raise SigningError(f"{label} exceeds the {maximum}-byte limit")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise SigningError(f"{label} changed type while opening")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(maximum + 1)
    except SigningError:
        raise
    except OSError as error:
        raise SigningError(f"cannot read {label}: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > maximum:
        raise SigningError(f"{label} exceeds the {maximum}-byte limit")
    return raw


def _openssl_executable(value: str | os.PathLike[str] | None) -> Path:
    selected = str(value) if value is not None else shutil.which("openssl")
    if not selected:
        raise SigningError("OpenSSL is required for corporate signatures")
    try:
        executable = Path(selected).resolve(strict=True)
        metadata = executable.stat()
    except OSError as error:
        raise SigningError(f"cannot resolve OpenSSL executable: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or not os.access(executable, os.X_OK):
        raise SigningError("OpenSSL executable is not a regular executable file")
    return executable


def _run_openssl(
    executable: Path,
    arguments: list[str],
    *,
    input_bytes: bytes | None = None,
    passphrase: str | None = None,
    label: str,
) -> bytes:
    environment = {"LANG": "C", "LC_ALL": "C"}
    if passphrase is not None:
        if not passphrase or any(character in passphrase for character in "\x00\r\n"):
            raise SigningError(
                "private-key passphrase must be a non-empty single line"
            )
        environment["PGEXTASSURE_KEY_PASSPHRASE"] = passphrase
    try:
        result = subprocess.run(
            [str(executable), *arguments],
            input=input_bytes,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=OPENSSL_TIMEOUT_SECONDS,
            env=environment,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SigningError(f"{label}: OpenSSL could not complete") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", errors="replace")
        detail = " ".join(detail.split())[:512]
        raise SigningError(
            f"{label}: OpenSSL rejected the operation"
            + (f": {detail}" if detail else "")
        )
    return result.stdout


def _write_private_temporary(path: Path, raw: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb", closefd=True) as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())


def _public_material(
    executable: Path,
    key_raw: bytes,
    *,
    private: bool,
    passphrase: str | None = None,
) -> tuple[bytes, bytes, int]:
    with tempfile.TemporaryDirectory(prefix="pgextassure-key-") as directory:
        key_path = Path(directory) / ("private.pem" if private else "public.pem")
        _write_private_temporary(key_path, key_raw)
        command = ["pkey"]
        if not private:
            command.append("-pubin")
        command.extend(["-in", str(key_path), "-pubout", "-outform", "DER"])
        if private and passphrase is not None:
            command.extend(["-passin", "env:PGEXTASSURE_KEY_PASSPHRASE"])
        public_der = _run_openssl(
            executable,
            command,
            passphrase=passphrase,
            label="public-key derivation",
        )
        public_pem = _run_openssl(
            executable,
            [
                "pkey",
                "-pubin",
                "-inform",
                "DER",
                "-outform",
                "PEM",
            ],
            input_bytes=public_der,
            label="public-key encoding",
        )
        description = _run_openssl(
            executable,
            [
                "pkey",
                "-pubin",
                "-inform",
                "DER",
                "-text_pub",
                "-noout",
            ],
            input_bytes=public_der,
            label="public-key inspection",
        ).decode("utf-8", errors="replace")
    match = _RSA_BITS_PATTERN.search(description)
    if match is None or "Modulus:" not in description or "Exponent:" not in description:
        raise SigningError("corporate signing key must be RSA")
    bits = int(match.group(1))
    if bits < MINIMUM_RSA_BITS:
        raise SigningError(
            f"corporate signing key must be at least {MINIMUM_RSA_BITS} bits"
        )
    return public_der, public_pem, bits


def _verified_bundle(
    raw: bytes,
) -> tuple[dict[str, Any], str]:
    with tempfile.TemporaryDirectory(prefix="pgextassure-bundle-") as directory:
        bundle_path = Path(directory) / "evidence.zip"
        _write_private_temporary(bundle_path, raw)
        try:
            verification = verify_evidence_bundle(bundle_path)
        except EvidenceError as error:
            raise SigningError(f"Evidence Bundle verification failed: {error}") from error
    return (
        verification.summary,
        "sha256:" + hashlib.sha256(raw).hexdigest(),
    )


def _signer_id(value: str) -> str:
    if (
        not value
        or len(value.encode("utf-8")) > MAX_SIGNER_ID_BYTES
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise SigningError("signer ID must be bounded printable UTF-8")
    return value


def sign_evidence_bundle(
    bundle_path: str | os.PathLike[str],
    *,
    private_key_path: str | os.PathLike[str],
    signer_id: str,
    created_on: date,
    passphrase: str | None = None,
    openssl_path: str | os.PathLike[str] | None = None,
) -> CorporateSignature:
    """Verify and sign one Evidence Bundle using a corporate RSA key."""

    if type(created_on) is not date:
        raise SigningError("signature created_on must be a date")
    bundle = _read_regular(
        bundle_path,
        label="Evidence Bundle",
        maximum=MAX_BUNDLE_BYTES,
    )
    evidence, bundle_digest = _verified_bundle(bundle)
    private_key = _read_regular(
        private_key_path,
        label="private key",
        maximum=MAX_KEY_BYTES,
    )
    executable = _openssl_executable(openssl_path)
    public_der, public_pem, bits = _public_material(
        executable,
        private_key,
        private=True,
        passphrase=passphrase,
    )
    key_digest = "sha256:" + hashlib.sha256(public_der).hexdigest()
    statement_document = {
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "statement_type": STATEMENT_TYPE,
        "signature": {
            "profile": SIGNATURE_PROFILE,
            "public_key": {
                "algorithm": "RSA",
                "bits": bits,
                "format": "SubjectPublicKeyInfo",
                "sha256": key_digest,
            },
        },
        "signer": {"id": _signer_id(signer_id)},
        "created_on": created_on.isoformat(),
        "subject": {
            "media_type": "application/vnd.pgextassure.evidence+zip",
            "size": len(bundle),
            "digest": bundle_digest,
        },
        "evidence": {
            "schema_version": evidence["schema_version"],
            "gate": evidence["gate"],
            "manifest_digest": evidence["manifest_digest"],
            "coverage_digest": evidence["coverage_digest"],
            "policy_digest": evidence["policy_digest"],
        },
    }
    statement = _json_bytes(statement_document)
    with tempfile.TemporaryDirectory(prefix="pgextassure-sign-") as directory:
        private_path = Path(directory) / "private.pem"
        _write_private_temporary(private_path, private_key)
        command = [
            "dgst",
            "-sha256",
            "-sign",
            str(private_path),
            "-sigopt",
            "rsa_padding_mode:pss",
            "-sigopt",
            "rsa_pss_saltlen:digest",
            "-binary",
        ]
        if passphrase is not None:
            command.extend(["-passin", "env:PGEXTASSURE_KEY_PASSPHRASE"])
        signature = _run_openssl(
            executable,
            command,
            input_bytes=statement,
            passphrase=passphrase,
            label="corporate signature",
        )
    if not signature or len(signature) > MAX_SIGNATURE_BYTES:
        raise SigningError("OpenSSL returned an invalid signature size")
    return CorporateSignature(
        statement=statement,
        signature=signature,
        public_key=public_pem,
        summary={
            "schema_version": SIGNATURE_SCHEMA_VERSION,
            "valid": True,
            "signer_id": signer_id,
            "profile": SIGNATURE_PROFILE,
            "public_key_sha256": key_digest,
            "subject_digest": bundle_digest,
            "gate": evidence["gate"],
        },
    )


def _parse_statement(raw: bytes) -> dict[str, Any]:
    if len(raw) > MAX_STATEMENT_BYTES or b"\x00" in raw:
        raise SigningError("signature statement exceeds its safe input boundary")
    try:
        parsed = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs)
    except SigningError:
        raise
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError) as error:
        raise SigningError(f"invalid signature statement JSON: {error}") from error
    statement = _object(
        parsed,
        label="signature statement",
        fields=frozenset(
            {
                "schema_version",
                "statement_type",
                "signature",
                "signer",
                "created_on",
                "subject",
                "evidence",
            }
        ),
    )
    if raw != _json_bytes(statement):
        raise SigningError("signature statement is not canonically rendered")
    if (
        statement["schema_version"] != SIGNATURE_SCHEMA_VERSION
        or statement["statement_type"] != STATEMENT_TYPE
    ):
        raise SigningError("unsupported corporate signature statement")
    created_on = statement["created_on"]
    try:
        if not isinstance(created_on, str) or not _DATE_PATTERN.fullmatch(
            created_on
        ):
            raise ValueError
        date.fromisoformat(created_on)
    except (TypeError, ValueError) as error:
        raise SigningError("signature statement created_on is invalid") from error
    signer = _object(
        statement["signer"],
        label="signature signer",
        fields=frozenset({"id"}),
    )
    if not isinstance(signer["id"], str):
        raise SigningError("signature signer ID is invalid")
    _signer_id(signer["id"])
    signature = _object(
        statement["signature"],
        label="signature profile",
        fields=frozenset({"profile", "public_key"}),
    )
    if signature["profile"] != SIGNATURE_PROFILE:
        raise SigningError("unsupported corporate signature profile")
    public_key = _object(
        signature["public_key"],
        label="signature public key",
        fields=frozenset({"algorithm", "bits", "format", "sha256"}),
    )
    if (
        public_key["algorithm"] != "RSA"
        or type(public_key["bits"]) is not int
        or public_key["bits"] < MINIMUM_RSA_BITS
        or public_key["format"] != "SubjectPublicKeyInfo"
        or not isinstance(public_key["sha256"], str)
        or not _DIGEST_PATTERN.fullmatch(public_key["sha256"])
    ):
        raise SigningError("signature public-key metadata is invalid")
    subject = _object(
        statement["subject"],
        label="signature subject",
        fields=frozenset({"media_type", "size", "digest"}),
    )
    if (
        subject["media_type"] != "application/vnd.pgextassure.evidence+zip"
        or type(subject["size"]) is not int
        or not 0 < subject["size"] <= MAX_BUNDLE_BYTES
        or not isinstance(subject["digest"], str)
        or not _DIGEST_PATTERN.fullmatch(subject["digest"])
    ):
        raise SigningError("signature subject metadata is invalid")
    evidence = _object(
        statement["evidence"],
        label="signature evidence",
        fields=frozenset(
            {
                "schema_version",
                "gate",
                "manifest_digest",
                "coverage_digest",
                "policy_digest",
            }
        ),
    )
    if evidence["schema_version"] != "1.0" or evidence["gate"] not in {
        "pass",
        "blocked",
    }:
        raise SigningError("signature evidence metadata is invalid")
    for field in ("manifest_digest", "coverage_digest"):
        if (
            not isinstance(evidence[field], str)
            or not _DIGEST_PATTERN.fullmatch(evidence[field])
        ):
            raise SigningError(f"signature evidence {field} is invalid")
    if evidence["policy_digest"] is not None and (
        not isinstance(evidence["policy_digest"], str)
        or not _DIGEST_PATTERN.fullmatch(evidence["policy_digest"])
    ):
        raise SigningError("signature evidence policy_digest is invalid")
    return statement


def verify_evidence_signature(
    bundle_path: str | os.PathLike[str],
    *,
    statement_path: str | os.PathLike[str],
    signature_path: str | os.PathLike[str],
    public_key_path: str | os.PathLike[str],
    expected_public_key_sha256: str | None = None,
    openssl_path: str | os.PathLike[str] | None = None,
) -> CorporateSignatureVerification:
    """Verify the bundle, corporate statement, key identity, and signature."""

    bundle = _read_regular(
        bundle_path,
        label="Evidence Bundle",
        maximum=MAX_BUNDLE_BYTES,
    )
    evidence, bundle_digest = _verified_bundle(bundle)
    statement_raw = _read_regular(
        statement_path,
        label="signature statement",
        maximum=MAX_STATEMENT_BYTES,
    )
    statement = _parse_statement(statement_raw)
    signature_raw = _read_regular(
        signature_path,
        label="detached signature",
        maximum=MAX_SIGNATURE_BYTES,
    )
    if not signature_raw:
        raise SigningError("detached signature is empty")
    public_key_raw = _read_regular(
        public_key_path,
        label="public key",
        maximum=MAX_KEY_BYTES,
    )
    executable = _openssl_executable(openssl_path)
    public_der, public_pem, bits = _public_material(
        executable,
        public_key_raw,
        private=False,
    )
    key_digest = "sha256:" + hashlib.sha256(public_der).hexdigest()
    if expected_public_key_sha256 is not None:
        if not _DIGEST_PATTERN.fullmatch(expected_public_key_sha256):
            raise SigningError(
                "expected public-key SHA-256 must use sha256:<64 lowercase hex>"
            )
        if key_digest != expected_public_key_sha256:
            raise SigningError(
                "public key does not match the trusted expected fingerprint"
            )
    declared_key = statement["signature"]["public_key"]
    if key_digest != declared_key["sha256"] or bits != declared_key["bits"]:
        raise SigningError("public key does not match the signature statement")
    if statement["subject"] != {
        "media_type": "application/vnd.pgextassure.evidence+zip",
        "size": len(bundle),
        "digest": bundle_digest,
    }:
        raise SigningError("Evidence Bundle does not match the signature subject")
    if statement["evidence"] != {
        "schema_version": evidence["schema_version"],
        "gate": evidence["gate"],
        "manifest_digest": evidence["manifest_digest"],
        "coverage_digest": evidence["coverage_digest"],
        "policy_digest": evidence["policy_digest"],
    }:
        raise SigningError("Evidence Bundle metadata does not match the statement")

    with tempfile.TemporaryDirectory(prefix="pgextassure-verify-") as directory:
        public_path = Path(directory) / "public.pem"
        signature_file = Path(directory) / "signature.bin"
        _write_private_temporary(public_path, public_pem)
        _write_private_temporary(signature_file, signature_raw)
        _run_openssl(
            executable,
            [
                "dgst",
                "-sha256",
                "-verify",
                str(public_path),
                "-signature",
                str(signature_file),
                "-sigopt",
                "rsa_padding_mode:pss",
                "-sigopt",
                "rsa_pss_saltlen:digest",
            ],
            input_bytes=statement_raw,
            label="corporate signature verification",
        )
    summary = {
        "schema_version": SIGNATURE_SCHEMA_VERSION,
        "valid": True,
        "signer_id": statement["signer"]["id"],
        "created_on": statement["created_on"],
        "profile": SIGNATURE_PROFILE,
        "public_key_sha256": key_digest,
        "subject_digest": bundle_digest,
        "gate": evidence["gate"],
    }
    return CorporateSignatureVerification(statement=statement, summary=summary)
