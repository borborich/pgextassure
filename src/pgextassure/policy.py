"""Strict organization policy for deterministic admission gates."""

from __future__ import annotations

from dataclasses import dataclass, replace
import hashlib
from importlib.resources import files
import json
import os
from pathlib import Path
import re
import stat
from typing import Any

from .admission import Baseline, SuppressionSet, decision_map
from .grouping import group_findings
from .models import SEVERITY_RANK, ScanReport, Severity


MAX_POLICY_FILE_BYTES = 1024 * 1024
MAX_POLICY_LIST_ENTRIES = 256
POLICY_TEMPLATE_PROFILES = ("adoption", "strict")
_RULE_ID_PATTERN = re.compile(r"[a-z][a-z0-9.-]{0,127}\Z")
_CAPABILITY_PATTERN = re.compile(r"[a-z][a-z0-9._-]{0,127}\Z")


class PolicyError(ValueError):
    """An organization policy is malformed, stale, or cannot be enforced."""


def render_policy_template(profile: str) -> str:
    """Return one packaged, review-before-use organization policy template."""

    if profile not in POLICY_TEMPLATE_PROFILES:
        raise PolicyError(f"unknown policy template profile {profile!r}")
    try:
        return (
            files("pgextassure")
            .joinpath("policies", f"{profile}.json")
            .read_text(encoding="utf-8")
        )
    except (FileNotFoundError, OSError) as error:
        raise PolicyError(
            f"cannot read packaged policy template {profile!r}: {error}"
        ) from error


@dataclass(frozen=True, slots=True)
class GatePolicy:
    minimum_severity: Severity | None
    blocked_capabilities: tuple[str, ...]
    blocked_rules: tuple[str, ...]
    maximum_skipped_files: int | None


@dataclass(frozen=True, slots=True)
class AdmissionPolicy:
    allow_baseline: bool
    allow_suppressions: bool
    require_suppression_ticket: bool


@dataclass(frozen=True, slots=True)
class OrganizationPolicy:
    digest: str
    ruleset_version: str
    gate: GatePolicy
    admission: AdmissionPolicy


def _pairs_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _object(
    value: object,
    *,
    label: str,
    fields: frozenset[str],
) -> dict[str, object]:
    if not isinstance(value, dict):
        raise PolicyError(f"{label} must be an object")
    keys = frozenset(value)
    unknown = keys - fields
    missing = fields - keys
    if unknown:
        raise PolicyError(
            f"{label} contains unknown field {sorted(unknown)[0]!r}"
        )
    if missing:
        raise PolicyError(f"{label} is missing field {sorted(missing)[0]!r}")
    return value


def _string_list(
    value: object,
    *,
    label: str,
    pattern: re.Pattern[str],
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise PolicyError(f"{label} must be a list")
    if len(value) > MAX_POLICY_LIST_ENTRIES:
        raise PolicyError(
            f"{label} exceeds the {MAX_POLICY_LIST_ENTRIES}-entry limit"
        )
    result: list[str] = []
    seen: set[str] = set()
    for index, item in enumerate(value):
        if not isinstance(item, str) or not pattern.fullmatch(item):
            raise PolicyError(f"{label} entry {index} is invalid")
        if item in seen:
            raise PolicyError(f"{label} repeats {item!r}")
        seen.add(item)
        result.append(item)
    return tuple(result)


def _read_policy(path: str | os.PathLike[str]) -> bytes:
    candidate = Path(path)
    try:
        metadata = candidate.lstat()
    except OSError as error:
        raise PolicyError(f"cannot inspect policy: {error}") from error
    if stat.S_ISLNK(metadata.st_mode):
        raise PolicyError("policy must not be a symlink")
    if not stat.S_ISREG(metadata.st_mode):
        raise PolicyError("policy must be a regular file")
    if metadata.st_size > MAX_POLICY_FILE_BYTES:
        raise PolicyError(
            f"policy exceeds the {MAX_POLICY_FILE_BYTES}-byte limit"
        )
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    descriptor: int | None = None
    try:
        descriptor = os.open(candidate, flags)
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode):
            raise PolicyError("policy must remain a regular file")
        with os.fdopen(descriptor, "rb", closefd=True) as handle:
            descriptor = None
            raw = handle.read(MAX_POLICY_FILE_BYTES + 1)
    except PolicyError:
        raise
    except OSError as error:
        raise PolicyError(f"cannot read policy: {error}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(raw) > MAX_POLICY_FILE_BYTES:
        raise PolicyError(
            f"policy exceeds the {MAX_POLICY_FILE_BYTES}-byte limit"
        )
    if b"\x00" in raw:
        raise PolicyError("policy contains binary data")
    return raw


def load_policy(path: str | os.PathLike[str]) -> OrganizationPolicy:
    """Load a closed-schema policy without aliases or wildcard selectors."""

    raw = _read_policy(path)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise PolicyError("policy is not UTF-8") from error
    try:
        parsed = json.loads(text, object_pairs_hook=_pairs_object)
    except PolicyError:
        raise
    except (json.JSONDecodeError, RecursionError) as error:
        raise PolicyError(f"invalid policy JSON: {error}") from error
    document = _object(
        parsed,
        label="policy",
        fields=frozenset(
            {"schema_version", "ruleset_version", "gate", "admission"}
        ),
    )
    if document["schema_version"] != "1.0":
        raise PolicyError("policy schema_version must be '1.0'")
    ruleset_version = document["ruleset_version"]
    if (
        not isinstance(ruleset_version, str)
        or not ruleset_version
        or len(ruleset_version.encode("utf-8", errors="ignore")) > 128
    ):
        raise PolicyError("policy ruleset_version is invalid")
    gate = _object(
        document["gate"],
        label="policy gate",
        fields=frozenset(
            {
                "minimum_severity",
                "blocked_capabilities",
                "blocked_rules",
                "maximum_skipped_files",
            }
        ),
    )
    minimum_value = gate["minimum_severity"]
    if minimum_value == "none":
        minimum = None
    else:
        try:
            minimum = Severity(minimum_value)
        except (TypeError, ValueError) as error:
            raise PolicyError("policy minimum_severity is invalid") from error
    blocked_capabilities = _string_list(
        gate["blocked_capabilities"],
        label="policy blocked_capabilities",
        pattern=_CAPABILITY_PATTERN,
    )
    blocked_rules = _string_list(
        gate["blocked_rules"],
        label="policy blocked_rules",
        pattern=_RULE_ID_PATTERN,
    )
    maximum_skipped_files = gate["maximum_skipped_files"]
    if maximum_skipped_files is not None and (
        type(maximum_skipped_files) is not int
        or maximum_skipped_files < 0
        or maximum_skipped_files > 100_000
    ):
        raise PolicyError(
            "policy maximum_skipped_files must be null or an integer "
            "between 0 and 100000"
        )
    admission = _object(
        document["admission"],
        label="policy admission",
        fields=frozenset(
            {
                "allow_baseline",
                "allow_suppressions",
                "require_suppression_ticket",
            }
        ),
    )
    for field in (
        "allow_baseline",
        "allow_suppressions",
        "require_suppression_ticket",
    ):
        if type(admission[field]) is not bool:
            raise PolicyError(f"policy admission {field} must be a boolean")
    return OrganizationPolicy(
        digest="sha256:" + hashlib.sha256(raw).hexdigest(),
        ruleset_version=ruleset_version,
        gate=GatePolicy(
            minimum,
            blocked_capabilities,
            blocked_rules,
            maximum_skipped_files,
        ),
        admission=AdmissionPolicy(
            allow_baseline=admission["allow_baseline"],
            allow_suppressions=admission["allow_suppressions"],
            require_suppression_ticket=admission[
                "require_suppression_ticket"
            ],
        ),
    )


def apply_policy(
    report: ScanReport,
    policy: OrganizationPolicy,
    *,
    baseline: Baseline | None,
    suppressions: SuppressionSet | None,
) -> ScanReport:
    """Validate admission inputs and attach the policy gate decision."""

    if policy.ruleset_version != report.tool["ruleset_version"]:
        raise PolicyError(
            "policy ruleset_version does not match the scanner ruleset"
        )
    if baseline is not None and not policy.admission.allow_baseline:
        raise PolicyError("policy does not allow baselines")
    if suppressions is not None and not policy.admission.allow_suppressions:
        raise PolicyError("policy does not allow suppressions")
    if (
        suppressions is not None
        and policy.admission.require_suppression_ticket
    ):
        missing_ticket = next(
            (
                entry.root_cause_id
                for entry in suppressions.entries
                if entry.ticket is None
            ),
            None,
        )
        if missing_ticket is not None:
            raise PolicyError(
                "policy requires a ticket for suppression "
                f"{missing_ticket!r}"
            )

    decisions = decision_map(report)
    blocked: list[str] = []
    minimum_rank = (
        None
        if policy.gate.minimum_severity is None
        else SEVERITY_RANK[policy.gate.minimum_severity]
    )
    blocked_capabilities = set(policy.gate.blocked_capabilities)
    blocked_rules = set(policy.gate.blocked_rules)
    for group in group_findings(report.findings):
        status = decisions.get(group.root_cause_id, {}).get("status", "active")
        if status not in {"active", "expired"}:
            continue
        if (
            (
                minimum_rank is not None
                and SEVERITY_RANK[group.severity] >= minimum_rank
            )
            or group.capability in blocked_capabilities
            or group.rule_id in blocked_rules
        ):
            blocked.append(group.root_cause_id)

    skipped_count = len(report.coverage.skipped_files)
    coverage_violation = (
        policy.gate.maximum_skipped_files is not None
        and skipped_count > policy.gate.maximum_skipped_files
    )
    policy_document: dict[str, Any] = {
        "schema_version": "1.0",
        "digest": policy.digest,
        "ruleset_version": policy.ruleset_version,
        "gate": {
            "minimum_severity": (
                "none"
                if policy.gate.minimum_severity is None
                else policy.gate.minimum_severity.value
            ),
            "blocked_capabilities": list(policy.gate.blocked_capabilities),
            "blocked_rules": list(policy.gate.blocked_rules),
            "maximum_skipped_files": policy.gate.maximum_skipped_files,
        },
        "admission": {
            "allow_baseline": policy.admission.allow_baseline,
            "allow_suppressions": policy.admission.allow_suppressions,
            "require_suppression_ticket": (
                policy.admission.require_suppression_ticket
            ),
        },
        "result": {
            "blocked": bool(blocked) or coverage_violation,
            "blocked_count": len(blocked),
            "blocked_root_causes": blocked,
            "coverage_violation": coverage_violation,
            "skipped_count": skipped_count,
        },
    }
    return replace(report, policy=policy_document)
