from __future__ import annotations

import dataclasses
import json
import os
import subprocess
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any


TESTS_ROOT = Path(__file__).resolve().parent
PROJECT_ROOT = TESTS_ROOT.parent
FIXTURES_ROOT = TESTS_ROOT / "fixtures"
SAFE_ROOT = FIXTURES_ROOT / "safe"
VULNERABLE_ROOT = FIXTURES_ROOT / "vulnerable"
UPGRADE_ROOT = FIXTURES_ROOT / "upgrade"


def scan(path: Path) -> Any:
    """Call the public Python API without depending on report implementation details."""
    from pgextassure.scanner import scan_path

    return scan_path(path)


def findings_from(report: Any) -> list[Any]:
    if isinstance(report, Mapping):
        value = report.get("findings", [])
    else:
        value = getattr(report, "findings", [])

    if value is None:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, tuple):
        return list(value)
    if isinstance(value, Iterable) and not isinstance(value, (str, bytes)):
        return list(value)
    raise AssertionError(f"report.findings is not iterable: {type(value)!r}")


def to_plain(value: Any) -> Any:
    if dataclasses.is_dataclass(value):
        return {field.name: to_plain(getattr(value, field.name)) for field in dataclasses.fields(value)}
    if isinstance(value, Mapping):
        return {str(key): to_plain(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [to_plain(item) for item in value]
    if isinstance(value, Path):
        return value.as_posix()
    if hasattr(value, "value") and not isinstance(value, (str, bytes)):
        return to_plain(value.value)
    return value


def finding_text(finding: Any) -> str:
    """Flatten a finding so tests tolerate dataclass/dict report representations."""
    plain = to_plain(finding)

    def strings(value: Any) -> Iterable[str]:
        if isinstance(value, str):
            yield value
        elif isinstance(value, Mapping):
            for key, item in value.items():
                yield str(key)
                yield from strings(item)
        elif isinstance(value, list):
            for item in value:
                yield from strings(item)
        elif value is not None:
            yield str(value)

    return " ".join(strings(plain)).casefold()


def findings_matching(report: Any, *needles: str) -> list[Any]:
    wanted = tuple(needle.casefold() for needle in needles)
    return [
        finding
        for finding in findings_from(report)
        if all(needle in finding_text(finding) for needle in wanted)
    ]


def finding_field(finding: Any, name: str, default: Any = None) -> Any:
    if isinstance(finding, Mapping):
        return finding.get(name, default)
    return getattr(finding, name, default)


def rule_ids_from(report: Any) -> list[str]:
    return [
        str(finding_field(finding, "rule_id", ""))
        for finding in findings_from(report)
    ]


def run_cli(*args: str) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env["PYTHONHASHSEED"] = "0"
    env["NO_COLOR"] = "1"
    return subprocess.run(
        [sys.executable, "-m", "pgextassure", *args],
        cwd=PROJECT_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )


def parse_json_stdout(result: subprocess.CompletedProcess[str]) -> Any:
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise AssertionError(
            "CLI did not emit valid JSON.\n"
            f"exit={result.returncode}\nstdout={result.stdout!r}\nstderr={result.stderr!r}"
        ) from error
