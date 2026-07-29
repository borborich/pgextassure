"""Tiny stdlib-only PEP 517/660 backend for PgExtAssure.

The project intentionally has no runtime dependencies and must also install in
offline, freshly-created virtual environments that do not bundle setuptools.
This backend implements only the hooks needed to build this single pure-Python
distribution; it is not intended to be a general packaging framework.
"""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
from io import BytesIO, StringIO
from pathlib import Path
import tarfile
from typing import Iterable
import zipfile


NAME = "pgextassure"
VERSION = "0.1.0a11"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"
WHEEL_NAME = f"{NAME}-{VERSION}-py3-none-any.whl"
SDIST_NAME = f"{NAME}-{VERSION}.tar.gz"
PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = PROJECT_ROOT / "src"
PACKAGE_ROOT = SOURCE_ROOT / NAME
_ZIP_TIME = (1980, 1, 1, 0, 0, 0)


def _metadata() -> bytes:
    readme_path = PROJECT_ROOT / "README.md"
    description = (
        readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""
    )
    headers = (
        "Metadata-Version: 2.1\n"
        f"Name: {NAME}\n"
        f"Version: {VERSION}\n"
        "Summary: Static assurance scanner for PostgreSQL extensions\n"
        "Author: PgExtAssure contributors\n"
        "Requires-Python: >=3.11\n"
        "License: Apache-2.0\n"
        "Keywords: postgresql,security,static-analysis,extensions\n"
        "Classifier: Development Status :: 3 - Alpha\n"
        "Classifier: Environment :: Console\n"
        "Classifier: License :: OSI Approved :: Apache Software License\n"
        "Classifier: Programming Language :: Python :: 3 :: Only\n"
        "Classifier: Programming Language :: Python :: 3.11\n"
        "Classifier: Programming Language :: Python :: 3.12\n"
        "Classifier: Programming Language :: Python :: 3.13\n"
        "Classifier: Programming Language :: Python :: 3.14\n"
        "Classifier: Topic :: Database\n"
        "Classifier: Topic :: Security\n"
        "Project-URL: Homepage, https://github.com/borborich/pgextassure\n"
        "Project-URL: Repository, https://github.com/borborich/pgextassure\n"
        "Project-URL: Issues, https://github.com/borborich/pgextassure/issues\n"
        "Project-URL: Security Policy, "
        "https://github.com/borborich/pgextassure/security/policy\n"
        "Description-Content-Type: text/markdown\n"
        "\n"
    )
    return (headers + description).encode("utf-8")


def _wheel_metadata() -> bytes:
    return (
        "Wheel-Version: 1.0\n"
        "Generator: pgextassure-stdlib-backend 0.1\n"
        "Root-Is-Purelib: true\n"
        "Tag: py3-none-any\n"
    ).encode("utf-8")


def _entry_points() -> bytes:
    return b"[console_scripts]\npgextassure = pgextassure.cli:main\n"


def _hash(data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest())
    return digest.rstrip(b"=").decode("ascii")


def _record(files: dict[str, bytes]) -> bytes:
    output = StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    for path in sorted(files):
        data = files[path]
        writer.writerow((path, f"sha256={_hash(data)}", str(len(data))))
    writer.writerow((f"{DIST_INFO}/RECORD", "", ""))
    return output.getvalue().encode("utf-8")


def _base_wheel_files() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    for source in sorted(PACKAGE_ROOT.rglob("*.py")):
        if source.is_symlink() or not source.is_file():
            continue
        relative = source.relative_to(SOURCE_ROOT).as_posix()
        files[relative] = source.read_bytes()
    for source in sorted(PACKAGE_ROOT.rglob("*.json")):
        if source.is_symlink() or not source.is_file():
            continue
        relative = source.relative_to(SOURCE_ROOT).as_posix()
        files[relative] = source.read_bytes()
    schema_root = PROJECT_ROOT / "schemas"
    for source in sorted(schema_root.glob("*.json")):
        files[f"{NAME}/schemas/{source.name}"] = source.read_bytes()
    files[f"{DIST_INFO}/METADATA"] = _metadata()
    files[f"{DIST_INFO}/WHEEL"] = _wheel_metadata()
    files[f"{DIST_INFO}/entry_points.txt"] = _entry_points()
    license_path = PROJECT_ROOT / "LICENSE"
    if license_path.exists():
        files[f"{DIST_INFO}/LICENSE"] = license_path.read_bytes()
    return files


def _write_zip(path: Path, files: dict[str, bytes]) -> None:
    files = dict(files)
    files[f"{DIST_INFO}/RECORD"] = _record(files)
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(
        path, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name in sorted(files):
            info = zipfile.ZipInfo(name, date_time=_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o100644 << 16
            archive.writestr(info, files[name])


def get_requires_for_build_wheel(config_settings=None) -> list[str]:
    return []


def get_requires_for_build_editable(config_settings=None) -> list[str]:
    return []


def get_requires_for_build_sdist(config_settings=None) -> list[str]:
    return []


def prepare_metadata_for_build_wheel(
    metadata_directory: str, config_settings=None
) -> str:
    target = Path(metadata_directory) / DIST_INFO
    target.mkdir(parents=True, exist_ok=True)
    (target / "METADATA").write_bytes(_metadata())
    (target / "WHEEL").write_bytes(_wheel_metadata())
    (target / "entry_points.txt").write_bytes(_entry_points())
    license_path = PROJECT_ROOT / "LICENSE"
    if license_path.exists():
        (target / "LICENSE").write_bytes(license_path.read_bytes())
    return DIST_INFO


def prepare_metadata_for_build_editable(
    metadata_directory: str, config_settings=None
) -> str:
    return prepare_metadata_for_build_wheel(metadata_directory, config_settings)


def build_wheel(
    wheel_directory: str, config_settings=None, metadata_directory=None
) -> str:
    destination = Path(wheel_directory) / WHEEL_NAME
    _write_zip(destination, _base_wheel_files())
    return WHEEL_NAME


def build_editable(
    wheel_directory: str, config_settings=None, metadata_directory=None
) -> str:
    files = {
        "_pgextassure_editable.pth": (str(SOURCE_ROOT.resolve()) + "\n").encode(
            "utf-8"
        ),
        f"{DIST_INFO}/METADATA": _metadata(),
        f"{DIST_INFO}/WHEEL": _wheel_metadata(),
        f"{DIST_INFO}/entry_points.txt": _entry_points(),
    }
    license_path = PROJECT_ROOT / "LICENSE"
    if license_path.exists():
        files[f"{DIST_INFO}/LICENSE"] = license_path.read_bytes()
    destination = Path(wheel_directory) / WHEEL_NAME
    _write_zip(destination, files)
    return WHEEL_NAME


def _sdist_sources() -> Iterable[tuple[Path, str]]:
    top_level = (
        ".dockerignore",
        "Dockerfile",
        "pyproject.toml",
        "README.md",
        "LICENSE",
        "action.yml",
        "CHANGELOG.md",
        "CODE_OF_CONDUCT.md",
        "CONTRIBUTING.md",
        "SECURITY.md",
        "SUPPORT.md",
    )
    for name in top_level:
        source = PROJECT_ROOT / name
        if source.is_file():
            yield source, name
    for directory in (
        "src",
        "tests",
        "docs",
        "schemas",
        "examples",
        "admission",
        "deploy",
        "docker",
        "integration",
    ):
        root = PROJECT_ROOT / directory
        if not root.exists():
            continue
        for source in sorted(root.rglob("*")):
            relative = source.relative_to(PROJECT_ROOT)
            if (
                not source.is_file()
                or source.is_symlink()
                or any(part.startswith(".") for part in relative.parts)
                or "__pycache__" in source.parts
                or source.suffix in {".pyc", ".pyo"}
            ):
                continue
            yield source, relative.as_posix()


def build_sdist(sdist_directory: str, config_settings=None) -> str:
    destination = Path(sdist_directory) / SDIST_NAME
    destination.parent.mkdir(parents=True, exist_ok=True)
    prefix = f"{NAME}-{VERSION}"
    with destination.open("wb") as raw:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9
        ) as compressed:
            with tarfile.open(fileobj=compressed, mode="w") as archive:
                for source, relative in _sdist_sources():
                    info = archive.gettarinfo(
                        str(source), arcname=f"{prefix}/{relative}"
                    )
                    info.uid = info.gid = 0
                    info.uname = info.gname = ""
                    info.mtime = 0
                    with source.open("rb") as handle:
                        archive.addfile(info, handle)
                package_info = _metadata()
                info = tarfile.TarInfo(f"{prefix}/PKG-INFO")
                info.size = len(package_info)
                info.mode = 0o644
                info.mtime = 0
                archive.addfile(info, BytesIO(package_info))
    return SDIST_NAME
