"""Release metadata and source-distribution contract tests."""

import os
from pathlib import Path, PurePosixPath
from tempfile import TemporaryDirectory
import tomllib
import unittest
from unittest.mock import patch

from pgextassure import __release_version__, __version__
from pgextassure import _build_backend
from pgextassure.scanner import TOOL_VERSION


PROJECT_ROOT = Path(__file__).resolve().parents[1]


class PackagingContractTests(unittest.TestCase):
    def test_release_versions_are_synchronized(self) -> None:
        configuration = tomllib.loads(
            (PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        )

        self.assertEqual(configuration["project"]["version"], __version__)
        self.assertEqual(__version__, _build_backend.VERSION)
        self.assertEqual("0.1.0-alpha.4", __release_version__)
        self.assertEqual(__release_version__, TOOL_VERSION)

    def test_sdist_omits_hidden_worktree_files(self) -> None:
        relative_paths = [
            PurePosixPath(relative)
            for _source, relative in _build_backend._sdist_sources()
        ]

        self.assertTrue(relative_paths)
        for relative in relative_paths:
            self.assertFalse(
                any(part.startswith(".") for part in relative.parts),
                f"hidden path leaked into the source distribution: {relative}",
            )

    def test_wheel_metadata_keeps_public_project_fields(self) -> None:
        metadata = _build_backend._metadata().decode("utf-8")

        self.assertIn("Author: PgExtAssure contributors\n", metadata)
        self.assertIn(
            "Keywords: postgresql,security,static-analysis,extensions\n",
            metadata,
        )
        self.assertIn(
            "Classifier: Development Status :: 3 - Alpha\n",
            metadata,
        )
        self.assertIn(
            "Project-URL: Security Policy, "
            "https://github.com/borborich/pgextassure/security/policy\n",
            metadata,
        )

    def test_wheel_and_sdist_include_published_schemas(self) -> None:
        wheel_files = _build_backend._base_wheel_files()
        sdist_paths = {
            relative for _source, relative in _build_backend._sdist_sources()
        }

        self.assertIn(
            "pgextassure/schemas/scan-report-1.3.schema.json",
            wheel_files,
        )
        self.assertIn(
            "pgextassure/schemas/policy-1.0.schema.json",
            wheel_files,
        )
        self.assertIn(
            "pgextassure/policies/adoption.json",
            wheel_files,
        )
        self.assertIn(
            "pgextassure/policies/strict.json",
            wheel_files,
        )
        self.assertIn(
            "schemas/scan-report-1.3.schema.json",
            sdist_paths,
        )
        self.assertIn(
            "schemas/evidence-bundle-1.0.schema.json",
            sdist_paths,
        )
        self.assertIn(
            "examples/enterprise/policy.json",
            sdist_paths,
        )
        self.assertIn(
            "examples/enterprise/pgextassure.yml",
            sdist_paths,
        )

    @unittest.skipUnless(hasattr(os, "symlink"), "requires filesystem symlinks")
    def test_wheel_omits_symlinked_python_sources(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "src"
            package_root = source_root / "pgextassure"
            package_root.mkdir(parents=True)
            (package_root / "safe.py").write_bytes(b"SAFE_SOURCE = True\n")
            outside = root / "outside.py"
            outside.write_bytes(b"EXTERNAL_SECRET = True\n")
            (package_root / "leak.py").symlink_to(outside)

            with (
                patch.object(_build_backend, "SOURCE_ROOT", source_root),
                patch.object(_build_backend, "PACKAGE_ROOT", package_root),
            ):
                files = _build_backend._base_wheel_files()

            self.assertEqual(
                b"SAFE_SOURCE = True\n",
                files["pgextassure/safe.py"],
            )
            self.assertNotIn("pgextassure/leak.py", files)
            self.assertNotIn(outside.read_bytes(), files.values())


if __name__ == "__main__":
    unittest.main()
