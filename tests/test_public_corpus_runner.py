"""Contract tests for the opt-in public corpus runner."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import shutil
import sys
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RUNNER_PATH = PROJECT_ROOT / "tools" / "run_public_corpus.py"
SPEC = importlib.util.spec_from_file_location(
    "pgextassure_public_corpus_runner",
    RUNNER_PATH,
)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError(f"cannot import corpus runner from {RUNNER_PATH}")
RUNNER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = RUNNER
SPEC.loader.exec_module(RUNNER)


COMMIT = "1" * 40
HEADER = "repository\turl\tcommit\tcommit_date\tscan_path\n"


class PublicCorpusRunnerTests(unittest.TestCase):
    def _manifest(self, root: Path, row: str) -> Path:
        manifest = root / "manifest.tsv"
        manifest.write_text(HEADER + row + "\n", encoding="utf-8")
        return manifest

    def test_normalized_output_omits_evidence_and_is_deterministic(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_root = root / "corpus"
            checkout = corpus_root / "sample"
            shutil.copytree(
                PROJECT_ROOT / "tests" / "fixtures" / "safe",
                checkout,
            )
            manifest = self._manifest(
                root,
                (
                    "sample\thttps://github.com/example/sample.git\t"
                    f"{COMMIT}\t2026-07-28\t."
                ),
            )
            output = root / "normalized"

            with patch.object(RUNNER, "_git_head", return_value=COMMIT):
                first = RUNNER.run_corpus(corpus_root, manifest, output)
                first_json = (output / "summary.json").read_bytes()
                second = RUNNER.run_corpus(corpus_root, manifest, output)
                second_json = (output / "summary.json").read_bytes()

            self.assertEqual(0, first)
            self.assertEqual(0, second)
            self.assertEqual(first_json, second_json)
            self.assertNotIn(b'"evidence"', first_json)
            document = json.loads(first_json)
            record = document["corpus"][0]
            self.assertEqual("ok", record["status"])
            self.assertEqual(6, record["files_scanned"])
            self.assertEqual(0, record["findings"])
            self.assertEqual(0, record["root_causes"])
            self.assertEqual(
                {"critical": 0, "high": 0, "medium": 0, "low": 0},
                record["root_causes_by_severity"],
            )
            self.assertEqual({}, record["rule_counts"])
            self.assertEqual({}, record["root_cause_rule_counts"])
            self.assertFalse((output / "sample.json").exists())

    def test_raw_reports_require_explicit_directory(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_root = root / "corpus"
            checkout = corpus_root / "sample"
            shutil.copytree(
                PROJECT_ROOT / "tests" / "fixtures" / "vulnerable",
                checkout,
            )
            manifest = self._manifest(
                root,
                (
                    "sample\thttps://github.com/example/sample.git\t"
                    f"{COMMIT}\t2026-07-28\t."
                ),
            )
            raw = root / "private-raw"

            with patch.object(RUNNER, "_git_head", return_value=COMMIT):
                result = RUNNER.run_corpus(
                    corpus_root,
                    manifest,
                    root / "normalized",
                    raw_report_dir=raw,
                )

            self.assertEqual(0, result)
            report = json.loads((raw / "sample.json").read_text())
            self.assertGreater(len(report["findings"]), 0)
            self.assertIn("evidence", report["findings"][0])

    def test_revision_mismatch_fails_before_scanning(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_root = root / "corpus"
            (corpus_root / "sample").mkdir(parents=True)
            manifest = self._manifest(
                root,
                (
                    "sample\thttps://github.com/example/sample.git\t"
                    f"{COMMIT}\t2026-07-28\t."
                ),
            )

            with (
                patch.object(RUNNER, "_git_head", return_value="2" * 40),
                patch.object(RUNNER, "scan_path") as scanner,
            ):
                with self.assertRaisesRegex(
                    RUNNER.CorpusError,
                    "expected",
                ):
                    RUNNER.run_corpus(
                        corpus_root,
                        manifest,
                        root / "normalized",
                    )
            scanner.assert_not_called()

    def test_manifest_rejects_checkout_traversal(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = self._manifest(
                root,
                (
                    "sample\thttps://github.com/example/sample.git\t"
                    f"{COMMIT}\t2026-07-28\t../outside"
                ),
            )

            with self.assertRaisesRegex(
                RUNNER.CorpusError,
                "stay inside checkout",
            ):
                RUNNER.load_manifest(manifest)

    def test_scan_error_is_normalized_without_path_or_message(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus_root = root / "corpus"
            checkout = corpus_root / "sample"
            checkout.mkdir(parents=True)
            manifest = self._manifest(
                root,
                (
                    "sample\thttps://github.com/example/sample.git\t"
                    f"{COMMIT}\t2026-07-28\t."
                ),
            )
            output = root / "normalized"
            error = RUNNER.ScanInputError(
                "refusing symlinked directory in scan tree: secret/path"
            )

            with (
                patch.object(RUNNER, "_git_head", return_value=COMMIT),
                patch.object(RUNNER, "scan_path", side_effect=error),
            ):
                result = RUNNER.run_corpus(
                    corpus_root,
                    manifest,
                    output,
                )

            self.assertEqual(1, result)
            raw = (output / "summary.json").read_text()
            self.assertNotIn("secret/path", raw)
            record = json.loads(raw)["corpus"][0]
            self.assertEqual("scan_error", record["status"])
            self.assertEqual("ScanInputError", record["error_type"])
            self.assertEqual("symlinked_directory", record["error_code"])


if __name__ == "__main__":
    unittest.main()
