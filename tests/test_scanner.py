from __future__ import annotations

import os
import sys
import unittest
from tempfile import TemporaryDirectory
from pathlib import Path
from unittest.mock import patch

from pgextassure.graph import _has_cycle
from pgextassure.scanner import ScanError, ScanInputError, scan_path
from pgextassure.source import (
    mask_psql_meta_commands,
    mask_sql_comments,
    mask_sql_dollar_bodies,
    mask_sql_literals_and_comments,
    sql_statements,
)

from tests.support import (
    SAFE_ROOT,
    UPGRADE_ROOT,
    VULNERABLE_ROOT,
    finding_field,
    findings_from,
    rule_ids_from,
    scan,
)


class ScannerContractTests(unittest.TestCase):
    def assert_has_rule(self, path: Path, rule_id: str) -> None:
        report = scan(path)
        self.assertIn(
            rule_id,
            rule_ids_from(report),
            f"expected {rule_id!r} for {path}; got {rule_ids_from(report)!r}",
        )

    def test_coverage_lists_every_skipped_regular_file_without_hashing_it(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.sql").write_text("SELECT 1;\n", encoding="utf-8")
            (root / "README.md").write_text("documentation\n", encoding="utf-8")
            (root / "image.bin").write_bytes(b"\x00\x01")

            report = scan_path(root)
            coverage = report.coverage.to_dict()

        self.assertEqual(1, coverage["analyzed_files"])
        self.assertEqual(2, coverage["skipped_count"])
        self.assertEqual(
            [
                {
                    "path": "README.md",
                    "kind": "regular",
                    "reason": "unsupported_file_type",
                    "size": 14,
                },
                {
                    "path": "image.bin",
                    "kind": "regular",
                    "reason": "unsupported_file_type",
                    "size": 2,
                },
            ],
            coverage["skipped_files"],
        )
        self.assertRegex(coverage["digest"], r"^sha256:[0-9a-f]{64}$")

    @unittest.skipUnless(hasattr(os, "symlink"), "requires filesystem symlinks")
    def test_coverage_records_unsupported_symlink_without_following_it(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.sql").write_text("SELECT 1;\n", encoding="utf-8")
            target = root / "notes.txt"
            target.write_text("not analyzed\n", encoding="utf-8")
            (root / "alias.txt").symlink_to(target.name)

            report = scan_path(root)

        skipped = {
            item.path: item.to_dict() for item in report.coverage.skipped_files
        }
        self.assertEqual("unsupported_symlink", skipped["alias.txt"]["reason"])
        self.assertNotIn("size", skipped["alias.txt"])

    def test_safe_fixture_tree_has_no_findings(self) -> None:
        report = scan(SAFE_ROOT)
        self.assertEqual(
            [],
            findings_from(report),
            "safe fixtures, including keyword-like comments and strings, must be quiet",
        )

    def test_sql_comments_and_string_literals_do_not_trigger_rules(self) -> None:
        report = scan(SAFE_ROOT / "sql" / "ordinary_copy.sql")
        self.assertEqual([], findings_from(report))

    def test_c_comments_and_string_literals_do_not_trigger_rules(self) -> None:
        report = scan(SAFE_ROOT / "c" / "safe_extension.c")
        self.assertEqual([], findings_from(report))

    def test_rust_comments_and_string_literals_do_not_trigger_rules(self) -> None:
        report = scan(SAFE_ROOT / "rust" / "src" / "lib.rs")
        self.assertEqual([], findings_from(report))

    def test_control_file_flags_privileged_install(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "control" / "dangerous.control",
            "control.superuser-required",
        )

    def test_control_file_exposes_all_seeded_risk_signals(self) -> None:
        report = scan(VULNERABLE_ROOT / "control" / "dangerous.control")
        self.assertTrue(
            {
                "control.superuser-required",
                "control.trusted-install",
                "control.relocatable",
                "control.risky-requirement",
            }.issubset(set(rule_ids_from(report))),
            rule_ids_from(report),
        )

    def test_control_boolean_prefixes_match_postgresql(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "prefixes.control"
            path.write_text(
                "default_version = '1'\n"
                "superuser = f\n"
                "trusted = tr\n",
                encoding="utf-8",
            )

            rules = rule_ids_from(scan(path))

        self.assertIn("control.trusted-install", rules)
        self.assertNotIn("control.superuser-required", rules)

    def test_quoted_risky_control_requirement_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "requires.control"
            path.write_text(
                "superuser = false\n"
                "requires = '\"dblink\"'\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "control.risky-requirement")

    def test_control_include_directive_is_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "included.control"
            path.write_text(
                "superuser = false\ninclude 'hidden.conf'\n",
                encoding="utf-8",
            )
            (root / "hidden.conf").write_text(
                "trusted = true\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "control.external-include")

    def test_control_assignment_equals_is_optional(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "optional-equals.control"
            path.write_text(
                "default_version '2'\n"
                "superuser false\n"
                "trusted true\n"
                "requires dblink\n",
                encoding="utf-8",
            )
            (root / "optional-equals--1.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            rules = rule_ids_from(scan(root))

        self.assertIn("control.trusted-install", rules)
        self.assertIn("control.risky-requirement", rules)
        self.assertNotIn("control.superuser-required", rules)
        self.assertIn("update.install-script-missing", rules)

    def test_control_quoted_backslash_escapes_are_decoded(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "escaped.control"
            path.write_text(
                "superuser false\n"
                r"trusted 'tr\ue'" + "\n"
                r"requires 'd\142link'" + "\n",
                encoding="utf-8",
            )

            rules = rule_ids_from(scan(path))

        self.assertIn("control.trusted-install", rules)
        self.assertIn("control.risky-requirement", rules)

    def test_security_definer_without_safe_search_path_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "sql" / "security_definer.sql",
            "sql.security-definer-search-path",
        )

    def test_copy_program_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "sql" / "copy_program.sql",
            "sql.copy-program",
        )

    def test_copy_server_file_access_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "sql" / "copy_file.sql",
            "sql.copy-file",
        )

    def test_untrusted_procedural_languages_are_flagged(self) -> None:
        report = scan(VULNERABLE_ROOT / "sql" / "untrusted_languages.sql")
        rule_ids = rule_ids_from(report)
        self.assertGreaterEqual(
            rule_ids.count("sql.untrusted-language"),
            2,
            f"expected both PL/Python and PL/Perl findings, got {rule_ids!r}",
        )

    def test_public_function_execution_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "sql" / "public_execute.sql",
            "sql.public-execute",
        )

    def test_c_file_access_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "c" / "dangerous_extension.c",
            "c.file-io",
        )

    def test_posix_open_is_flagged_as_native_file_access(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "open_file.c"
            path.write_text(
                'int fd = open("/etc/passwd", O_RDONLY);\n',
                encoding="utf-8",
            )

            self.assert_has_rule(path, "c.file-io")

    def test_c_network_access_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "c" / "dangerous_extension.c",
            "c.network",
        )

    def test_c_process_execution_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "c" / "dangerous_extension.c",
            "c.process-exec",
        )

    def test_c_background_worker_registration_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "c" / "dangerous_extension.c",
            "c.background-worker",
        )

    def test_rust_unsafe_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "rust" / "src" / "lib.rs",
            "rust.unsafe",
        )

    def test_rust_process_execution_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "rust" / "src" / "lib.rs",
            "rust.process-exec",
        )

    def test_rust_network_access_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "rust" / "src" / "lib.rs",
            "rust.network",
        )

    def test_rust_file_access_is_flagged(self) -> None:
        self.assert_has_rule(
            VULNERABLE_ROOT / "rust" / "src" / "lib.rs",
            "rust.file-io",
        )

    def test_rust_lifetime_does_not_mask_process_execution(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "lifetime.rs"
            path.write_text(
                "fn run<'a>(_value: &'a str) {\n"
                '    std::process::Command::new("id");\n'
                "}\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "rust.process-exec")

    def test_plain_sql_backslash_does_not_mask_following_statement(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "standard-string.sql"
            path.write_text(
                "SELECT '\\'; SELECT pg_read_file('/etc/passwd');\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.server-file-function")

    def test_non_ascii_identifier_does_not_enable_escape_prefix(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "non-ascii-prefix.sql"
            path.write_text(
                "CREATE DOMAIN ©E AS text; "
                "SELECT ©E'\\'; COPY demo TO '/tmp/x';\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.copy-file")

    def test_sql_cr_line_comment_does_not_hide_following_copy(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "cr-comment.sql"
            path.write_text(
                "-- harmless\rCOPY demo TO '/tmp/x';",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.copy-file")

    def test_identifier_embedded_dollar_tag_does_not_open_body(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "identifier-dollar.sql"
            path.write_text(
                "SELECT foo$tag$; COPY demo TO '/tmp/x';",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.copy-file")

    def test_newline_concatenated_escape_mode_keeps_semicolons_quoted(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            text = (
                "SELECT E'x'\n"
                "'abc\\';hidden;xyz'; "
                "COPY demo TO '/tmp/x';"
            )
            statements = list(sql_statements(text))
            self.assertEqual(2, len(statements), statements)
            self.assertIn(";hidden;xyz'", statements[0][1])
            self.assertTrue(
                statements[1][1].lstrip().startswith("COPY demo"),
                statements,
            )

            path = root / "continued.sql"
            path.write_text(text, encoding="utf-8")
            self.assert_has_rule(path, "sql.copy-file")

    def test_dollar_body_masker_is_quote_and_comment_aware(self) -> None:
        text = (
            "SELECT '$tag$quoted$tag$', E'$escape$quoted$escape$'; "
            "-- $comment$ignored$comment$\r\n"
            "/* $block$ignored$block$ */ "
            "AS $body$ SELECT 1; $body$;"
        )

        masked = mask_sql_dollar_bodies(text)

        self.assertEqual(len(text), len(masked))
        self.assertIn("'$tag$quoted$tag$'", masked)
        self.assertIn("E'$escape$quoted$escape$'", masked)
        self.assertIn("$comment$ignored$comment$", masked)
        self.assertIn("$block$ignored$block$", masked)
        self.assertNotIn("$body$ SELECT 1; $body$", masked)

    def test_sql_masking_preserves_cr_lf_offsets(self) -> None:
        text = (
            "-- comment\r\nSELECT 'value';\r"
            "\\echo ignored\nCOPY demo TO '/tmp/x';"
        )
        line_breaks = [
            (index, character)
            for index, character in enumerate(text)
            if character in {"\r", "\n"}
        ]

        for masker in (
            mask_sql_comments,
            mask_sql_literals_and_comments,
            mask_psql_meta_commands,
        ):
            with self.subTest(masker=masker.__name__):
                masked = masker(text)
                self.assertEqual(len(text), len(masked))
                self.assertEqual(
                    line_breaks,
                    [
                        (index, character)
                        for index, character in enumerate(masked)
                        if character in {"\r", "\n"}
                    ],
                )

    def test_copy_escape_strings_are_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            program = root / "program.sql"
            file_path = root / "file.sql"
            program.write_text(
                "COPY demo FROM PROGRAM E'id';\n",
                encoding="utf-8",
            )
            file_path.write_text(
                "COPY demo TO E'/tmp/export.csv';\n",
                encoding="utf-8",
            )

            self.assert_has_rule(program, "sql.copy-program")
            self.assert_has_rule(file_path, "sql.copy-file")

    def test_copy_dollar_and_unicode_strings_are_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            dollar_program = root / "dollar-program.sql"
            dollar_file = root / "dollar-file.sql"
            unicode_program = root / "unicode-program.sql"
            dollar_program.write_text(
                "COPY demo FROM PROGRAM $$id$$;\n",
                encoding="utf-8",
            )
            dollar_file.write_text(
                "COPY demo TO $path$/tmp/export.csv$path$;\n",
                encoding="utf-8",
            )
            unicode_program.write_text(
                "COPY demo FROM PROGRAM U&'id';\n",
                encoding="utf-8",
            )

            self.assert_has_rule(dollar_program, "sql.copy-program")
            self.assert_has_rule(dollar_file, "sql.copy-file")
            self.assert_has_rule(unicode_program, "sql.copy-program")

    def test_copy_unicode_dollar_tag_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "unicode-dollar.sql"
            path.write_text(
                "COPY demo TO $тег$/tmp/export.csv$тег$;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.copy-file")

    def test_unicode_dollar_body_is_not_split_into_statements(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "unicode-dollar-body.sql"
            path.write_text(
                "CREATE FUNCTION public.safe() RETURNS text "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "AS $тег$ SELECT '; LANGUAGE plpython3u' $тег$;\n"
                "REVOKE ALL ON FUNCTION public.safe() FROM PUBLIC;\n",
                encoding="utf-8",
            )

            report = scan(path)

        self.assertEqual([], findings_from(report))

    def test_public_routine_grants_cover_all_and_later_grantees(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "public-grants.sql"
            path.write_text(
                "GRANT ALL ON FUNCTION public.one() TO PUBLIC;\n"
                "GRANT EXECUTE ON FUNCTION public.two() TO app, PUBLIC;\n",
                encoding="utf-8",
            )

            report = scan(path)

        self.assertGreaterEqual(
            rule_ids_from(report).count("sql.public-execute"),
            2,
        )

    def test_psql_guard_line_does_not_hide_following_sql(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            copy_path = root / "guarded-copy.sql"
            grant_path = root / "guarded-grant.sql"
            guard = "\\echo Use CREATE EXTENSION instead. \\quit\n"
            copy_path.write_text(
                guard + "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            grant_path.write_text(
                guard + "GRANT EXECUTE ON FUNCTION public.f() TO PUBLIC;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(copy_path, "sql.copy-program")
            self.assert_has_rule(grant_path, "sql.public-execute")

    def test_psql_guard_recognizes_all_postgresql_line_endings(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for index, line_ending in enumerate(("\r", "\n", "\r\n")):
                with self.subTest(line_ending=repr(line_ending)):
                    path = root / f"guard-{index}.sql"
                    path.write_text(
                        "\\echo guard"
                        + line_ending
                        + "COPY demo TO '/tmp/x';",
                        encoding="utf-8",
                    )
                    self.assert_has_rule(path, "sql.copy-file")

    def test_psql_copy_statements_recognize_all_line_endings(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            for index, line_ending in enumerate(("\r", "\n", "\r\n")):
                with self.subTest(line_ending=repr(line_ending)):
                    prefix = "\\copy demo FROM STDIN" + line_ending
                    text = prefix + "COPY demo TO '/tmp/x';"
                    statements = list(sql_statements(text))
                    self.assertEqual(2, len(statements), statements)
                    self.assertEqual((0, prefix), statements[0])
                    self.assertEqual(len(prefix), statements[1][0])

                    path = root / f"copy-{index}.sql"
                    path.write_text(text, encoding="utf-8")
                    self.assert_has_rule(path, "sql.copy-file")

    def test_psql_like_text_inside_multiline_literal_is_not_a_command(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "literal-command.sql"
            path.write_text(
                "SELECT 'harmless\n"
                "\\echo not-a-command';\n"
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.copy-program")

    def test_line_terminated_psql_copy_does_not_hide_following_sql(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "psql-copy-then-grant.sql"
            path.write_text(
                "\\copy demo FROM STDIN\n"
                "GRANT EXECUTE ON FUNCTION public.f() TO PUBLIC;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.public-execute")

    def test_quoted_server_file_function_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-function.sql"
            path.write_text(
                'SELECT pg_catalog."pg_read_file"(\'/etc/passwd\');\n',
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.server-file-function")

    def test_dblink_get_result_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "dblink.sql"
            path.write_text(
                "SELECT dblink_get_result('connection');\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.external-connection")

    def test_quoted_dblink_get_result_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-dblink.sql"
            path.write_text(
                'SELECT "dblink_get_result"(\'connection\');\n',
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.external-connection")

    def test_external_connection_ignores_non_introducing_routine_ddl(
        self,
    ) -> None:
        statements = (
            "ALTER FUNCTION net.http_get(text) SECURITY DEFINER;\n",
            "ALTER PROCEDURE public.http_post(text) PARALLEL UNSAFE;\n",
            "DROP FUNCTION net.http_delete(text, jsonb);\n",
            "DROP ROUTINE public.http_head(text);\n",
        )
        for statement in statements:
            with (
                self.subTest(statement=statement),
                TemporaryDirectory() as directory,
            ):
                path = Path(directory) / "routine-ddl.sql"
                path.write_text(statement, encoding="utf-8")

                report = scan(path)

            self.assertNotIn(
                "sql.external-connection",
                rule_ids_from(report),
            )

    def test_external_connection_after_routine_ddl_is_still_flagged(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "ddl-then-call.sql"
            path.write_text(
                "ALTER FUNCTION net.http_get(text) SECURITY DEFINER;\n"
                "SELECT net.http_get('https://example.invalid');\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.external-connection")

    def test_quoted_and_string_language_names_are_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-languages.sql"
            path.write_text(
                "CREATE FUNCTION public.one() RETURNS void "
                'AS $$ SELECT 1 $$ LANGUAGE "plpython3u";\n'
                "CREATE FUNCTION public.two() RETURNS void "
                "AS $$ SELECT 1 $$ LANGUAGE 'plperlu';\n",
                encoding="utf-8",
            )

            report = scan(path)

        self.assertGreaterEqual(
            rule_ids_from(report).count("sql.untrusted-language"),
            2,
        )

    def test_escaped_language_name_is_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "escaped-language.sql"
            path.write_text(
                "CREATE FUNCTION public.one() RETURNS void "
                "AS $$ SELECT 1 $$ LANGUAGE E'plpython\\x33u';\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.untrusted-language")

    def test_unicode_uescape_language_name_is_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "uescape-language.sql"
            path.write_text(
                "CREATE FUNCTION public.one() RETURNS void "
                "AS $$ SELECT 1 $$ "
                "LANGUAGE U&\"plpython!0033u\" UESCAPE '!';\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.untrusted-language")

    def test_newline_concatenated_language_name_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "concatenated-language.sql"
            path.write_text(
                "CREATE FUNCTION public.one() RETURNS void "
                "AS $$ SELECT 1 $$ LANGUAGE 'plpython'\n"
                "'3u';\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.untrusted-language")

    def test_security_definer_body_set_does_not_count_as_configuration(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "body-search-path.sql"
            path.write_text(
                "CREATE FUNCTION public.risky() RETURNS void\n"
                "LANGUAGE plpgsql SECURITY DEFINER\n"
                "AS $$ BEGIN PERFORM secrets.value; "
                "SET search_path = pg_catalog, pg_temp; END $$;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(
                path,
                "sql.security-definer-search-path-review",
            )

    def test_security_definer_uses_last_search_path_setting(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "last-search-path.sql"
            path.write_text(
                "CREATE FUNCTION public.risky() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "SET search_path = public, pg_temp "
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky() FROM PUBLIC;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.security-definer-search-path")

    def test_unicode_escape_public_search_path_is_not_treated_as_safe(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "unicode-search-path.sql"
            path.write_text(
                "CREATE FUNCTION public.risky() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                'SET search_path = U&"public", pg_temp '
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky() FROM PUBLIC;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.security-definer-search-path")

    def test_quoted_uppercase_pg_temp_is_not_special(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-pg-temp.sql"
            path.write_text(
                "CREATE FUNCTION public.risky() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                'SET search_path = pg_catalog, "PG_TEMP" '
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky() FROM PUBLIC;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.security-definer-search-path")

    def test_quoted_uppercase_public_is_a_distinct_schema(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-public.sql"
            path.write_text(
                "CREATE FUNCTION public.risky() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                'SET search_path = "PUBLIC", pg_temp '
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky() FROM PUBLIC;\n",
                encoding="utf-8",
            )

            report = scan(path)

        self.assertNotIn(
            "sql.security-definer-search-path",
            rule_ids_from(report),
        )

    def test_keyword_like_schema_after_pg_temp_is_not_truncated(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "keyword-schema.sql"
            path.write_text(
                "CREATE FUNCTION public.risky() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp, language "
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky() FROM PUBLIC;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.security-definer-search-path")

    def test_unicode_security_definer_name_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "unicode-routine.sql"
            path.write_text(
                "CREATE FUNCTION public.опасная() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\n",
                encoding="utf-8",
            )

            report = scan(path)

        rules = rule_ids_from(report)
        self.assertIn("sql.security-definer-search-path-review", rules)
        self.assertIn("sql.security-definer-public-execute", rules)

    def test_extschema_placeholder_security_definer_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "placeholder-routine.sql"
            path.write_text(
                "CREATE FUNCTION @extschema@.risky() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\n",
                encoding="utf-8",
            )

            report = scan(path)

        rules = rule_ids_from(report)
        self.assertIn("sql.security-definer-search-path-review", rules)
        self.assertIn("sql.security-definer-public-execute", rules)

    def test_extschema_named_placeholder_with_hyphen_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "named-placeholder-routine.sql"
            path.write_text(
                "CREATE FUNCTION @extschema:uuid-ossp@.risky() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\n",
                encoding="utf-8",
            )

            report = scan(path)

        rules = rule_ids_from(report)
        self.assertIn("sql.security-definer-search-path-review", rules)
        self.assertIn("sql.security-definer-public-execute", rules)

    def test_unicode_uescape_routine_name_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "uescape-routine.sql"
            path.write_text(
                "CREATE FUNCTION U&\"f!006f\" UESCAPE '!'() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER AS $$ SELECT 1 $$;\n",
                encoding="utf-8",
            )

            report = scan(path)

        rules = rule_ids_from(report)
        self.assertIn("sql.security-definer-search-path-review", rules)
        self.assertIn("sql.security-definer-public-execute", rules)

    def test_alter_security_definer_without_safe_path_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "alter-definer.sql"
            path.write_text(
                "ALTER FUNCTION public.risky() SECURITY DEFINER;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(
                path,
                "sql.security-definer-search-path-review",
            )

    def test_alter_security_definer_without_signature_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "alter-no-signature.sql"
            path.write_text(
                "ALTER FUNCTION public.risky SECURITY DEFINER;\n",
                encoding="utf-8",
            )

            report = scan(path)

        rules = rule_ids_from(report)
        self.assertIn("sql.security-definer-search-path-review", rules)
        self.assertIn("sql.security-definer-public-execute", rules)

    def test_alter_security_definer_with_safe_path_still_requires_revoke(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "alter-public.sql"
            path.write_text(
                "ALTER FUNCTION public.risky() SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(
                path,
                "sql.security-definer-public-execute",
            )

    def test_later_alter_cannot_reset_security_definer_search_path(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "reset-definer.sql"
            path.write_text(
                "CREATE FUNCTION public.risky() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky() FROM PUBLIC;\n"
                "ALTER FUNCTION public.risky() RESET search_path;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.security-definer-search-path")

    def test_later_alter_cannot_make_definer_search_path_unsafe(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "alter-unsafe-definer.sql"
            path.write_text(
                "CREATE FUNCTION public.risky() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky() FROM PUBLIC;\n"
                "ALTER FUNCTION public.risky() "
                "SET search_path = public, pg_temp;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.security-definer-search-path")

    def test_named_create_argument_does_not_hide_unsafe_alter(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "named-alter-definer.sql"
            path.write_text(
                "CREATE FUNCTION public.risky(value integer) RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky(integer) FROM PUBLIC;\n"
                "ALTER FUNCTION public.risky(integer) RESET search_path;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.security-definer-search-path")

    def test_later_alter_search_path_variants_fail_closed(self) -> None:
        mutations = (
            'SET "search_path" = public, pg_temp',
            "SET search_path FROM CURRENT",
            "RESET ALL",
            'SET U&"search_path" = public, pg_temp',
            r'SET U&"search_pat\0068" = public, pg_temp',
            'RESET U&"search_path"',
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                with TemporaryDirectory() as directory:
                    path = Path(directory) / "alter-variant.sql"
                    path.write_text(
                        "CREATE FUNCTION public.risky() RETURNS void "
                        "LANGUAGE sql SECURITY DEFINER "
                        "SET search_path = pg_catalog, pg_temp "
                        "AS $$ SELECT 1 $$;\n"
                        "REVOKE ALL ON FUNCTION public.risky() FROM PUBLIC;\n"
                        f"ALTER FUNCTION public.risky() {mutation};\n",
                        encoding="utf-8",
                    )

                    report = scan(path)

                self.assertIn(
                    "sql.security-definer-search-path",
                    rule_ids_from(report),
                )

    def test_quoted_lowercase_name_matches_known_definer_state(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-alter-name.sql"
            path.write_text(
                "CREATE FUNCTION public.f() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.f() FROM PUBLIC;\n"
                'ALTER FUNCTION public."f"() RESET search_path;\n',
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.security-definer-search-path")

    def test_signatureless_alter_matches_known_definer_state(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "signatureless-alter.sql"
            path.write_text(
                "CREATE FUNCTION public.f() RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.f() FROM PUBLIC;\n"
                "ALTER FUNCTION public.f RESET search_path;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.security-definer-search-path")

    def test_unknown_routine_unsafe_search_path_alter_is_reviewed(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "unknown-routine-alter.sql"
            path.write_text(
                "ALTER FUNCTION public.external() RESET ALL;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.routine-unsafe-search-path")

    def test_security_definer_requires_later_public_revoke(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "default-public.sql"
            path.write_text(
                "CREATE FUNCTION public.risky() RETURNS integer\n"
                "LANGUAGE sql SECURITY DEFINER\n"
                "SET search_path = pg_catalog, pg_temp\n"
                "AS $$ SELECT 1 $$;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(
                path,
                "sql.security-definer-public-execute",
            )

    def test_one_revoke_does_not_clear_multiple_definer_overloads(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "overloads.sql"
            path.write_text(
                "CREATE FUNCTION public.risky(integer) RETURNS integer "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;\n"
                "CREATE FUNCTION public.risky(text) RETURNS integer "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky(integer) FROM PUBLIC;\n",
                encoding="utf-8",
            )

            report = scan(path)

        self.assertGreaterEqual(
            rule_ids_from(report).count(
                "sql.security-definer-public-execute"
            ),
            1,
        )

    def test_named_default_arguments_match_revoke_identity_types(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "named-default-revoke.sql"
            path.write_text(
                "CREATE FUNCTION public.safe("
                "extension_name TEXT, source TEXT DEFAULT 'core'"
                ") RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.safe(TEXT, TEXT) FROM PUBLIC;\n",
                encoding="utf-8",
            )

            report = scan(path)

        self.assertNotIn(
            "sql.security-definer-public-execute",
            rule_ids_from(report),
        )

    def test_multiword_identity_type_is_not_mistaken_for_argument_name(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "multiword-revoke.sql"
            path.write_text(
                "CREATE FUNCTION public.safe(double precision) RETURNS void "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.safe(double precision) "
                "FROM PUBLIC;\n",
                encoding="utf-8",
            )

            report = scan(path)

        self.assertNotIn(
            "sql.security-definer-public-execute",
            rule_ids_from(report),
        )

    def test_wrong_signature_revoke_does_not_clear_public_execute(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "wrong-revoke.sql"
            path.write_text(
                "CREATE FUNCTION public.risky(text) RETURNS integer "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky(integer) FROM PUBLIC;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(
                path,
                "sql.security-definer-public-execute",
            )

    def test_signature_whitespace_cannot_merge_distinct_types(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "spaced-signature.sql"
            path.write_text(
                "CREATE FUNCTION public.risky(a bc) RETURNS integer "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky(abc) FROM PUBLIC;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(
                path,
                "sql.security-definer-public-execute",
            )

    def test_quoted_type_whitespace_cannot_merge_overloads(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "quoted-signature.sql"
            path.write_text(
                'CREATE FUNCTION public.risky("My Type") RETURNS integer '
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;\n"
                'REVOKE ALL ON FUNCTION public.risky("MyType") FROM PUBLIC;\n',
                encoding="utf-8",
            )

            self.assert_has_rule(
                path,
                "sql.security-definer-public-execute",
            )

    def test_non_ascii_identifier_is_not_unicode_casefolded(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "non-ascii-name.sql"
            path.write_text(
                "CREATE FUNCTION public.ß() RETURNS integer "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.ss() FROM PUBLIC;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(
                path,
                "sql.security-definer-public-execute",
            )

    def test_non_ascii_argument_type_is_not_unicode_casefolded(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "non-ascii-type.sql"
            path.write_text(
                "CREATE FUNCTION public.risky(ß) RETURNS integer "
                "LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION public.risky(ss) FROM PUBLIC;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(
                path,
                "sql.security-definer-public-execute",
            )

    def test_sql_finding_volume_is_capped_per_rule_and_file(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "many-findings.sql"
            path.write_text(
                "SELECT pg_read_file('/etc/passwd');\n" * 100,
                encoding="utf-8",
            )

            report = scan(path)

        file_findings = [
            finding
            for finding in findings_from(report)
            if finding_field(finding, "rule_id") == "sql.server-file-function"
        ]
        self.assertEqual(32, len(file_findings))
        self.assertTrue(
            any(
                "showing first 32 of 100" in str(
                    finding_field(finding, "evidence")
                )
                for finding in file_findings
            )
        )

    def test_global_finding_limit_fails_instead_of_returning_partial_report(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "many-rules.sql"
            path.write_text(
                "SELECT pg_read_file('/etc/passwd');\n"
                "SELECT lo_import('/etc/passwd');\n",
                encoding="utf-8",
            )

            with patch("pgextassure.scanner.MAX_FINDINGS", 1):
                with self.assertRaisesRegex(ScanInputError, "finding report limit"):
                    scan_path(path)

    def test_escape_string_content_remains_masked(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "escape-string.sql"
            path.write_text(
                r"SELECT E'pg_read_file(\'/etc/passwd\')';" + "\n",
                encoding="utf-8",
            )

            report = scan(path)

        self.assertNotIn("sql.server-file-function", rule_ids_from(report))

    def test_connected_upgrade_graph_is_quiet(self) -> None:
        report = scan(UPGRADE_ROOT / "connected")
        update_rules = [
            rule_id for rule_id in rule_ids_from(report) if rule_id.startswith("update.")
        ]
        self.assertEqual([], update_rules)

    def test_disconnected_upgrade_graph_is_flagged(self) -> None:
        self.assert_has_rule(
            UPGRADE_ROOT / "disconnected",
            "update.missing-path",
        )

    def test_reachable_side_branch_must_reach_default_version(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.control").write_text(
                "default_version = '3'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "demo--1.sql").write_text("SELECT 1;\n", encoding="utf-8")
            (root / "demo--1--2.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )
            (root / "demo--1--3.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(root, "update.missing-path")

    def test_sibling_sql_directory_uses_nearest_package_control(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            vendor_control = root / "vendor" / "control"
            vendor_sql = root / "vendor" / "sql"
            vendor_control.mkdir(parents=True)
            vendor_sql.mkdir(parents=True)
            (root / "demo.control").write_text(
                "default_version = '1'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "demo--1.sql").write_text("SELECT 1;\n", encoding="utf-8")
            (vendor_control / "demo.control").write_text(
                "default_version = '2'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (vendor_sql / "demo--1.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )
            (vendor_sql / "demo--1--2.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            report = scan(root)

        update_findings = [
            finding
            for finding in findings_from(report)
            if str(finding_field(finding, "rule_id")).startswith("update.")
        ]
        self.assertEqual([], update_findings, update_findings)

    def test_control_template_selects_only_matching_install_sql(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.control.in").write_text(
                "default_version = '@VERSION@'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "demo--1.0.sql.in").write_text(
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            (root / "regression.sql").write_text(
                "COPY regression FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )

            findings = findings_from(scan(root))

        copy_findings = [
            finding
            for finding in findings
            if finding_field(finding, "rule_id") == "sql.copy-program"
        ]
        self.assertEqual(1, len(copy_findings), copy_findings)
        self.assertEqual(
            "demo--1.0.sql.in",
            finding_field(copy_findings[0], "path"),
        )

    def test_secondary_control_inherits_primary_security_defaults(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.control").write_text(
                "default_version = '1'\nsuperuser = false\ntrusted = false\n",
                encoding="utf-8",
            )
            (root / "demo--1.control").write_text(
                "comment = 'version-specific metadata'\n",
                encoding="utf-8",
            )
            (root / "demo--1.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            report = scan(root)

        self.assertEqual([], findings_from(report))

    def test_secondary_control_security_override_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.control").write_text(
                "default_version = '1'\nsuperuser = false\ntrusted = false\n",
                encoding="utf-8",
            )
            (root / "demo--1.control").write_text(
                "trusted = true\n",
                encoding="utf-8",
            )
            (root / "demo--1.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            report = scan(root)

        trusted = [
            finding
            for finding in findings_from(report)
            if finding_field(finding, "rule_id") == "control.trusted-install"
        ]
        self.assertEqual(1, len(trusted), trusted)
        self.assertEqual(
            "demo--1.control",
            finding_field(trusted[0], "path"),
        )

    def test_nested_plain_sql_template_is_scanned_but_regression_sql_is_not(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            sql_directory = root / "sql"
            sql_directory.mkdir()
            (root / "demo.control.in").write_text(
                "default_version = '@VERSION@'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (sql_directory / "demo.sql.in").write_text(
                "COPY template_input FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            (sql_directory / "demo.sql").write_text(
                "COPY regression_case FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )

            findings = findings_from(scan(root))

        copy_paths = [
            finding_field(finding, "path")
            for finding in findings
            if finding_field(finding, "rule_id") == "sql.copy-program"
        ]
        self.assertEqual(["sql/demo.sql.in"], copy_paths)

    def test_update_only_graph_without_install_script_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.control").write_text(
                "default_version = '2.0'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "demo--1.0--2.0.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(root, "update.install-script-missing")

    def test_duplicate_extension_names_have_isolated_update_graphs(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            incomplete = root / "incomplete"
            connected = root / "connected"
            incomplete.mkdir()
            connected.mkdir()
            for package in (incomplete, connected):
                (package / "demo.control").write_text(
                    "default_version = '2.0'\nsuperuser = false\n",
                    encoding="utf-8",
                )
                (package / "demo--1.0.sql").write_text(
                    "SELECT 1;\n",
                    encoding="utf-8",
                )
            (connected / "demo--1.0--2.0.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            findings = findings_from(scan(root))

        update_findings = [
            finding
            for finding in findings
            if finding_field(finding, "rule_id").startswith("update.")
        ]
        self.assertTrue(update_findings)
        self.assertTrue(
            all(
                str(finding_field(finding, "path")).startswith("incomplete/")
                for finding in update_findings
            ),
            update_findings,
        )
        self.assertIn(
            "update.missing-path",
            [finding_field(finding, "rule_id") for finding in update_findings],
        )

    def test_same_scope_duplicate_controls_fail_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.control").write_text(
                "default_version = '2'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "demo.control.in").write_text(
                "default_version = '@VERSION@'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "demo--1--2.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(root, "update.ambiguous-scope")

    def test_template_default_version_does_not_hide_update_cycle(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.control.in").write_text(
                "default_version = '@VERSION@'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "demo--1.0--2.0.sql.in").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )
            (root / "demo--2.0--1.0.sql.in").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            self.assert_has_rule(root, "update.cycle")

    def test_unresolved_boolean_templates_do_not_create_control_findings(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.control.in").write_text(
                "\n".join(
                    (
                        "default_version = '@VERSION@'",
                        "superuser = @SUPERUSER@",
                        "trusted = @TRUSTED@",
                        "relocatable = @RELOCATABLE@",
                    )
                )
                + "\n",
                encoding="utf-8",
            )

            report = scan(root)

        control_rules = [
            rule_id
            for rule_id in rule_ids_from(report)
            if rule_id.startswith("control.")
        ]
        self.assertEqual([], control_rules)

    def test_direct_sql_file_is_scanned_even_when_not_an_install_artifact(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "regression.sql"
            path.write_text(
                "COPY regression FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )

            self.assert_has_rule(path, "sql.copy-program")

    def test_oversized_source_is_rejected_before_scanning(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "oversized.sql"
            path.write_bytes(b"x" * 9)

            with patch("pgextassure.scanner.MAX_FILE_BYTES", 8):
                with self.assertRaisesRegex(ScanInputError, "per-file limit"):
                    scan_path(path)

    def test_total_entry_limit_counts_unsupported_files(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "supported.sql").write_text("SELECT 1;\n", encoding="utf-8")
            (root / "ignored.txt").write_text("ignored\n", encoding="utf-8")

            with patch("pgextassure.scanner.MAX_ENTRIES", 1):
                with self.assertRaisesRegex(
                    ScanInputError,
                    "entry filesystem limit",
                ):
                    scan_path(root)

    def test_directory_limit_includes_the_scan_root(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "one").mkdir()
            (root / "two").mkdir()
            (root / "supported.sql").write_text("SELECT 1;\n", encoding="utf-8")

            with patch("pgextassure.scanner.MAX_DIRECTORIES", 2):
                with self.assertRaisesRegex(ScanInputError, "directory limit"):
                    scan_path(root)

    def test_relative_path_depth_limit_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            nested = root / "one" / "two"
            nested.mkdir(parents=True)
            (nested / "supported.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            with patch("pgextassure.scanner.MAX_PATH_DEPTH", 2):
                with self.assertRaisesRegex(
                    ScanInputError,
                    "relative path depth limit",
                ):
                    scan_path(root)

    def test_relative_path_byte_limit_uses_utf8_length(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            name = "é.sql"
            (root / name).write_text("SELECT 1;\n", encoding="utf-8")

            with patch(
                "pgextassure.scanner.MAX_RELATIVE_PATH_BYTES",
                len(name.encode("utf-8")) - 1,
            ):
                with self.assertRaisesRegex(
                    ScanInputError,
                    "byte relative path limit",
                ):
                    scan_path(root)

    def test_empty_directory_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            with self.assertRaisesRegex(ScanInputError, "no supported source"):
                scan_path(directory)

    @unittest.skipUnless(hasattr(os, "symlink"), "requires filesystem symlinks")
    def test_supported_source_symlink_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            payload = root / "payload.txt"
            payload.write_text(
                "COPY secrets FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            (root / "demo.control").write_text(
                "default_version = '1.0'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "demo--1.0.sql").symlink_to(payload.name)

            with self.assertRaisesRegex(ScanInputError, "symlinked supported"):
                scan_path(root)

    @unittest.skipUnless(
        os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() != 0,
        "requires non-root POSIX permissions",
    )
    def test_unreadable_subtree_fails_closed(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            blocked = root / "blocked"
            blocked.mkdir()
            (blocked / "danger.sql").write_text(
                "COPY secrets FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )
            blocked.chmod(0)
            try:
                with self.assertRaisesRegex(ScanError, "cannot traverse"):
                    scan_path(root)
            finally:
                blocked.chmod(0o700)

    @unittest.skipUnless(
        sys.platform.startswith("linux"),
        "byte-oriented non-UTF-8 filenames require Linux",
    )
    def test_non_utf8_supported_filename_is_rejected_explicitly(self) -> None:
        with TemporaryDirectory() as directory:
            raw_path = os.fsencode(directory) + b"/invalid-\xff.sql"
            descriptor = os.open(raw_path, os.O_WRONLY | os.O_CREAT, 0o600)
            try:
                os.write(descriptor, b"SELECT 1;\n")
            finally:
                os.close(descriptor)

            with self.assertRaisesRegex(ScanInputError, "not valid UTF-8"):
                scan_path(directory)

    @unittest.skipUnless(hasattr(os, "mkfifo"), "requires POSIX named pipes")
    def test_non_regular_supported_file_is_rejected_without_blocking(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "blocked.sql"
            os.mkfifo(path)

            with self.assertRaisesRegex(ScanInputError, "non-regular"):
                scan_path(Path(directory))

    def test_cycle_detection_handles_long_update_chains_iteratively(self) -> None:
        node_count = 5_000
        nodes = {str(index) for index in range(node_count)}
        edges = {
            str(index): {str(index + 1)}
            for index in range(node_count - 1)
        }

        self.assertFalse(_has_cycle(nodes, edges))
        edges[str(node_count - 1)] = {"0"}
        self.assertTrue(_has_cycle(nodes, edges))


if __name__ == "__main__":
    unittest.main()
