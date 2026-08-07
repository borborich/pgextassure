from __future__ import annotations

from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from pgextassure.scanner import scan_path


def _rules(path: Path) -> list[str]:
    return [finding.rule_id for finding in scan_path(path).findings]


class PostgreSqlEdgeRegressionTests(unittest.TestCase):
    def test_security_definer_event_trigger_is_not_ordinary_public_api(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "event-trigger.sql"
            path.write_text(
                "CREATE FUNCTION public.audit_ddl() RETURNS event_trigger "
                "LANGUAGE C SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "AS 'audit', 'audit_ddl';\n",
                encoding="utf-8",
            )

            report = scan_path(path)

        rules = [finding.rule_id for finding in report.findings]
        self.assertIn("sql.security-definer-event-trigger", rules)
        self.assertNotIn("sql.security-definer-public-execute", rules)

    def test_fully_qualified_definer_body_is_review_not_exploit_claim(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "qualified.sql"
            path.write_text(
                "CREATE FUNCTION public.wrapper(value bigint) RETURNS bigint "
                "LANGUAGE plpgsql SECURITY DEFINER AS $$ "
                "BEGIN RETURN trusted.target(value); END $$;\n",
                encoding="utf-8",
            )

            report = scan_path(path)

        rules = [finding.rule_id for finding in report.findings]
        self.assertIn("sql.security-definer-search-path-review", rules)
        self.assertNotIn("sql.security-definer-search-path", rules)

    def test_unqualified_definer_call_remains_critical(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "unqualified.sql"
            path.write_text(
                "CREATE FUNCTION public.wrapper(value bigint) RETURNS bigint "
                "LANGUAGE plpgsql SECURITY DEFINER AS $$ "
                "BEGIN RETURN target(value); END $$;\n",
                encoding="utf-8",
            )

            report = scan_path(path)

        findings = {
            finding.rule_id: finding for finding in report.findings
        }
        self.assertIn("sql.security-definer-search-path", findings)
        self.assertEqual(
            findings["sql.security-definer-search-path"].severity.value,
            "critical",
        )

    def test_runtime_search_path_logic_is_explicit_review_signal(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "runtime-path.sql"
            path.write_text(
                "CREATE FUNCTION public.wrapper() RETURNS void "
                "LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN "
                "PERFORM pg_catalog.set_config("
                "'search_path', 'trusted, pg_temp', true); END $$;\n",
                encoding="utf-8",
            )

            report = scan_path(path)

        rules = [finding.rule_id for finding in report.findings]
        self.assertIn("sql.security-definer-search-path-review", rules)
        self.assertNotIn("sql.security-definer-search-path", rules)

    def test_literal_at_sign_version_is_not_treated_as_template(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "demo.control").write_text(
                "default_version = 'release@2'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "demo--1.sql").write_text("SELECT 1;\n", encoding="utf-8")

            rules = _rules(root)

        self.assertIn("update.install-script-missing", rules)

    def test_secondary_control_inherits_from_configured_sibling_directory(
        self,
    ) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            control_root = root / "pkg" / "extension"
            sql_root = root / "pkg" / "sql"
            control_root.mkdir(parents=True)
            sql_root.mkdir(parents=True)
            (control_root / "demo.control").write_text(
                "directory = 'sql'\n"
                "default_version = '1'\n"
                "superuser = false\n",
                encoding="utf-8",
            )
            (sql_root / "demo--1.control").write_text(
                "comment = 'version metadata'\n",
                encoding="utf-8",
            )
            (sql_root / "demo--1.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            rules = _rules(root)

        self.assertNotIn("control.superuser-required", rules)

    def test_hyphenated_secondary_control_name_inherits_primary(self) -> None:
        with TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "foo-bar.control").write_text(
                "default_version = '1'\nsuperuser = false\n",
                encoding="utf-8",
            )
            (root / "foo-bar--1.control").write_text(
                "comment = 'version metadata'\n",
                encoding="utf-8",
            )
            (root / "foo-bar--1.sql").write_text(
                "SELECT 1;\n",
                encoding="utf-8",
            )

            rules = _rules(root)

        self.assertNotIn("control.superuser-required", rules)

    def test_uescape_literal_forms_do_not_hide_security_definer(self) -> None:
        suffixes = ("E'!'", "$q$!$q$", "'!'\n''")
        for suffix in suffixes:
            with self.subTest(suffix=suffix):
                with TemporaryDirectory() as directory:
                    path = Path(directory) / "demo.sql"
                    path.write_text(
                        f'CREATE FUNCTION U&"f!006f" UESCAPE {suffix}() '
                        "RETURNS void LANGUAGE sql SECURITY DEFINER "
                        "SET search_path = pg_catalog, pg_temp "
                        "AS $$ SELECT 1 $$;\n",
                        encoding="utf-8",
                    )

                    rules = _rules(path)

                self.assertIn("sql.security-definer-public-execute", rules)

    def test_exact_custom_uescape_revoke_correlates(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                'CREATE FUNCTION U&"f!006f" UESCAPE \'!\'() '
                "RETURNS void LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "AS $$ SELECT 1 $$;\n"
                'REVOKE ALL ON FUNCTION U&"f!006f" UESCAPE \'!\'() '
                "FROM PUBLIC;\n",
                encoding="utf-8",
            )

            rules = _rules(path)

        self.assertNotIn("sql.security-definer-public-execute", rules)

    def test_quoted_configuration_name_is_case_insensitive(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                "CREATE FUNCTION f() RETURNS void LANGUAGE sql "
                "SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "AS $$ SELECT 1 $$;\n"
                "REVOKE ALL ON FUNCTION f() FROM PUBLIC;\n"
                'ALTER FUNCTION f() SET "SEARCH_PATH" = public, pg_temp;\n',
                encoding="utf-8",
            )

            rules = _rules(path)

        self.assertIn("sql.security-definer-search-path", rules)

    def test_extschema_search_path_placeholders_are_recognized(self) -> None:
        placeholders = ("@extschema@", "@extschema:uuid-ossp@")
        for placeholder in placeholders:
            with self.subTest(placeholder=placeholder):
                with TemporaryDirectory() as directory:
                    path = Path(directory) / "demo.sql"
                    path.write_text(
                        "CREATE FUNCTION f() RETURNS void LANGUAGE sql "
                        "SECURITY DEFINER "
                        f"SET search_path = {placeholder}, pg_temp "
                        "AS $$ SELECT 1 $$;\n"
                        "REVOKE ALL ON FUNCTION f() FROM PUBLIC;\n",
                        encoding="utf-8",
                    )

                    rules = _rules(path)

                self.assertNotIn("sql.security-definer-search-path", rules)

    def test_pg_temp_must_appear_once_and_only_at_search_path_end(self) -> None:
        unsafe_paths = (
            "pg_temp",
            "pg_temp, pg_catalog, pg_temp",
        )
        for search_path in unsafe_paths:
            with self.subTest(search_path=search_path):
                with TemporaryDirectory() as directory:
                    path = Path(directory) / "demo.sql"
                    path.write_text(
                        "CREATE FUNCTION f() RETURNS void LANGUAGE sql "
                        "SECURITY DEFINER "
                        f"SET search_path = {search_path} "
                        "AS $$ SELECT 1 $$;\n"
                        "REVOKE ALL ON FUNCTION f() FROM PUBLIC;\n",
                        encoding="utf-8",
                    )

                    rules = _rules(path)

                self.assertIn("sql.security-definer-search-path", rules)

    def test_cr_concatenated_language_is_flagged(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                "CREATE FUNCTION f() RETURNS void AS $$ SELECT 1 $$ "
                "LANGUAGE 'plpython'\r'3u';\n",
                encoding="utf-8",
            )

            rules = _rules(path)

        self.assertIn("sql.untrusted-language", rules)

    def test_cr_line_comment_does_not_hide_native_capability(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.c"
            path.write_text(
                "// harmless\rvoid run(void) { system(\"id\"); }\n",
                encoding="utf-8",
            )

            rules = _rules(path)

        self.assertIn("c.process-exec", rules)

    def test_escape_state_carries_into_concatenated_language(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                "CREATE FUNCTION f() RETURNS void AS $$ SELECT 1 $$ "
                "LANGUAGE E'plpython'\n'\\x33u';\n",
                encoding="utf-8",
            )

            rules = _rules(path)

        self.assertIn("sql.untrusted-language", rules)

    def test_unicode_string_backslash_does_not_escape_quote(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                "SELECT U&'abc\\' UESCAPE '!'; "
                "COPY demo FROM PROGRAM 'id';\n",
                encoding="utf-8",
            )

            rules = _rules(path)

        self.assertIn("sql.copy-program", rules)

    def test_unicode_identifier_backslash_does_not_escape_quote(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                'CREATE FUNCTION U&"foo\\" UESCAPE \'!\'() '
                "RETURNS void LANGUAGE sql SECURITY DEFINER "
                "AS $$ SELECT 1 $$;\n",
                encoding="utf-8",
            )

            rules = _rules(path)

        self.assertIn("sql.security-definer-search-path-review", rules)
        self.assertIn("sql.security-definer-public-execute", rules)

    def test_dollar_like_text_in_literal_does_not_hide_unsafe_alter(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                "ALTER FUNCTION f() SET application_name = '$tag$' "
                "SET search_path = public, pg_temp;\n",
                encoding="utf-8",
            )

            rules = _rules(path)

        self.assertIn("sql.routine-unsafe-search-path", rules)

    def test_begin_atomic_inside_identifier_does_not_hide_unsafe_alter(
        self,
    ) -> None:
        statements = (
            'ALTER FUNCTION public.f("BEGIN ATOMIC") RESET search_path;',
            'ALTER FUNCTION "BEGIN ATOMIC"() RESET ALL;',
            'ALTER FUNCTION public.f("x BEGIN ATOMIC y") '
            "SET search_path = public, pg_temp;",
        )
        for statement in statements:
            with self.subTest(statement=statement):
                with TemporaryDirectory() as directory:
                    path = Path(directory) / "demo.sql"
                    path.write_text(statement + "\n", encoding="utf-8")

                    rules = _rules(path)

                self.assertIn("sql.routine-unsafe-search-path", rules)

    def test_sql_standard_body_does_not_change_invoker_mode(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                "CREATE FUNCTION f() RETURNS text LANGUAGE sql "
                "SECURITY INVOKER "
                "BEGIN ATOMIC SELECT security definer FROM demo; END;\n",
                encoding="utf-8",
            )

            rules = _rules(path)

        self.assertNotIn("sql.security-definer-search-path", rules)
        self.assertNotIn("sql.security-definer-public-execute", rules)

    def test_public_execute_evidence_uses_source_name(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                "CREATE FUNCTION public.lookup_secret(secret_id bigint) "
                "RETURNS bigint LANGUAGE sql SECURITY DEFINER "
                "SET search_path = pg_catalog, pg_temp "
                "AS $$ SELECT secret_id $$;\n",
                encoding="utf-8",
            )

            findings = scan_path(path).findings

        public_execute = next(
            finding
            for finding in findings
            if finding.rule_id == "sql.security-definer-public-execute"
        )
        self.assertEqual(
            "routine = function public.lookup_secret(secret_id bigint)",
            public_execute.evidence,
        )

    def test_search_path_evidence_uses_source_routine_identity(self) -> None:
        with TemporaryDirectory() as directory:
            path = Path(directory) / "demo.sql"
            path.write_text(
                'CREATE FUNCTION public."LookupSecret"(secret_id bigint) '
                "RETURNS bigint LANGUAGE sql SECURITY DEFINER "
                "AS $$ SELECT secret_id $$;\n",
                encoding="utf-8",
            )

            findings = scan_path(path).findings

        search_path = next(
            finding
            for finding in findings
            if finding.rule_id == "sql.security-definer-search-path-review"
        )
        self.assertEqual(
            'routine = function public."LookupSecret"(secret_id bigint)',
            search_path.evidence,
        )


if __name__ == "__main__":
    unittest.main()
