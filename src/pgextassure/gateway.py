"""Loopback-first HTTP admission gateway with a persistent replay ledger."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date
import hashlib
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sqlite3
import stat
import tempfile
import threading
from typing import Any, Callable, Protocol

from .enterprise import (
    AdmissionEnforcementError,
    enforce_pilot_package,
)
from .pilot import MAX_PILOT_PACKAGE_BYTES


GATEWAY_MEDIA_TYPE = "application/vnd.pgextassure.pilot+zip"
MAX_GATEWAY_HEADER_BYTES = 512
MAX_IDEMPOTENCY_KEY_BYTES = 128
_IDEMPOTENCY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}\Z")
_REQUIRED_HEADERS = {
    "package_digest": "X-PgExtAssure-Package-SHA256",
    "key_digest": "X-PgExtAssure-Key-SHA256",
    "policy_digest": "X-PgExtAssure-Trust-Policy-SHA256",
    "request_id": "X-PgExtAssure-Request-ID",
    "target": "X-PgExtAssure-Target",
    "evaluated_on": "X-PgExtAssure-Evaluated-On",
    "verified_on": "X-PgExtAssure-Verified-On",
    "idempotency_key": "Idempotency-Key",
}


class GatewayError(ValueError):
    """Gateway configuration or request error."""


class GatewayConflict(GatewayError):
    """A request conflicts with the persistent replay ledger."""


class GatewayLedgerError(GatewayError):
    """The local replay ledger failed its own integrity contract."""


@dataclass(frozen=True, slots=True)
class GatewayConfig:
    host: str
    port: int
    ledger_path: Path | None = None
    postgres_dsn_file: Path | None = None
    initialize_postgres_ledger: bool = False
    maximum_request_bytes: int = MAX_PILOT_PACKAGE_BYTES
    maximum_concurrent_requests: int = 4
    request_timeout_seconds: int = 30
    openssl_path: str | None = None


@dataclass(frozen=True, slots=True)
class LedgerResult:
    event: bytes
    status_code: int
    replayed: bool


class Ledger(Protocol):
    """Persistence boundary shared by local and distributed gateways."""

    def ready(self) -> bool: ...

    def execute(
        self,
        *,
        idempotency_key: str,
        request_id: str,
        target: str,
        package_digest: str,
        operation: Callable[[], tuple[bytes, int]],
    ) -> LedgerResult: ...


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


def _error(code: str, message: str) -> bytes:
    return _json_bytes(
        {
            "schema_version": "1.0",
            "error": {
                "code": code,
                "message": message[:1024],
            },
        }
    )


def _strict_date(value: str, *, label: str) -> date:
    try:
        parsed = date.fromisoformat(value)
    except ValueError as error:
        raise GatewayError(f"{label} must use YYYY-MM-DD") from error
    if parsed.isoformat() != value:
        raise GatewayError(f"{label} must use YYYY-MM-DD")
    return parsed


def _header(value: str | None, *, label: str, maximum: int) -> str:
    if value is None or not value:
        raise GatewayError(f"missing required header {label}")
    try:
        raw = value.encode("ascii", errors="strict")
    except UnicodeEncodeError as error:
        raise GatewayError(f"header {label} must be ASCII") from error
    if len(raw) > maximum:
        raise GatewayError(f"header {label} exceeds the safe size limit")
    if any(byte < 0x20 or byte == 0x7F for byte in raw):
        raise GatewayError(f"header {label} contains control characters")
    return value


def _safe_ledger_path(path: str | os.PathLike[str]) -> Path:
    target = Path(path)
    if not target.name:
        raise GatewayError("ledger path must name a file")
    absolute = Path(os.path.abspath(target))
    current = Path(absolute.anchor)
    for part in absolute.parts[1:-1]:
        current /= part
        try:
            current_stat = current.lstat()
        except OSError as error:
            raise GatewayError(
                f"cannot inspect ledger directory {current}: {error}"
            ) from error
        if stat.S_ISLNK(current_stat.st_mode):
            raise GatewayError(
                f"ledger directory must not contain symlinks: {current}"
            )
        if not stat.S_ISDIR(current_stat.st_mode):
            raise GatewayError(f"ledger parent is not a directory: {current}")
    parent_stat = absolute.parent.stat()
    if parent_stat.st_mode & 0o077:
        raise GatewayError(
            "ledger parent permissions must not grant group or other access"
        )
    try:
        target_stat = absolute.lstat()
    except FileNotFoundError:
        return absolute
    except OSError as error:
        raise GatewayError(f"cannot inspect ledger path: {error}") from error
    if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
        raise GatewayError("ledger must be a regular non-symlink file")
    return absolute


def _safe_secret_file(path: str | os.PathLike[str]) -> Path:
    target = Path(os.path.abspath(Path(path)))
    current = Path(target.anchor)
    for part in target.parts[1:-1]:
        current /= part
        try:
            current_stat = current.lstat()
        except OSError as error:
            raise GatewayError(
                f"cannot inspect PostgreSQL DSN directory {current}: {error}"
            ) from error
        if stat.S_ISLNK(current_stat.st_mode):
            raise GatewayError(
                "PostgreSQL DSN directory must not contain symlinks"
            )
        if not stat.S_ISDIR(current_stat.st_mode):
            raise GatewayError("PostgreSQL DSN parent is not a directory")
    try:
        target_stat = target.lstat()
    except OSError as error:
        raise GatewayError(f"cannot inspect PostgreSQL DSN file: {error}") from error
    if stat.S_ISLNK(target_stat.st_mode) or not stat.S_ISREG(target_stat.st_mode):
        raise GatewayError(
            "PostgreSQL DSN file must be a regular non-symlink file"
        )
    if target_stat.st_mode & 0o077:
        raise GatewayError(
            "PostgreSQL DSN file permissions must not grant group or other access"
        )
    return target


def validate_gateway_config(config: GatewayConfig) -> GatewayConfig:
    """Validate bounded server configuration and ledger placement."""

    if not isinstance(config.host, str) or not config.host:
        raise GatewayError("gateway host must be non-empty")
    if type(config.port) is not int or not 0 <= config.port <= 65535:
        raise GatewayError("gateway port must be between 0 and 65535")
    if (
        type(config.maximum_request_bytes) is not int
        or not 1 <= config.maximum_request_bytes <= MAX_PILOT_PACKAGE_BYTES
    ):
        raise GatewayError(
            "maximum request bytes exceeds the Pilot Package boundary"
        )
    if (
        type(config.maximum_concurrent_requests) is not int
        or not 1 <= config.maximum_concurrent_requests <= 64
    ):
        raise GatewayError("maximum concurrency must be between 1 and 64")
    if (
        type(config.request_timeout_seconds) is not int
        or not 1 <= config.request_timeout_seconds <= 300
    ):
        raise GatewayError("request timeout must be between 1 and 300 seconds")
    if (config.ledger_path is None) == (config.postgres_dsn_file is None):
        raise GatewayError(
            "configure exactly one ledger: SQLite file or PostgreSQL DSN file"
        )
    if (
        type(config.initialize_postgres_ledger) is not bool
        or config.initialize_postgres_ledger
        and config.postgres_dsn_file is None
    ):
        raise GatewayError(
            "PostgreSQL ledger initialization requires a PostgreSQL DSN file"
        )
    return GatewayConfig(
        host=config.host,
        port=config.port,
        ledger_path=(
            _safe_ledger_path(config.ledger_path)
            if config.ledger_path is not None
            else None
        ),
        postgres_dsn_file=(
            _safe_secret_file(config.postgres_dsn_file)
            if config.postgres_dsn_file is not None
            else None
        ),
        initialize_postgres_ledger=config.initialize_postgres_ledger,
        maximum_request_bytes=config.maximum_request_bytes,
        maximum_concurrent_requests=config.maximum_concurrent_requests,
        request_timeout_seconds=config.request_timeout_seconds,
        openssl_path=config.openssl_path,
    )


def is_loopback_host(host: str) -> bool:
    """Return whether a configured bind host is explicitly loopback-only."""

    if host.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


class SQLiteAdmissionLedger:
    """SQLite uniqueness and idempotency boundary for admission requests."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(
            self.path,
            timeout=30.0,
            isolation_level=None,
        )
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA busy_timeout = 30000")
        return connection

    def _initialize(self) -> None:
        try:
            descriptor = os.open(
                self.path,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
        except FileExistsError:
            existing = self.path.stat()
            if existing.st_mode & 0o077:
                raise GatewayError(
                    "existing ledger permissions must not grant group or "
                    "other access"
                )
        else:
            os.close(descriptor)
        connection = self._connect()
        try:
            connection.execute("PRAGMA journal_mode = DELETE")
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS admissions (
                    idempotency_key TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    package_digest TEXT NOT NULL,
                    event_json BLOB NOT NULL,
                    event_sha256 TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (request_id, target)
                )
                """
            )
        finally:
            connection.close()

    def ready(self) -> bool:
        try:
            connection = self._connect()
            try:
                row = connection.execute("SELECT 1").fetchone()
                return row == (1,)
            finally:
                connection.close()
        except sqlite3.Error:
            return False

    def execute(
        self,
        *,
        idempotency_key: str,
        request_id: str,
        target: str,
        package_digest: str,
        operation: Callable[[], tuple[bytes, int]],
    ) -> LedgerResult:
        connection = self._connect()
        try:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                """
                SELECT request_id, target, package_digest, event_json,
                       event_sha256, status_code
                FROM admissions
                WHERE idempotency_key = ?
                """,
                (idempotency_key,),
            ).fetchone()
            if existing is not None:
                if existing[:3] != (request_id, target, package_digest):
                    raise GatewayConflict(
                        "idempotency key is already bound to another request"
                    )
                event = bytes(existing[3])
                event_digest = "sha256:" + hashlib.sha256(event).hexdigest()
                if event_digest != existing[4]:
                    raise GatewayLedgerError(
                        "stored Admission Event failed ledger integrity check"
                    )
                connection.execute("COMMIT")
                return LedgerResult(
                    event=event,
                    status_code=int(existing[5]),
                    replayed=True,
                )
            context = connection.execute(
                """
                SELECT idempotency_key
                FROM admissions
                WHERE request_id = ? AND target = ?
                """,
                (request_id, target),
            ).fetchone()
            if context is not None:
                raise GatewayConflict(
                    "request ID and target were already admitted "
                    "under another idempotency key"
                )
            event, status_code = operation()
            connection.execute(
                """
                INSERT INTO admissions (
                    idempotency_key,
                    request_id,
                    target,
                    package_digest,
                    event_json,
                    event_sha256,
                    status_code
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    idempotency_key,
                    request_id,
                    target,
                    package_digest,
                    sqlite3.Binary(event),
                    "sha256:" + hashlib.sha256(event).hexdigest(),
                    status_code,
                ),
            )
            connection.execute("COMMIT")
            return LedgerResult(
                event=event,
                status_code=status_code,
                replayed=False,
            )
        except BaseException:
            if connection.in_transaction:
                connection.execute("ROLLBACK")
            raise
        finally:
            connection.close()


# Backwards-compatible public name for the alpha12 local ledger.
AdmissionLedger = SQLiteAdmissionLedger


def _advisory_lock_key(value: str) -> int:
    raw = hashlib.sha256(value.encode("utf-8")).digest()[:8]
    return int.from_bytes(raw, byteorder="big", signed=True)


def _read_postgres_dsn(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise GatewayError(f"cannot read PostgreSQL DSN file: {error}") from error
    if not raw or len(raw) > 4096:
        raise GatewayError("PostgreSQL DSN file must contain 1 to 4096 bytes")
    if raw.endswith(b"\n"):
        raw = raw[:-1]
    try:
        dsn = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise GatewayError("PostgreSQL DSN file must be UTF-8") from error
    if not dsn or any(character in dsn for character in "\x00\r\n"):
        raise GatewayError("PostgreSQL DSN file must contain one non-empty line")
    return dsn


class PostgreSQLAdmissionLedger:
    """Globally consistent admission ledger backed by PostgreSQL."""

    _SCHEMA_LOCK = 0x5047455854415353

    def __init__(
        self,
        dsn_file: Path,
        *,
        connect: Callable[..., Any] | None = None,
        initialize: bool = False,
    ) -> None:
        self.dsn_file = dsn_file
        self._dsn = _read_postgres_dsn(dsn_file)
        self._connect_function = connect or self._load_connect()
        if initialize:
            self._initialize()
        self._validate_schema()

    @staticmethod
    def _load_connect() -> Callable[..., Any]:
        try:
            import psycopg
        except ImportError as error:
            raise GatewayError(
                "PostgreSQL ledger requires the 'postgres' installation extra"
            ) from error
        return psycopg.connect

    def _connect(self) -> Any:
        try:
            return self._connect_function(self._dsn)
        except Exception as error:
            raise GatewayLedgerError(
                "cannot connect to PostgreSQL ledger"
            ) from error

    @staticmethod
    def _rollback(connection: Any) -> None:
        try:
            connection.rollback()
        except Exception:
            pass

    def _initialize(self) -> None:
        connection = self._connect()
        try:
            cursor = connection.cursor()
            cursor.execute(
                "SELECT pg_advisory_xact_lock(%s)",
                (self._SCHEMA_LOCK,),
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS pgextassure_ledger_metadata (
                    singleton BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (singleton),
                    schema_version INTEGER NOT NULL
                )
                """
            )
            cursor.execute(
                """
                INSERT INTO pgextassure_ledger_metadata (
                    singleton, schema_version
                ) VALUES (TRUE, 1)
                ON CONFLICT (singleton) DO NOTHING
                """
            )
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS pgextassure_admissions (
                    idempotency_key TEXT PRIMARY KEY,
                    request_id TEXT NOT NULL,
                    target TEXT NOT NULL,
                    package_digest TEXT NOT NULL,
                    event_json BYTEA NOT NULL,
                    event_sha256 TEXT NOT NULL,
                    status_code INTEGER NOT NULL,
                    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE (request_id, target)
                )
                """
            )
            connection.commit()
        except Exception as error:
            self._rollback(connection)
            raise GatewayLedgerError(
                "cannot initialize PostgreSQL ledger"
            ) from error
        finally:
            connection.close()

    def _validate_schema(self) -> None:
        connection = self._connect()
        try:
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT schema_version
                FROM pgextassure_ledger_metadata
                WHERE singleton = TRUE
                """
            )
            if cursor.fetchone() != (1,):
                raise GatewayLedgerError(
                    "unsupported PostgreSQL ledger schema version"
                )
            cursor.execute(
                """
                SELECT idempotency_key, request_id, target, package_digest,
                       event_json, event_sha256, status_code
                FROM pgextassure_admissions
                WHERE FALSE
                """
            )
            connection.rollback()
        except GatewayLedgerError:
            self._rollback(connection)
            raise
        except Exception as error:
            self._rollback(connection)
            raise GatewayLedgerError(
                "PostgreSQL ledger schema is not initialized"
            ) from error
        finally:
            connection.close()

    def ready(self) -> bool:
        try:
            connection = self._connect()
            try:
                row = connection.cursor().execute(
                    """
                    SELECT schema_version
                    FROM pgextassure_ledger_metadata
                    WHERE singleton = TRUE
                      AND to_regclass('pgextassure_admissions') IS NOT NULL
                    """
                ).fetchone()
                return row == (1,)
            finally:
                connection.close()
        except Exception:
            return False

    def execute(
        self,
        *,
        idempotency_key: str,
        request_id: str,
        target: str,
        package_digest: str,
        operation: Callable[[], tuple[bytes, int]],
    ) -> LedgerResult:
        connection = self._connect()
        try:
            cursor = connection.cursor()
            lock_keys = sorted(
                {
                    _advisory_lock_key(f"idempotency:{idempotency_key}"),
                    _advisory_lock_key(f"context:{request_id}\0{target}"),
                }
            )
            for lock_key in lock_keys:
                cursor.execute(
                    "SELECT pg_advisory_xact_lock(%s)",
                    (lock_key,),
                )
            cursor.execute(
                """
                SELECT request_id, target, package_digest, event_json,
                       event_sha256, status_code
                FROM pgextassure_admissions
                WHERE idempotency_key = %s
                """,
                (idempotency_key,),
            )
            existing = cursor.fetchone()
            if existing is not None:
                if existing[:3] != (request_id, target, package_digest):
                    raise GatewayConflict(
                        "idempotency key is already bound to another request"
                    )
                event = bytes(existing[3])
                event_digest = "sha256:" + hashlib.sha256(event).hexdigest()
                if event_digest != existing[4]:
                    raise GatewayLedgerError(
                        "stored Admission Event failed ledger integrity check"
                    )
                connection.commit()
                return LedgerResult(
                    event=event,
                    status_code=int(existing[5]),
                    replayed=True,
                )
            cursor.execute(
                """
                SELECT idempotency_key
                FROM pgextassure_admissions
                WHERE request_id = %s AND target = %s
                """,
                (request_id, target),
            )
            if cursor.fetchone() is not None:
                raise GatewayConflict(
                    "request ID and target were already admitted "
                    "under another idempotency key"
                )
            event, status_code = operation()
            cursor.execute(
                """
                INSERT INTO pgextassure_admissions (
                    idempotency_key,
                    request_id,
                    target,
                    package_digest,
                    event_json,
                    event_sha256,
                    status_code
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    idempotency_key,
                    request_id,
                    target,
                    package_digest,
                    event,
                    "sha256:" + hashlib.sha256(event).hexdigest(),
                    status_code,
                ),
            )
            connection.commit()
            return LedgerResult(
                event=event,
                status_code=status_code,
                replayed=False,
            )
        except (GatewayError, AdmissionEnforcementError):
            self._rollback(connection)
            raise
        except Exception as error:
            self._rollback(connection)
            raise GatewayLedgerError(
                "PostgreSQL ledger operation failed"
            ) from error
        finally:
            connection.close()

class _GatewayServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(
        self,
        address: tuple[str, int],
        config: GatewayConfig,
        ledger: Ledger,
    ) -> None:
        self.config = config
        self.ledger = ledger
        self.capacity = threading.BoundedSemaphore(
            config.maximum_concurrent_requests
        )
        super().__init__(address, _GatewayHandler)

    def process_request(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        if self.capacity.acquire(blocking=False):
            super().process_request(request, client_address)
            return
        body = _error(
            "capacity-exhausted",
            "gateway capacity is exhausted",
        )
        response = (
            b"HTTP/1.1 503 Service Unavailable\r\n"
            b"Content-Type: application/json; charset=utf-8\r\n"
            + f"Content-Length: {len(body)}\r\n".encode("ascii")
            + b"Cache-Control: no-store\r\n"
            b"Connection: close\r\n"
            b"X-PgExtAssure-Replayed: false\r\n"
            b"\r\n"
            + body
        )
        try:
            request.sendall(response)
        except OSError:
            pass
        finally:
            self.shutdown_request(request)

    def process_request_thread(
        self,
        request: socket.socket,
        client_address: tuple[str, int],
    ) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.capacity.release()


class _GatewayHandler(BaseHTTPRequestHandler):
    server: _GatewayServer
    protocol_version = "HTTP/1.1"
    server_version = "PgExtAssureGateway/1.0"
    sys_version = ""

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(
            self.server.config.request_timeout_seconds
        )

    def log_message(self, format: str, *args: object) -> None:
        return

    def _respond(
        self,
        status: int,
        body: bytes,
        *,
        replayed: bool = False,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header(
            "Cache-Control",
            "no-store",
        )
        self.send_header(
            "X-PgExtAssure-Replayed",
            "true" if replayed else "false",
        )
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self._respond(
                HTTPStatus.OK,
                _json_bytes({"status": "ok"}),
            )
            return
        if self.path == "/readyz":
            ready = self.server.ledger.ready()
            self._respond(
                HTTPStatus.OK if ready else HTTPStatus.SERVICE_UNAVAILABLE,
                _json_bytes({"status": "ready" if ready else "not-ready"}),
            )
            return
        self._respond(
            HTTPStatus.NOT_FOUND,
            _error("not-found", "resource not found"),
        )

    def do_POST(self) -> None:
        if self.path != "/v1/admissions":
            self._respond(
                HTTPStatus.NOT_FOUND,
                _error("not-found", "resource not found"),
            )
            return
        self._admit()

    def _admit(self) -> None:
        try:
            if self.headers.get("Transfer-Encoding") is not None:
                raise GatewayError("Transfer-Encoding is not supported")
            for header_name in (
                "Content-Type",
                "Content-Length",
                *_REQUIRED_HEADERS.values(),
            ):
                values = self.headers.get_all(header_name, failobj=[])
                if len(values) > 1:
                    raise GatewayError(
                        f"header {header_name} must appear exactly once"
                    )
            media_type = self.headers.get_content_type()
            if media_type != GATEWAY_MEDIA_TYPE:
                raise GatewayError(
                    f"Content-Type must be {GATEWAY_MEDIA_TYPE}"
                )
            length_value = self.headers.get("Content-Length")
            if (
                length_value is None
                or not length_value.isascii()
                or not re.fullmatch(r"[1-9][0-9]*", length_value)
            ):
                raise GatewayError("Content-Length is required")
            try:
                length = int(length_value, 10)
            except ValueError as error:
                raise GatewayError("Content-Length is invalid") from error
            if not 1 <= length <= self.server.config.maximum_request_bytes:
                raise GatewayError("request body exceeds the safe size boundary")
            values = {
                name: _header(
                    self.headers.get(header_name),
                    label=header_name,
                    maximum=(
                        MAX_IDEMPOTENCY_KEY_BYTES
                        if name == "idempotency_key"
                        else MAX_GATEWAY_HEADER_BYTES
                    ),
                )
                for name, header_name in _REQUIRED_HEADERS.items()
            }
            if not _IDEMPOTENCY_PATTERN.fullmatch(
                values["idempotency_key"]
            ):
                raise GatewayError("Idempotency-Key is invalid")
            evaluated_on = _strict_date(
                values["evaluated_on"],
                label="X-PgExtAssure-Evaluated-On",
            )
            verified_on = _strict_date(
                values["verified_on"],
                label="X-PgExtAssure-Verified-On",
            )
            descriptor, package_name = tempfile.mkstemp(
                prefix="pgextassure-gateway-",
                suffix=".zip",
            )
            try:
                with os.fdopen(descriptor, "wb") as package:
                    remaining = length
                    while remaining:
                        chunk = self.rfile.read(min(remaining, 1024 * 1024))
                        if not chunk:
                            raise GatewayError("request body is truncated")
                        package.write(chunk)
                        remaining -= len(chunk)
                    package.flush()
                    os.fsync(package.fileno())
                digest = hashlib.sha256()
                with Path(package_name).open("rb") as package:
                    while chunk := package.read(1024 * 1024):
                        digest.update(chunk)
                body_digest = "sha256:" + digest.hexdigest()
                if body_digest != values["package_digest"]:
                    raise AdmissionEnforcementError(
                        "request body does not match the expected package digest"
                    )

                def operation() -> tuple[bytes, int]:
                    enforcement = enforce_pilot_package(
                        package_name,
                        expected_package_sha256=values["package_digest"],
                        expected_public_key_sha256=values["key_digest"],
                        expected_trust_policy_sha256=values["policy_digest"],
                        expected_request_id=values["request_id"],
                        expected_target=values["target"],
                        expected_evaluated_on=evaluated_on,
                        verified_on=verified_on,
                        openssl_path=self.server.config.openssl_path,
                    )
                    return (
                        enforcement.event,
                        (
                            HTTPStatus.OK
                            if enforcement.active
                            else HTTPStatus.CONFLICT
                        ),
                    )

                result = self.server.ledger.execute(
                    idempotency_key=values["idempotency_key"],
                    request_id=values["request_id"],
                    target=values["target"],
                    package_digest=values["package_digest"],
                    operation=operation,
                )
            finally:
                try:
                    os.unlink(package_name)
                except FileNotFoundError:
                    pass
            self._respond(
                result.status_code,
                result.event,
                replayed=result.replayed,
            )
        except GatewayConflict as error:
            self._respond(
                HTTPStatus.CONFLICT,
                _error("replay-conflict", str(error)),
            )
        except GatewayLedgerError:
            self._respond(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                _error("internal-error", "gateway operation failed"),
            )
        except GatewayError as error:
            self._respond(
                HTTPStatus.BAD_REQUEST,
                _error("invalid-request", str(error)),
            )
        except AdmissionEnforcementError as error:
            self._respond(
                HTTPStatus.UNPROCESSABLE_ENTITY,
                _error("admission-verification-failed", str(error)),
            )
        except (OSError, sqlite3.Error, socket.error):
            self._respond(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                _error("internal-error", "gateway operation failed"),
            )


def create_gateway_server(config: GatewayConfig) -> ThreadingHTTPServer:
    """Create an initialized gateway server without starting its loop."""

    validated = validate_gateway_config(config)
    ledger: Ledger
    if validated.ledger_path is not None:
        ledger = SQLiteAdmissionLedger(validated.ledger_path)
    else:
        assert validated.postgres_dsn_file is not None
        ledger = PostgreSQLAdmissionLedger(
            validated.postgres_dsn_file,
            initialize=validated.initialize_postgres_ledger,
        )
    return _GatewayServer(
        (validated.host, validated.port),
        validated,
        ledger,
    )
