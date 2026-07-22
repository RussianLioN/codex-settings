"""Нормативная проекция и отпечаток схемы SQLite версии 2."""

from __future__ import annotations

import hashlib
import re
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator

from .canonical_json import CanonicalJsonError, canonical_json_bytes, domain_fingerprint
from .operation_deadline_v2 import (
    checkpoint_current_operation_deadline_if_scoped_v2,
)


APPLICATION_ID = 1_129_529_650
SCHEMA_PROJECTION_VERSION = "database-schema-projection-v1"
SQL_NORMALIZATION_VERSION = "sqlite-schema-sql-normalization-v1"


class SchemaProjectionError(ValueError):
    """Схему или значение нельзя безопасно привести к нормативной форме."""


@dataclass(frozen=True)
class SchemaFingerprint:
    projection: dict[str, Any]
    canonical_bytes: bytes
    canonical_size: int
    fingerprint: str


def canonical_json_v1(value: Any) -> bytes:
    """Переэкспортировать общий кодировщик с ошибкой слоя схемы."""

    try:
        return canonical_json_bytes(value)
    except CanonicalJsonError as error:
        raise SchemaProjectionError(str(error)) from error


def normalize_schema_sql(value: str) -> str:
    """Нормализовать SQL из sqlite_schema единственным конечным автоматом."""

    if type(value) is not str:
        raise SchemaProjectionError("schema SQL must be a string")
    value = value.replace("\r\n", "\n")
    result: list[str] = []
    pending_space = False
    quote: str | None = None
    index = 0
    while index < len(value):
        character = value[index]
        if quote is not None:
            result.append(character)
            closing = "]" if quote == "[" else quote
            if character == closing:
                if index + 1 < len(value) and value[index + 1] == closing:
                    result.append(closing)
                    index += 1
                else:
                    quote = None
            index += 1
            continue
        if character in "'\"`[":
            if pending_space and result:
                result.append(" ")
            pending_space = False
            quote = character
            result.append(character)
            index += 1
            continue
        if value.startswith("--", index) or value.startswith("/*", index):
            raise SchemaProjectionError("comments outside quoted SQL are forbidden")
        if character in "\t\n\v\f\r ":
            pending_space = True
            index += 1
            continue
        if pending_space and result:
            result.append(" ")
        pending_space = False
        result.append(character)
        index += 1
    if quote is not None:
        raise SchemaProjectionError("unterminated quoted SQL token")
    return "".join(result).strip()


def _utf8_key(*values: str | int) -> tuple[bytes | int, ...]:
    return tuple(
        value.encode("utf-8") if isinstance(value, str) else value
        for value in values
    )


def _pragma_string(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def database_schema_projection(connection: sqlite3.Connection) -> dict[str, Any]:
    """Построить полную закрытую проекцию фактически открытой базы."""

    sqlite_schema = [
        {
            "type": str(row[0]),
            "name": str(row[1]),
            "table": str(row[2]),
            "sql": normalize_schema_sql(str(row[3]))
            if row[3] is not None
            else None,
        }
        for row in connection.execute(
            "select type, name, tbl_name, sql from sqlite_schema"
        )
    ]
    sqlite_schema.sort(
        key=lambda item: _utf8_key(item["type"], item["name"], item["table"])
    )
    table_names = sorted(
        (item["name"] for item in sqlite_schema if item["type"] == "table"),
        key=lambda value: value.encode("utf-8"),
    )

    table_xinfo: list[dict[str, Any]] = []
    foreign_key_list: list[dict[str, Any]] = []
    index_list: list[dict[str, Any]] = []
    index_xinfo: list[dict[str, Any]] = []
    for table in table_names:
        argument = _pragma_string(table)
        for row in connection.execute(f"pragma table_xinfo({argument})"):
            table_xinfo.append(
                {
                    "table": table,
                    "cid": int(row[0]),
                    "name": str(row[1]),
                    "type": str(row[2]),
                    "notNull": int(row[3]),
                    "defaultValue": str(row[4]) if row[4] is not None else None,
                    "primaryKey": int(row[5]),
                    "hidden": int(row[6]),
                }
            )
        for row in connection.execute(f"pragma foreign_key_list({argument})"):
            foreign_key_list.append(
                {
                    "table": table,
                    "id": int(row[0]),
                    "sequence": int(row[1]),
                    "referencedTable": str(row[2]),
                    "from": str(row[3]),
                    "to": str(row[4]) if row[4] is not None else None,
                    "onUpdate": str(row[5]),
                    "onDelete": str(row[6]),
                    "match": str(row[7]),
                }
            )
        for row in connection.execute(f"pragma index_list({argument})"):
            index_name = str(row[1])
            index_list.append(
                {
                    "table": table,
                    "name": index_name,
                    "unique": int(row[2]),
                    "origin": str(row[3]),
                    "partial": int(row[4]),
                }
            )
            for index_row in connection.execute(
                f"pragma index_xinfo({_pragma_string(index_name)})"
            ):
                index_xinfo.append(
                    {
                        "table": table,
                        "index": index_name,
                        "sequence": int(index_row[0]),
                        "columnId": int(index_row[1]),
                        "columnName": str(index_row[2])
                        if index_row[2] is not None
                        else None,
                        "descending": int(index_row[3]),
                        "collation": str(index_row[4])
                        if index_row[4] is not None
                        else None,
                        "key": int(index_row[5]),
                    }
                )

    table_xinfo.sort(key=lambda item: _utf8_key(item["table"], item["cid"]))
    foreign_key_list.sort(
        key=lambda item: _utf8_key(
            item["table"], item["id"], item["sequence"]
        )
    )
    index_list.sort(key=lambda item: _utf8_key(item["table"], item["name"]))
    index_xinfo.sort(
        key=lambda item: _utf8_key(
            item["table"], item["index"], item["sequence"]
        )
    )
    return {
        "applicationId": int(connection.execute("pragma application_id").fetchone()[0]),
        "userVersion": int(connection.execute("pragma user_version").fetchone()[0]),
        "sqliteSchema": sqlite_schema,
        "tableXinfo": table_xinfo,
        "foreignKeyList": foreign_key_list,
        "indexList": index_list,
        "indexXinfo": index_xinfo,
        "sqliteSequencePresent": any(
            item["name"] == "sqlite_sequence" for item in sqlite_schema
        ),
    }


def database_schema_fingerprint(
    connection: sqlite3.Connection, *, version: int
) -> SchemaFingerprint:
    if version not in (1, 2):
        raise SchemaProjectionError("database schema fingerprint version must be 1 or 2")
    projection = database_schema_projection(connection)
    canonical = canonical_json_v1(projection)
    try:
        fingerprint = domain_fingerprint(
            f"codex-smart/database-schema/v{version}", projection
        )
    except CanonicalJsonError as error:
        raise SchemaProjectionError(str(error)) from error
    return SchemaFingerprint(
        projection=projection,
        canonical_bytes=canonical,
        canonical_size=len(canonical),
        fingerprint=fingerprint,
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while True:
            checkpoint_current_operation_deadline_if_scoped_v2()
            block = stream.read(1024 * 1024)
            if not block:
                return digest.hexdigest()
            digest.update(block)


def read_schema_artifact(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(b"\xef\xbb\xbf"):
        raise SchemaProjectionError("schema artifact must not contain a UTF-8 BOM")
    if b"\r" in raw:
        raise SchemaProjectionError("schema artifact must use LF line endings")
    if not raw.endswith(b"\n"):
        raise SchemaProjectionError("schema artifact must end with LF")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SchemaProjectionError("schema artifact must be UTF-8") from error
    forbidden = {
        "comments": r"--|/\*",
        "conditional creation": r"\bif\s+not\s+exists\b",
        "triggers": r"\bcreate\s+trigger\b",
        "dynamic attachment": r"\battach\b",
        "vacuum": r"\bvacuum\b",
        "journal mode": r"\bpragma\s+journal_mode\b",
    }
    for label, pattern in forbidden.items():
        if re.search(pattern, text, flags=re.IGNORECASE):
            raise SchemaProjectionError(f"schema artifact contains forbidden {label}")
    return text


@contextmanager
def create_database_from_schema_artifact(
    path: Path,
) -> Iterator[sqlite3.Connection]:
    text = read_schema_artifact(path)
    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        connection.execute("pragma foreign_keys=ON")
        connection.execute("pragma trusted_schema=OFF")
        connection.execute("pragma synchronous=FULL")
        connection.execute("pragma secure_delete=FAST")
        connection.execute("pragma busy_timeout=5000")
        connection.execute(f"pragma application_id={APPLICATION_ID}")
        connection.executescript(text)
        connection.execute("pragma user_version=2")
        yield connection
    finally:
        connection.close()
