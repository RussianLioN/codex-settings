#!/usr/bin/env python3
"""Воспроизвести нормативную схему v2 и 38 исторических форм SQLite."""

from __future__ import annotations

import ast
import json
import sqlite3
import subprocess
import sys
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
PLUGIN_SRC = ROOT / "plugins" / "codex-smart-subagents" / "src"
SCHEMA_DIR = PLUGIN_SRC / "codex_smart_subagents" / "schema"
sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.schema_projection import (  # noqa: E402
    APPLICATION_ID,
    SCHEMA_PROJECTION_VERSION,
    SchemaProjectionError,
    SQL_NORMALIZATION_VERSION,
    canonical_json_v1,
    create_database_from_schema_artifact,
    database_schema_fingerprint,
    sha256_file,
)


class ValidationError(RuntimeError):
    """Артефакт не соответствует нормативному договору."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValidationError(message)


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ValidationError(f"duplicate manifest key: {key}")
        value[key] = item
    return value


def _reject_number(value: str) -> Any:
    raise ValidationError(f"unsupported manifest number: {value}")


def load_manifest(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    require(not raw.startswith(b"\xef\xbb\xbf"), "manifest contains UTF-8 BOM")
    require(b"\r" not in raw, "manifest must use LF line endings")
    require(raw.endswith(b"\n"), "manifest must end with LF")
    try:
        loaded = json.loads(
            raw,
            object_pairs_hook=_reject_duplicate_keys,
            parse_float=_reject_number,
            parse_constant=_reject_number,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("manifest is not strict UTF-8 JSON") from error
    require(type(loaded) is dict, "manifest root must be an object")
    canonical_json_v1(loaded)
    return loaded


def git_source(commit: str, path: str) -> str:
    require(
        len(commit) == 40
        and all(character in "0123456789abcdef" for character in commit),
        f"source commit is not a full SHA-1: {commit}",
    )
    resolved = subprocess.run(
        ["git", "rev-parse", "--verify", f"{commit}^{{commit}}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    require(resolved.returncode == 0, f"source commit is unavailable: {commit}")
    require(resolved.stdout.strip() == commit, f"source commit changed: {commit}")
    shown = subprocess.run(
        ["git", "show", f"{commit}:{path}"],
        cwd=ROOT,
        check=False,
        capture_output=True,
    )
    require(shown.returncode == 0, f"source path is unavailable at {commit}")
    try:
        return shown.stdout.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValidationError(f"source path is not UTF-8 at {commit}") from error


def _function(tree: ast.AST, name: str) -> ast.FunctionDef:
    matches = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == name
    ]
    require(len(matches) == 1, f"expected one historical method {name}")
    return matches[0]


def extract_executescript(source: str, method: str) -> str:
    function = _function(ast.parse(source), method)
    scripts: list[str] = []
    for node in ast.walk(function):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "executescript"
            and len(node.args) == 1
            and isinstance(node.args[0], ast.Constant)
            and type(node.args[0].value) is str
        ):
            scripts.append(node.args[0].value)
    require(len(scripts) == 1, f"expected one executescript in {method}")
    return scripts[0]


def split_sql_statements(script: str) -> list[str]:
    statements: list[str] = []
    buffer = ""
    for line in script.splitlines(keepends=True):
        buffer += line
        if sqlite3.complete_statement(buffer):
            statements.append(buffer)
            buffer = ""
    require(not buffer.strip(), "historical executescript has an incomplete tail")
    return statements


def extract_binding_alters(source: str) -> list[str]:
    function = _function(ast.parse(source), "_ensure_turn_binding_request_schema")
    candidates: list[list[str]] = []
    for loop in ast.walk(function):
        if not (
            isinstance(loop, ast.For)
            and isinstance(loop.target, ast.Name)
            and isinstance(loop.iter, (ast.Tuple, ast.List))
        ):
            continue
        names = [
            item.value
            for item in loop.iter.elts
            if isinstance(item, ast.Constant) and type(item.value) is str
        ]
        if len(names) != len(loop.iter.elts):
            continue
        for node in ast.walk(loop):
            if not (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "execute"
                and node.args
                and isinstance(node.args[0], ast.JoinedStr)
            ):
                continue
            statements: list[str] = []
            for name in names:
                parts: list[str] = []
                for part in node.args[0].values:
                    if isinstance(part, ast.Constant) and type(part.value) is str:
                        parts.append(part.value)
                    elif (
                        isinstance(part, ast.FormattedValue)
                        and isinstance(part.value, ast.Name)
                        and part.value.id == loop.target.id
                    ):
                        parts.append(name)
                    else:
                        raise ValidationError(
                            "historical binding ALTER f-string is not closed"
                        )
                statements.append("".join(parts))
            candidates.append(statements)
    require(len(candidates) == 1, "expected one historical binding ALTER chain")
    return candidates[0]


def _configure_legacy(connection: sqlite3.Connection) -> None:
    connection.execute("pragma foreign_keys=ON")
    connection.execute("pragma trusted_schema=OFF")
    connection.execute("pragma synchronous=FULL")
    connection.execute("pragma secure_delete=FAST")
    connection.execute("pragma busy_timeout=5000")
    connection.execute(f"pragma application_id={APPLICATION_ID}")


def explicit_objects(connection: sqlite3.Connection) -> set[str]:
    return {
        str(row[0])
        for row in connection.execute(
            "select name from sqlite_schema "
            "where type in ('table', 'index') and name not glob 'sqlite_*'"
        )
    }


def assert_application_tables_empty(connection: sqlite3.Connection) -> None:
    table_names = [
        str(row[0])
        for row in connection.execute(
            "select name from sqlite_schema "
            "where type = 'table' and name not glob 'sqlite_*'"
        )
    ]
    for table_name in table_names:
        quoted = '"' + table_name.replace('"', '""') + '"'
        count = int(connection.execute(f"select count(*) from {quoted}").fetchone()[0])
        require(count == 0, f"generated legacy table is not empty: {table_name}")


def generate_legacy_shape(
    recipe: dict[str, Any],
    *,
    base_scripts: dict[str, list[str]],
    binding_alters: list[str],
    runtime_scripts: list[str],
    candidate_scripts: list[str],
) -> sqlite3.Connection:
    required_fields = {
        "baseSource",
        "basePrefix",
        "setUserVersion",
        "alterBinding",
        "runtimePrefix",
        "candidatePrefix",
    }
    require(set(recipe) == required_fields, "legacy recipe has unexpected fields")
    base_source = recipe["baseSource"]
    require(base_source in base_scripts, f"unknown base source: {base_source}")
    base_prefix = recipe["basePrefix"]
    runtime_prefix = recipe["runtimePrefix"]
    candidate_prefix = recipe["candidatePrefix"]
    require(
        type(base_prefix) is int and 0 <= base_prefix <= len(base_scripts[base_source]),
        "base prefix is outside the pinned chain",
    )
    require(
        type(runtime_prefix) is int and 0 <= runtime_prefix <= len(runtime_scripts),
        "runtime prefix is outside the pinned chain",
    )
    require(
        type(candidate_prefix) is int
        and 0 <= candidate_prefix <= len(candidate_scripts),
        "candidate prefix is outside the pinned chain",
    )
    user_version = recipe["setUserVersion"]
    require(user_version in (0, 1), "legacy recipe has an unsupported user_version")
    require(
        type(recipe["alterBinding"]) is bool,
        "legacy recipe alterBinding must be boolean",
    )
    require(
        user_version == 1
        or (
            not recipe["alterBinding"]
            and runtime_prefix == 0
            and candidate_prefix == 0
        ),
        "user_version=0 recipe includes a post-base migration",
    )

    connection = sqlite3.connect(":memory:", isolation_level=None)
    try:
        _configure_legacy(connection)
        for statement in base_scripts[base_source][:base_prefix]:
            connection.executescript(statement)
        connection.execute(f"pragma user_version={user_version}")
        if recipe["alterBinding"]:
            for statement in binding_alters:
                connection.execute(statement)
        for statement in runtime_scripts[:runtime_prefix]:
            connection.executescript(statement)
        for statement in candidate_scripts[:candidate_prefix]:
            connection.executescript(statement)
        return connection
    except Exception:
        connection.close()
        raise


def validate_normative_schema(manifest: dict[str, Any]) -> None:
    sql_path = SCHEMA_DIR / "state-v2.sql"
    require(manifest["schemaVersion"] == 2, "manifest schemaVersion is not 2")
    require(manifest["applicationId"] == APPLICATION_ID, "applicationId changed")
    require(
        manifest["projectionVersion"] == SCHEMA_PROJECTION_VERSION,
        "projection version changed",
    )
    require(
        manifest["normalizationVersion"] == SQL_NORMALIZATION_VERSION,
        "SQL normalization version changed",
    )
    require(
        manifest["stateSqlSha256"] == sha256_file(sql_path),
        "state-v2.sql SHA-256 differs from manifest",
    )
    with create_database_from_schema_artifact(sql_path) as connection:
        require(
            connection.execute("pragma quick_check").fetchall() == [("ok",)],
            "state-v2 quick_check failed",
        )
        require(
            connection.execute("pragma foreign_key_check").fetchall() == [],
            "state-v2 foreign_key_check failed",
        )
        result = database_schema_fingerprint(connection, version=2)
    require(
        manifest["schemaFingerprint"] == result.fingerprint,
        "state-v2 schema fingerprint differs from manifest",
    )
    require(
        manifest["schemaCanonicalSize"] == result.canonical_size,
        "state-v2 canonical projection size differs from manifest",
    )


def validate_legacy_shapes(manifest: dict[str, Any]) -> tuple[int, int]:
    source_path = manifest["sourcePath"]
    source_commits = manifest["sourceCommits"]
    require(
        set(source_commits)
        == {"executionBase", "runtimeArtifacts", "candidateRegistry"},
        "source commit set is not closed",
    )
    sources = {
        name: git_source(commit, source_path)
        for name, commit in source_commits.items()
    }
    base_scripts = {
        "executionBase": split_sql_statements(
            extract_executescript(sources["executionBase"], "_migrate")
        ),
        "candidateRegistry": split_sql_statements(
            extract_executescript(sources["candidateRegistry"], "_migrate")
        ),
    }
    runtime_scripts = split_sql_statements(
        extract_executescript(
            sources["runtimeArtifacts"], "_ensure_runtime_artifacts_schema"
        )
    )
    candidate_scripts = split_sql_statements(
        extract_executescript(
            sources["candidateRegistry"], "_ensure_candidate_registry_schema"
        )
    )
    binding_alters = extract_binding_alters(sources["candidateRegistry"])
    require(
        {name: len(statements) for name, statements in base_scripts.items()}
        == {"executionBase": 9, "candidateRegistry": 9},
        "historical base object chains no longer contain nine groups",
    )
    require(len(binding_alters) == 2, "historical binding chain is not two ALTERs")
    require(len(runtime_scripts) == 2, "historical runtime chain is not two groups")
    require(len(candidate_scripts) == 5, "historical candidate chain is not five groups")

    explicit = manifest["legacyExplicitObjects"]
    require(
        type(explicit) is list
        and len(explicit) == 16
        and len(set(explicit)) == len(explicit)
        and all(type(name) is str and name for name in explicit),
        "legacy explicit object set is invalid",
    )
    explicit_set = set(explicit)
    legacy = manifest["legacyShapes"]
    require(set(legacy) == {"userVersion0", "userVersion1"}, "legacy groups changed")
    require(len(legacy["userVersion0"]) == 19, "expected 19 user_version=0 shapes")
    require(len(legacy["userVersion1"]) == 19, "expected 19 user_version=1 shapes")
    seen_names: set[str] = set()
    seen_keys: set[tuple[int, str]] = set()
    expected_predicates = {
        "all-application-tables-empty": {
            "kind": "empty",
            "scope": "all-existing-application-tables",
        },
        "runtime-artifacts-empty": {
            "kind": "empty",
            "tables": ["runtime_artifacts"],
        },
        "candidate-prefix-empty": {
            "kind": "empty",
            "scope": "all-existing-candidate-group-tables",
        },
        "legacy-quiescence-v2": {
            "kind": "external-proof",
            "schemaId": "quiescence-proof-v2",
            "proofKind": "legacy-migration",
        },
    }
    require(
        manifest["legacyDataPredicates"] == expected_predicates,
        "legacy data predicate definitions changed",
    )
    for group_name, expected_version in (("userVersion0", 0), ("userVersion1", 1)):
        for item in legacy[group_name]:
            require(
                set(item)
                == {
                    "name",
                    "fingerprint",
                    "canonicalSize",
                    "recipe",
                    "missingObjects",
                    "dataPredicate",
                },
                "legacy shape has unexpected fields",
            )
            name = item["name"]
            require(type(name) is str and name not in seen_names, "duplicate shape name")
            seen_names.add(name)
            require(
                item["dataPredicate"] in expected_predicates,
                f"unknown data predicate for {name}",
            )
            connection = generate_legacy_shape(
                item["recipe"],
                base_scripts=base_scripts,
                binding_alters=binding_alters,
                runtime_scripts=runtime_scripts,
                candidate_scripts=candidate_scripts,
            )
            try:
                require(
                    connection.execute("pragma quick_check").fetchall() == [("ok",)],
                    f"legacy quick_check failed for {name}",
                )
                require(
                    connection.execute("pragma foreign_key_check").fetchall() == [],
                    f"legacy foreign_key_check failed for {name}",
                )
                actual_version = int(
                    connection.execute("pragma user_version").fetchone()[0]
                )
                require(
                    actual_version == expected_version,
                    f"legacy user_version differs for {name}",
                )
                assert_application_tables_empty(connection)
                result = database_schema_fingerprint(connection, version=1)
                require(
                    result.fingerprint == item["fingerprint"],
                    f"legacy fingerprint differs for {name}: {result.fingerprint}",
                )
                require(
                    result.canonical_size == item["canonicalSize"],
                    f"legacy canonical size differs for {name}: {result.canonical_size}",
                )
                actual_objects = explicit_objects(connection)
                require(
                    actual_objects <= explicit_set,
                    f"legacy shape has unknown objects for {name}",
                )
                require(
                    explicit_set - actual_objects == set(item["missingObjects"]),
                    f"legacy missing object set differs for {name}",
                )
                key = (expected_version, result.fingerprint)
                require(key not in seen_keys, f"duplicate version/fingerprint for {name}")
                seen_keys.add(key)
            finally:
                connection.close()
    require(len(seen_names) == 38, "legacy shape name set is not 38")
    return len(legacy["userVersion0"]), len(legacy["userVersion1"])


def main() -> int:
    try:
        manifest = load_manifest(SCHEMA_DIR / "state-v2.manifest.json")
        validate_normative_schema(manifest)
        user_version0, user_version1 = validate_legacy_shapes(manifest)
    except (
        KeyError,
        TypeError,
        ValidationError,
        SchemaProjectionError,
        sqlite3.Error,
    ) as error:
        print(str(error), file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "status": "ok",
                "legacyShapes": user_version0 + user_version1,
                "userVersion0": user_version0,
                "userVersion1": user_version1,
                "schemaFingerprint": manifest["schemaFingerprint"],
                "stateSqlSha256": manifest["stateSqlSha256"],
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
