#!/usr/bin/env python3
"""Rollback helper for the Codex autonomous workflow setup."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HOME = Path.home()
CODEX_HOME = HOME / ".codex"
FD_GUARDRAILS_MANIFEST = "manifest.json"
FD_GUARDRAILS_MANIFEST_KIND = "codex-runtime-fd-guardrails-backup"
FD_GUARDRAILS_LEGACY_MANIFEST_VERSION = 1
FD_GUARDRAILS_MANIFEST_VERSION = 2
# Граница защиты: каталог backup 0700 и файлы 0600 закрывают резерв от других
# пользователей; sha256 ловит повреждение или подмену байтов, но не является
# подписью против владельца, который может переписать и файл, и manifest.
FD_GUARDRAILS_TARGETS_V1 = (
    ("config.toml", "config.toml"),
    ("AGENTS.md", "AGENTS.md"),
    ("codex_fd_doctor.sh", "codex_fd_doctor.sh"),
    ("validate_wide_wave_manifest.py", "validate_wide_wave_manifest.py"),
    ("trusted-wide-wave-skills.json", "trusted-wide-wave-skills.json"),
)
FD_GUARDRAILS_TARGETS_V2_LEGACY_BASE = (
    *FD_GUARDRAILS_TARGETS_V1[:3],
    ("codex_process_inventory.py", "codex_process_inventory.py"),
    *FD_GUARDRAILS_TARGETS_V1[3:],
)
FD_GUARDRAILS_TARGETS_V2_LEGACY_FULL = (
    *FD_GUARDRAILS_TARGETS_V2_LEGACY_BASE,
    ("hooks.json", "hooks.json"),
    ("autonomous_policy.py", "autonomous_policy.py"),
    ("codex_capacity.py", "codex_capacity.py"),
    ("codex_capacity_observer.py", "codex_capacity_observer.py"),
)
PROFILE_THREAD_CAPS = {
    "batch-workers": 1,
    "deep-review": 4,
    "full-access": 4,
    "safe-readonly": 2,
    "small": 2,
    "standard": 4,
    "wide-readers-16": 16,
    "wide-readers": 8,
}
PROFILE_CONFIG_NAMES = tuple(PROFILE_THREAD_CAPS)
FD_GUARDRAILS_TARGETS_V2_LEGACY_PROFILES = (
    *FD_GUARDRAILS_TARGETS_V2_LEGACY_FULL,
    *((f"{name}.config.toml", f"{name}.config.toml") for name in PROFILE_CONFIG_NAMES),
)
FD_GUARDRAILS_TARGETS_V2_LEGACY_WITH_HIGHFD = (
    *FD_GUARDRAILS_TARGETS_V2_LEGACY_PROFILES,
    ("codex-highfd", "codex-highfd"),
)
FD_GUARDRAILS_TARGETS = (
    ("config.toml", "config.toml"),
    ("codex_fd_doctor.sh", "codex_fd_doctor.sh"),
    ("codex-highfd", "codex-highfd"),
    ("codex_process_inventory.py", "codex_process_inventory.py"),
    ("validate_wide_wave_manifest.py", "validate_wide_wave_manifest.py"),
    ("trusted-wide-wave-skills.json", "trusted-wide-wave-skills.json"),
    ("codex_capacity.py", "codex_capacity.py"),
    ("codex_capacity_observer.py", "codex_capacity_observer.py"),
)
FD_GUARDRAILS_TARGETS_V2_PRE_HIGHFD = tuple(
    target for target in FD_GUARDRAILS_TARGETS if target[0] != "codex-highfd"
)
FD_GUARDRAILS_TARGETS_V2_PRE_CAPACITY = (
    ("config.toml", "config.toml"),
    ("codex_fd_doctor.sh", "codex_fd_doctor.sh"),
    ("codex_process_inventory.py", "codex_process_inventory.py"),
    ("validate_wide_wave_manifest.py", "validate_wide_wave_manifest.py"),
    ("trusted-wide-wave-skills.json", "trusted-wide-wave-skills.json"),
)
FD_GUARDRAILS_TARGET_SETS_V2 = (
    FD_GUARDRAILS_TARGETS,
    FD_GUARDRAILS_TARGETS_V2_PRE_HIGHFD,
    FD_GUARDRAILS_TARGETS_V2_PRE_CAPACITY,
    FD_GUARDRAILS_TARGETS_V2_LEGACY_BASE,
    FD_GUARDRAILS_TARGETS_V2_LEGACY_FULL,
    FD_GUARDRAILS_TARGETS_V2_LEGACY_PROFILES,
    FD_GUARDRAILS_TARGETS_V2_LEGACY_WITH_HIGHFD,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backup",
        type=Path,
        help="Runtime backup directory or legacy config backup. Defaults to the latest available backup.",
    )
    parser.add_argument("--apply", action="store_true", help="Apply rollback. Without this flag, only print planned actions.")
    parser.add_argument(
        "--legacy-runtime-cache-rollback",
        action="store_true",
        help="Explicitly allow legacy rollback to replace plugin cache trees.",
    )
    parser.add_argument("--codex-home", type=Path, default=CODEX_HOME)
    parser.add_argument(
        "--installed-doctor",
        type=Path,
        default=HOME / ".local/libexec/codex_fd_doctor.sh",
    )
    parser.add_argument(
        "--installed-highfd",
        type=Path,
        default=HOME / ".local/bin/codex-highfd",
    )
    parser.add_argument("--installed-process-inventory", type=Path, default=None)
    parser.add_argument("--installed-manifest-validator", type=Path, default=None)
    parser.add_argument("--installed-trusted-registry", type=Path, default=None)
    parser.add_argument("--installed-hooks-json", type=Path, default=None)
    parser.add_argument("--installed-autonomous-policy", type=Path, default=None)
    parser.add_argument("--installed-capacity", type=Path, default=None)
    parser.add_argument("--installed-capacity-observer", type=Path, default=None)
    parser.add_argument(
        "--fail-after-fd-guardrails-action",
        type=int,
        choices=range(1, len(FD_GUARDRAILS_TARGETS) + 1),
        help=argparse.SUPPRESS,
    )
    parser.add_argument(
        "--fail-fd-guardrails-compensation",
        action="store_true",
        help=argparse.SUPPRESS,
    )
    args = parser.parse_args()

    codex_home = args.codex_home
    installed_manifest_validator = (
        args.installed_manifest_validator
        if args.installed_manifest_validator is not None
        else args.installed_doctor.parent / "validate_wide_wave_manifest.py"
    )
    installed_process_inventory = (
        args.installed_process_inventory
        if args.installed_process_inventory is not None
        else args.installed_doctor.parent / "codex_process_inventory.py"
    )
    installed_trusted_registry = (
        args.installed_trusted_registry
        if args.installed_trusted_registry is not None
        else codex_home / "config" / "trusted-wide-wave-skills.json"
    )
    installed_hooks_json = args.installed_hooks_json or codex_home / "hooks.json"
    installed_autonomous_policy = (
        args.installed_autonomous_policy
        or codex_home / "hooks" / "autonomous_policy.py"
    )
    installed_capacity = args.installed_capacity or installed_manifest_validator.parent / "codex_capacity.py"
    installed_capacity_observer = (
        args.installed_capacity_observer
        or installed_manifest_validator.parent / "codex_capacity_observer.py"
    )

    backup = args.backup or latest_backup(codex_home)
    if backup.is_dir():
        return handle_runtime_backup(
            backup,
            args.apply,
            codex_home=codex_home,
            installed_doctor=args.installed_doctor,
            installed_highfd=args.installed_highfd,
            installed_process_inventory=installed_process_inventory,
            installed_manifest_validator=installed_manifest_validator,
            installed_trusted_registry=installed_trusted_registry,
            installed_hooks_json=installed_hooks_json,
            installed_autonomous_policy=installed_autonomous_policy,
            installed_capacity=installed_capacity,
            installed_capacity_observer=installed_capacity_observer,
            fail_after_fd_guardrails_action=args.fail_after_fd_guardrails_action,
            fail_fd_guardrails_compensation=args.fail_fd_guardrails_compensation,
            allow_legacy_cache_restore=args.legacy_runtime_cache_rollback,
        )

    return handle_legacy_backup(backup, args.apply, codex_home=codex_home)


def handle_runtime_backup(
    backup: Path,
    apply: bool,
    *,
    codex_home: Path | None = None,
    installed_doctor: Path | None = None,
    installed_highfd: Path | None = None,
    installed_process_inventory: Path | None = None,
    installed_manifest_validator: Path | None = None,
    installed_trusted_registry: Path | None = None,
    installed_hooks_json: Path | None = None,
    installed_autonomous_policy: Path | None = None,
    installed_capacity: Path | None = None,
    installed_capacity_observer: Path | None = None,
    fail_after_fd_guardrails_action: int | None = None,
    fail_fd_guardrails_compensation: bool = False,
    allow_legacy_cache_restore: bool = False,
) -> int:
    codex_home = codex_home or CODEX_HOME
    if (backup / FD_GUARDRAILS_MANIFEST).exists() or backup.name.startswith("fd-guardrails-"):
        doctor = installed_doctor or HOME / ".local/libexec/codex_fd_doctor.sh"
        return handle_fd_guardrails_backup(
            backup,
            apply,
            target_paths=fd_guardrails_target_paths(
                codex_home=codex_home,
                installed_doctor=doctor,
                installed_highfd=installed_highfd or HOME / ".local/bin/codex-highfd",
                installed_process_inventory=installed_process_inventory
                or doctor.parent / "codex_process_inventory.py",
                installed_manifest_validator=installed_manifest_validator
                or doctor.parent / "validate_wide_wave_manifest.py",
                installed_trusted_registry=installed_trusted_registry
                or codex_home / "config" / "trusted-wide-wave-skills.json",
                installed_hooks_json=installed_hooks_json or codex_home / "hooks.json",
                installed_autonomous_policy=installed_autonomous_policy
                or codex_home / "hooks" / "autonomous_policy.py",
                installed_capacity=installed_capacity
                or doctor.parent / "codex_capacity.py",
                installed_capacity_observer=installed_capacity_observer
                or doctor.parent / "codex_capacity_observer.py",
            ),
            fail_after_action=fail_after_fd_guardrails_action,
            fail_compensation=fail_fd_guardrails_compensation,
        )

    if not allow_legacy_cache_restore:
        raise SystemExit(
            "legacy runtime cache rollback requires explicit "
            "--legacy-runtime-cache-rollback confirmation"
        )

    required = {
        "config.toml": backup / "config.toml",
        "codex-autonomous-aliases.zsh": backup / "codex-autonomous-aliases.zsh",
        "autonomous_policy.py": backup / "autonomous_policy.py",
        "home-skills": backup / "home-skills",
        "consilium-skills": backup / "consilium-skills",
        "browser-cache": backup / "browser-cache",
        "openai-bundled-marketplace": backup / "openai-bundled-marketplace",
    }
    missing = [name for name, path in required.items() if not path.exists()]
    if missing:
        raise SystemExit(f"runtime backup is incomplete: {', '.join(sorted(missing))}")

    actions = [
        f"restore {required['config.toml']} -> {codex_home / 'config.toml'}",
        f"restore {required['codex-autonomous-aliases.zsh']} -> {codex_home / 'codex-autonomous-aliases.zsh'}",
        f"restore {required['autonomous_policy.py']} -> {codex_home / 'hooks/autonomous_policy.py'}",
        f"restore home-skills from {required['home-skills']}",
        f"restore consilium-skills from {required['consilium-skills']}",
        f"restore browser-cache from {required['browser-cache']}",
        f"restore openai-bundled marketplace from {required['openai-bundled-marketplace']}",
        "leave codex-highfd and FD doctor installed but inactive under the restored aliases",
        "manually close completed/stale agents in active interactive sessions",
    ]
    if not apply:
        print("\n".join(actions))
        return 0

    shutil.copy2(required["config.toml"], codex_home / "config.toml")
    shutil.copy2(required["codex-autonomous-aliases.zsh"], codex_home / "codex-autonomous-aliases.zsh")
    shutil.copy2(required["autonomous_policy.py"], codex_home / "hooks/autonomous_policy.py")
    restore_skills(required["home-skills"], codex_home / "skills")
    restore_skills(required["consilium-skills"], consilium_skills_root(codex_home))
    replace_tree(required["browser-cache"], codex_home / "plugins/cache/openai-bundled/browser")
    replace_tree(
        required["openai-bundled-marketplace"],
        codex_home / ".tmp/bundled-marketplaces/openai-bundled",
    )
    print("\n".join(actions))
    return 0


def handle_legacy_backup(backup: Path, apply: bool, *, codex_home: Path | None = None) -> int:
    codex_home = codex_home or CODEX_HOME
    alias_file = codex_home / "codex-autonomous-aliases.zsh"
    disabled_alias_file = codex_home / f"codex-autonomous-aliases.zsh.disabled.{timestamp()}"
    config = codex_home / "config.toml"

    actions = [
        f"restore {backup} -> {config}",
        f"disable aliases by moving {alias_file} -> {disabled_alias_file}",
        "manually close completed/stale agents in active interactive sessions",
        "remove only verified task-owned disposable worktrees after artifact collection",
        "start future sessions with --profile standard or --profile safe-readonly",
    ]

    if not apply:
        print("\n".join(actions))
        return 0

    if not backup.exists():
        raise SystemExit(f"backup does not exist: {backup}")
    shutil.copy2(backup, config)
    if alias_file.exists():
        alias_file.rename(disabled_alias_file)
    print("\n".join(actions))
    return 0


def fd_guardrails_target_paths(
    *,
    codex_home: Path,
    installed_doctor: Path,
    installed_highfd: Path,
    installed_process_inventory: Path,
    installed_manifest_validator: Path,
    installed_trusted_registry: Path,
    installed_hooks_json: Path | None = None,
    installed_autonomous_policy: Path | None = None,
    installed_capacity: Path | None = None,
    installed_capacity_observer: Path | None = None,
) -> dict[str, Path]:
    return {
        "config.toml": codex_home / "config.toml",
        "AGENTS.md": codex_home / "AGENTS.md",
        "codex_fd_doctor.sh": installed_doctor,
        "codex-highfd": installed_highfd,
        "codex_process_inventory.py": installed_process_inventory,
        "validate_wide_wave_manifest.py": installed_manifest_validator,
        "trusted-wide-wave-skills.json": installed_trusted_registry,
        "hooks.json": installed_hooks_json or codex_home / "hooks.json",
        "autonomous_policy.py": installed_autonomous_policy
        or codex_home / "hooks" / "autonomous_policy.py",
        "codex_capacity.py": installed_capacity
        or installed_doctor.parent / "codex_capacity.py",
        "codex_capacity_observer.py": installed_capacity_observer
        or installed_doctor.parent / "codex_capacity_observer.py",
        **{f"{name}.config.toml": codex_home / f"{name}.config.toml" for name in PROFILE_CONFIG_NAMES},
    }


def handle_fd_guardrails_backup(
    backup: Path,
    apply: bool,
    *,
    target_paths: dict[str, Path],
    fail_after_action: int | None = None,
    fail_compensation: bool = False,
) -> int:
    manifest = read_fd_guardrails_manifest(backup)
    actions = fd_guardrails_actions(backup, manifest, target_paths)
    if not apply:
        print("\n".join(actions))
        return 0

    validate_fd_guardrails_apply_targets(manifest, target_paths)
    snapshot = capture_target_snapshot(manifest, target_paths)
    try:
        for index, entry in enumerate(fd_guardrails_compensation_targets(manifest), start=1):
            target = target_paths[entry["id"]]
            if entry["existed"]:
                atomic_write_file(target, (backup / entry["backup"]).read_bytes(), int(entry["mode"], 8))
            elif target.exists():
                ensure_regular_target(target, context="rollback target")
                target.unlink()
            if fail_after_action == index:
                raise RuntimeError(f"injected fd-guardrails rollback failure after action {index}")
    except BaseException as exc:
        try:
            if fail_compensation:
                raise RuntimeError("injected fd-guardrails compensation failure")
            restore_target_snapshot(snapshot)
        except BaseException as compensation_error:
            marker = backup / ".rollback-compensation-failed"
            write_diagnostic_marker(marker, f"{compensation_error}; original error: {exc}\n")
            raise SystemExit(
                f"fd-guardrails rollback failed and automatic compensation failed: {compensation_error}; original error: {exc}"
            ) from compensation_error
        raise SystemExit(
            f"fd-guardrails rollback failed; automatic compensation restored pre-rollback state: {exc}"
        ) from exc
    print("\n".join(actions))
    return 0


def fd_guardrails_actions(
    backup: Path,
    manifest: dict[str, Any],
    target_paths: dict[str, Path],
) -> list[str]:
    actions: list[str] = []
    validate_fd_guardrails_targets(manifest, target_paths)
    for entry in fd_guardrails_compensation_targets(manifest):
        target = target_paths[entry["id"]]
        if entry["existed"]:
            actions.append(f"restore {entry['backup']} -> {target}")
        else:
            actions.append(f"remove absent-before-install target {target}")
    return actions


def fd_guardrails_compensation_targets(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    targets = manifest["targets"]
    if targets and "compensation_order" in targets[0]:
        return sorted(targets, key=lambda entry: entry["compensation_order"])
    return list(targets)


def read_fd_guardrails_manifest(backup: Path) -> dict[str, Any]:
    manifest_path = backup / FD_GUARDRAILS_MANIFEST
    if backup.is_symlink() or not backup.is_dir():
        raise SystemExit(f"fd-guardrails backup is unsafe: {backup}")
    if backup.stat().st_uid != os.getuid() or stat.S_IMODE(backup.stat().st_mode) != 0o700:
        raise SystemExit(f"fd-guardrails backup permissions are unsafe: {backup}")
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise SystemExit(f"fd-guardrails manifest is missing or unsafe: {manifest_path}")
    if manifest_path.stat().st_uid != os.getuid() or stat.S_IMODE(manifest_path.stat().st_mode) != 0o600:
        raise SystemExit(f"fd-guardrails manifest permissions are unsafe: {manifest_path}")
    try:
        document = json.loads(
            manifest_path.read_text(encoding="utf-8"),
            parse_constant=reject_json_constant,
        )
    except (json.JSONDecodeError, ValueError) as exc:
        raise SystemExit(f"fd-guardrails manifest is invalid JSON: {exc}") from exc
    validate_fd_guardrails_manifest_document(backup, document)
    return document


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is unsupported: {value}")


def validate_fd_guardrails_manifest_document(backup: Path, document: Any) -> None:
    if not isinstance(document, dict):
        raise SystemExit("fd-guardrails manifest must be an object")
    if document.get("kind") != FD_GUARDRAILS_MANIFEST_KIND:
        raise SystemExit("fd-guardrails manifest kind is unsupported")
    version = document.get("version")
    if version == FD_GUARDRAILS_LEGACY_MANIFEST_VERSION:
        expected_document_fields = {"kind", "version", "targets"}
        expected_targets = FD_GUARDRAILS_TARGETS_V1
        expected_target_fields = {"id", "backup", "existed", "mode", "sha256"}
    elif version == FD_GUARDRAILS_MANIFEST_VERSION:
        expected_document_fields = {
            "kind",
            "version",
            "source_commit",
            "created_at",
            "targets",
        }
        legacy_v2_target_fields = {
            "id",
            "backup",
            "existed",
            "mode",
            "sha256",
            "target_path",
            "installed_mode",
            "installed_sha256",
        }
    else:
        raise SystemExit("fd-guardrails manifest version is unsupported")
    if set(document) != expected_document_fields:
        raise SystemExit("fd-guardrails manifest has unexpected fields")
    if version == FD_GUARDRAILS_MANIFEST_VERSION:
        if not isinstance(document["source_commit"], str) or not re.fullmatch(
            r"[0-9a-f]{40}", document["source_commit"]
        ):
            raise SystemExit("fd-guardrails manifest source commit is invalid")
        if not isinstance(document["created_at"], str):
            raise SystemExit("fd-guardrails manifest creation time is invalid")
        try:
            created_at = datetime.fromisoformat(document["created_at"])
        except ValueError as exc:
            raise SystemExit("fd-guardrails manifest creation time is invalid") from exc
        if created_at.tzinfo is None:
            raise SystemExit("fd-guardrails manifest creation time must include a timezone")
    targets = document["targets"]
    if not isinstance(targets, list):
        raise SystemExit("fd-guardrails manifest has incomplete targets")
    if version == FD_GUARDRAILS_MANIFEST_VERSION:
        target_ids = [
            entry.get("id") if isinstance(entry, dict) else None
            for entry in targets
        ]
        supported_target_ids = [
            tuple(target_id for target_id, _ in target_set)
            for target_set in FD_GUARDRAILS_TARGET_SETS_V2
        ]
        if tuple(target_ids) not in supported_target_ids:
            raise SystemExit("fd-guardrails manifest has unsupported v2 target set")
        expected_targets = next(
            target_set
            for target_set in FD_GUARDRAILS_TARGET_SETS_V2
            if tuple(target_id for target_id, _ in target_set) == tuple(target_ids)
        )
    if len(targets) != len(expected_targets):
        raise SystemExit("fd-guardrails manifest has incomplete targets")
    expected = dict(expected_targets)
    uses_compensation_metadata = False
    if version == FD_GUARDRAILS_MANIFEST_VERSION:
        metadata_fields = {"source_sha256", "compensation_order"}
        observed_field_sets = {frozenset(entry) for entry in targets if isinstance(entry, dict)}
        if len(observed_field_sets) != 1 or not all(isinstance(entry, dict) for entry in targets):
            raise SystemExit("fd-guardrails manifest target has unexpected fields")
        observed_fields = next(iter(observed_field_sets))
        extended_fields = legacy_v2_target_fields | metadata_fields
        if observed_fields == extended_fields:
            uses_compensation_metadata = True
            expected_target_fields = extended_fields
        elif observed_fields == legacy_v2_target_fields and expected_targets != FD_GUARDRAILS_TARGETS:
            expected_target_fields = legacy_v2_target_fields
        else:
            raise SystemExit("fd-guardrails manifest target has unexpected fields")
    observed_ids: set[str] = set()
    compensation_orders: list[int] = []
    expected_files = {FD_GUARDRAILS_MANIFEST}
    for entry in targets:
        if not isinstance(entry, dict) or set(entry) != expected_target_fields:
            raise SystemExit("fd-guardrails manifest target has unexpected fields")
        target_id = entry["id"]
        if target_id not in expected or target_id in observed_ids:
            raise SystemExit("fd-guardrails manifest has unexpected targets")
        observed_ids.add(target_id)
        if entry["backup"] != expected[target_id] or Path(entry["backup"]).name != entry["backup"]:
            raise SystemExit("fd-guardrails manifest backup names are unsupported")
        if not isinstance(entry["existed"], bool):
            raise SystemExit("fd-guardrails manifest existence marker is invalid")
        if version == FD_GUARDRAILS_MANIFEST_VERSION:
            if not isinstance(entry["target_path"], str) or not Path(entry["target_path"]).is_absolute():
                raise SystemExit("fd-guardrails manifest target path is invalid")
            if not isinstance(entry["installed_mode"], str) or not re.fullmatch(
                r"0o[0-7]{3,4}", entry["installed_mode"]
            ):
                raise SystemExit("fd-guardrails manifest installed mode is invalid")
            if not isinstance(entry["installed_sha256"], str) or not re.fullmatch(
                r"[0-9a-f]{64}", entry["installed_sha256"]
            ):
                raise SystemExit("fd-guardrails manifest installed sha256 is invalid")
            if uses_compensation_metadata:
                if not isinstance(entry["source_sha256"], str) or not re.fullmatch(
                    r"[0-9a-f]{64}", entry["source_sha256"]
                ):
                    raise SystemExit("fd-guardrails manifest source sha256 is invalid")
                if type(entry["compensation_order"]) is not int:
                    raise SystemExit("fd-guardrails manifest compensation order is invalid")
                compensation_orders.append(entry["compensation_order"])
        if entry["existed"]:
            if not isinstance(entry["mode"], str) or not re.fullmatch(r"0o[0-7]{3,4}", entry["mode"]):
                raise SystemExit("fd-guardrails manifest mode is invalid")
            try:
                mode = int(entry["mode"], 8)
            except ValueError as exc:
                raise SystemExit("fd-guardrails manifest mode is invalid") from exc
            if mode < 0 or mode > 0o7777:
                raise SystemExit("fd-guardrails manifest mode is invalid")
            backup_file = backup / entry["backup"]
            if backup_file.is_symlink() or not backup_file.is_file():
                raise SystemExit("fd-guardrails manifest references a missing backup file")
            if backup_file.stat().st_uid != os.getuid() or stat.S_IMODE(backup_file.stat().st_mode) != 0o600:
                raise SystemExit("fd-guardrails backup file permissions are unsafe")
            if not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"]):
                raise SystemExit("fd-guardrails manifest sha256 is invalid")
            observed_sha = sha256_bytes(backup_file.read_bytes())
            if observed_sha != entry["sha256"]:
                raise SystemExit("fd-guardrails backup sha256 mismatch")
            expected_files.add(entry["backup"])
        else:
            if entry["mode"] is not None:
                raise SystemExit("fd-guardrails manifest absent target mode must be null")
            if entry["sha256"] is not None:
                raise SystemExit("fd-guardrails manifest absent target sha256 must be null")
    if observed_ids != set(expected):
        raise SystemExit("fd-guardrails manifest target set is incomplete")
    if uses_compensation_metadata and sorted(compensation_orders) != list(range(1, len(targets) + 1)):
        raise SystemExit("fd-guardrails manifest compensation order is invalid")
    actual_files = {entry.name for entry in backup.iterdir()}
    if actual_files != expected_files:
        raise SystemExit("fd-guardrails backup contains unexpected files")


def validate_fd_guardrails_targets(
    manifest: dict[str, Any],
    target_paths: dict[str, Path],
) -> None:
    supported_ids = {
        target_id
        for target_set in (FD_GUARDRAILS_TARGETS_V1, *FD_GUARDRAILS_TARGET_SETS_V2)
        for target_id, _ in target_set
    }
    manifest_ids = {entry["id"] for entry in manifest["targets"]}
    if not manifest_ids.issubset(supported_ids) or not manifest_ids.issubset(target_paths):
        raise SystemExit("fd-guardrails rollback target paths are incomplete")
    for entry in manifest["targets"]:
        target = target_paths[entry["id"]]
        if manifest["version"] == FD_GUARDRAILS_MANIFEST_VERSION and entry["target_path"] != str(target.resolve(strict=False)):
            raise SystemExit(f"fd-guardrails rollback target path mismatch: {entry['id']}")
        validate_target_parent(target, required=target.exists())
        ensure_regular_target(target, context="rollback target")


def validate_fd_guardrails_apply_targets(
    manifest: dict[str, Any],
    target_paths: dict[str, Path],
) -> None:
    for entry in manifest["targets"]:
        target = target_paths[entry["id"]]
        validate_target_parent(target, required=bool(entry["existed"]) or target.exists())
        ensure_regular_target(target, context="rollback target")


def ensure_regular_target(path: Path, *, context: str) -> None:
    if path.is_symlink():
        raise SystemExit(f"{context} is a symlink: {path}")
    if path.exists() and not path.is_file():
        raise SystemExit(f"{context} has unexpected type: {path}")


def validate_target_parent(path: Path, *, required: bool) -> None:
    parent = path.parent
    if parent.is_symlink():
        raise SystemExit(f"rollback target parent is a symlink: {parent}")
    if parent.exists() and not parent.is_dir():
        raise SystemExit(f"rollback target parent has unexpected type: {parent}")
    if required and not parent.is_dir():
        raise SystemExit(f"rollback target parent is missing: {parent}")


def capture_target_snapshot(
    manifest: dict[str, Any],
    target_paths: dict[str, Path],
) -> dict[str, dict[str, Any]]:
    snapshot: dict[str, dict[str, Any]] = {}
    for manifest_entry in manifest["targets"]:
        target_id = manifest_entry["id"]
        target = target_paths[target_id]
        validate_target_parent(target, required=target.exists())
        ensure_regular_target(target, context="rollback target")
        if target.exists():
            snapshot[target_id] = {
                "path": target,
                "existed": True,
                "data": target.read_bytes(),
                "mode": target.stat().st_mode & 0o7777,
            }
        else:
            snapshot[target_id] = {"path": target, "existed": False, "data": None, "mode": None}
    return snapshot


def restore_target_snapshot(snapshot: dict[str, dict[str, Any]]) -> None:
    for entry in snapshot.values():
        target = entry["path"]
        if entry["existed"]:
            atomic_write_file(target, entry["data"], entry["mode"])
        elif target.exists():
            ensure_regular_target(target, context="compensation target")
            target.unlink()


def atomic_write_file(path: Path, data: bytes, mode: int) -> None:
    validate_target_parent(path, required=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
            os.fchmod(stream.fileno(), mode)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def write_diagnostic_marker(path: Path, text: str) -> None:
    atomic_write_file(path, text.encode("utf-8"), 0o600)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def is_supported_fd_guardrails_backup(backup: Path) -> bool:
    try:
        read_fd_guardrails_manifest(backup)
    except SystemExit:
        return False
    return True


def restore_skills(source_dir: Path, target_root: Path) -> None:
    for source in sorted(source_dir.glob("*.SKILL.md")):
        skill_name = source.name.removesuffix(".SKILL.md")
        target = target_root / skill_name / "SKILL.md"
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def replace_tree(source: Path, target: Path) -> None:
    if target.is_symlink() or target.is_file():
        target.unlink()
    elif target.exists():
        shutil.rmtree(target)
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(source, target)


def consilium_skills_root(codex_home: Path | None = None) -> Path:
    codex_home = codex_home or CODEX_HOME
    roots = sorted((codex_home / "plugins/cache/agents-skills/consilium").glob("*/skills"))
    if not roots:
        raise SystemExit("installed Consilium runtime is missing")
    return roots[-1]


def latest_backup(codex_home: Path | None = None) -> Path:
    codex_home = codex_home or CODEX_HOME
    fd_guardrails_backups = [
        backup
        for backup in sorted((codex_home / "backups").glob("fd-guardrails-*"))
        if is_supported_fd_guardrails_backup(backup)
    ]
    if fd_guardrails_backups:
        return fd_guardrails_backups[-1]
    runtime_backups = sorted((codex_home / "backups").glob("runtime-fd-*"))
    if runtime_backups:
        return runtime_backups[-1]
    backups = sorted((codex_home / "backups").glob("config.toml.*.bak"))
    if not backups:
        raise SystemExit("no config backups found under ~/.codex/backups")
    return backups[-1]


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


if __name__ == "__main__":
    raise SystemExit(main())
