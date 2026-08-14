#!/usr/bin/env python3
"""Проверить и применить ограничители истощения ресурсов Codex."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import shlex
import stat
import subprocess
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path


SAFE_THREAD_CAP = 20
PUBLIC_THREAD_CAP_KEY = "max_concurrent_threads_per_session"
LEGACY_AGENT_THREAD_KEY = "max_threads"
LEGACY_NATIVE_THREAD_KEY = "max_concurrent_threads_per_session"
SOURCE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_PROCESS_INVENTORY = SOURCE_ROOT / "scripts" / "codex_process_inventory.py"
SOURCE_HIGHFD = SOURCE_ROOT / "scripts" / "codex-highfd"
SOURCE_CAPACITY = SOURCE_ROOT / "scripts" / "codex_capacity.py"
SOURCE_CAPACITY_OBSERVER = SOURCE_ROOT / "scripts" / "codex_capacity_observer.py"
SOURCE_MANIFEST_VALIDATOR = SOURCE_ROOT / "scripts" / "validate_wide_wave_manifest.py"
SOURCE_TRUSTED_WIDE_WAVE_REGISTRY = SOURCE_ROOT / "config" / "trusted-wide-wave-skills.json"
MANAGED_SOURCE_IDS = (
    "codex_fd_doctor.sh",
    "codex-highfd",
    "codex_process_inventory.py",
    "validate_wide_wave_manifest.py",
    "trusted-wide-wave-skills.json",
    "codex_capacity.py",
    "codex_capacity_observer.py",
)
SCRIPT_DIR = Path(__file__).resolve().parent
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))
from codex_autonomous_rollback import (  # noqa: E402
    FD_GUARDRAILS_MANIFEST,
    FD_GUARDRAILS_MANIFEST_KIND,
    FD_GUARDRAILS_MANIFEST_VERSION,
    FD_GUARDRAILS_TARGETS,
    PROFILE_CONFIG_NAMES,
    PROFILE_THREAD_CAPS,
    fd_guardrails_target_paths,
    handle_fd_guardrails_backup,
    read_fd_guardrails_manifest,
)
POLICY_START = "<!-- codex-runtime-fd-guardrails:start -->"
POLICY_END = "<!-- codex-runtime-fd-guardrails:end -->"
LEGACY_PARTIAL_REQUIRED_FILES = {
    "AGENTS.md",
    "config.toml",
}
LEGACY_PARTIAL_OPTIONAL_FILES = {"codex_fd_doctor.sh"}
HOOK_EVENTS = (
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "SubagentStart",
    "SubagentStop",
    "Stop",
    "SessionEnd",
)
SHORT_HOOK_TIMEOUT_SECONDS = 1
SESSION_END_HOOK_TIMEOUT_SECONDS = 3
HOOK_TRUST_REVIEW_REQUIRED = "hook_trust_review_required=true"
HOOK_TRUST_REVIEW_ACTION = "Откройте /hooks и подтвердите изменённые hooks"
POLICY_BLOCK = f"""{POLICY_START}
## Ограничение ресурсов субагентов

- Одновременно запускай не более 6 живых субагентов; значение 20 является аварийным потолком сеанса, а не размером обычной волны.
- Перед каждой новой волной выполняй `~/.local/bin/codex-highfd --fd-doctor --wave-size N`; `BLOCK` запрещает новые запуски, а `WARN` разрешает только волну не больше 6.
- Для доверенной широкой волны 7-20 выполняй `~/.local/bin/codex-highfd --fd-doctor --wave-size N --skill-id ID --skill-file PATH --manifest PATH`; все три параметра доверия обязательны, а любой `WARN` запрещает широкую волну.
- роли широкой волны не запускают вложенное делегирование; широкая волна является плоским набором участников с заранее заданным манифестом.
- 20 узлов умного графа маршрутизатора являются аварийным графовым потолком, а не разрешением запускать обычную или недоверенную широкую волну.
- Назначай один интегратор для общих или генерируемых файлов; остальные пишущие участники получают непересекающиеся области записи.
- При `Too many open files` или `EMFILE` немедленно прекрати новые запуски, собери уже готовые ответы и заверши либо закрой все доступные дочерние нити до продолжения.
{POLICY_END}"""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--codex-home", type=Path, default=Path.home() / ".codex")
    parser.add_argument(
        "--installed-doctor",
        type=Path,
        default=Path.home() / ".local/libexec/codex_fd_doctor.sh",
    )
    parser.add_argument(
        "--source-doctor",
        type=Path,
        default=Path(__file__).resolve().with_name("codex_fd_doctor.sh"),
    )
    parser.add_argument(
        "--installed-highfd",
        type=Path,
        default=Path.home() / ".local/bin/codex-highfd",
    )
    parser.add_argument(
        "--source-highfd",
        type=Path,
        default=SOURCE_HIGHFD,
    )
    parser.add_argument("--installed-process-inventory", type=Path, default=None)
    parser.add_argument(
        "--source-process-inventory",
        type=Path,
        default=SOURCE_PROCESS_INVENTORY,
    )
    parser.add_argument("--installed-capacity", type=Path, default=None)
    parser.add_argument(
        "--source-capacity",
        type=Path,
        default=SOURCE_CAPACITY,
    )
    parser.add_argument("--installed-capacity-observer", type=Path, default=None)
    parser.add_argument(
        "--source-capacity-observer",
        type=Path,
        default=SOURCE_CAPACITY_OBSERVER,
    )
    parser.add_argument(
        "--installed-manifest-validator",
        type=Path,
        default=None,
    )
    parser.add_argument(
        "--source-manifest-validator",
        type=Path,
        default=SOURCE_MANIFEST_VALIDATOR,
    )
    parser.add_argument(
        "--installed-trusted-registry",
        type=Path,
        default=None,
        help="default: CODEX_HOME/config/trusted-wide-wave-skills.json",
    )
    parser.add_argument(
        "--source-trusted-registry",
        type=Path,
        default=SOURCE_TRUSTED_WIDE_WAVE_REGISTRY,
    )
    parser.add_argument("--timestamp")
    parser.add_argument(
        "--source-commit",
        help="40-character Git commit recorded in the installation receipt",
    )
    parser.add_argument(
        "--migrate-legacy-backup",
        metavar="YYYYMMDD-HHMM[SS]",
        help="rename a legacy partial runtime-fd backup outside the rollback namespace",
    )
    parser.add_argument(
        "--fail-after-atomic-write",
        type=int,
        choices=range(1, len(FD_GUARDRAILS_TARGETS) + 1),
        help=argparse.SUPPRESS,
    )
    return parser.parse_args()


def upsert_table_integer(text: str, table: str, key: str, value: int) -> str:
    lines = text.splitlines()
    final_newline = text.endswith("\n")
    header = f"[{table}]"
    header_pattern = re.compile(rf"^\s*{re.escape(header)}(?:\s*#.*)?$")
    table_indexes = [
        index for index, line in enumerate(lines) if header_pattern.fullmatch(line)
    ]
    if len(table_indexes) > 1:
        raise ValueError(f"duplicate TOML table: {table}")
    if not table_indexes:
        if lines and lines[-1].strip():
            lines.append("")
        lines.extend((header, f"{key} = {value}"))
    else:
        start = table_indexes[0]
        end = next(
            (index for index in range(start + 1, len(lines)) if lines[index].lstrip().startswith("[")),
            len(lines),
        )
        pattern = re.compile(rf"^(?P<indent>\s*){re.escape(key)}\s*=")
        matches = [index for index in range(start + 1, end) if pattern.match(lines[index])]
        if len(matches) > 1:
            raise ValueError(f"duplicate TOML key: {table}.{key}")
        if matches:
            match = pattern.match(lines[matches[0]])
            assert match is not None
            lines[matches[0]] = f"{match.group('indent')}{key} = {value}"
        else:
            lines.insert(start + 1, f"{key} = {value}")
    rendered = "\n".join(lines)
    return rendered + ("\n" if final_newline else "")


def remove_table_key(text: str, table: str, key: str) -> str:
    lines = text.splitlines()
    final_newline = text.endswith("\n")
    header = f"[{table}]"
    header_pattern = re.compile(rf"^\s*{re.escape(header)}(?:\s*#.*)?$")
    table_indexes = [
        index for index, line in enumerate(lines) if header_pattern.fullmatch(line)
    ]
    if len(table_indexes) > 1:
        raise ValueError(f"duplicate TOML table: {table}")
    if not table_indexes:
        return text
    start = table_indexes[0]
    end = next(
        (index for index in range(start + 1, len(lines)) if lines[index].lstrip().startswith("[")),
        len(lines),
    )
    pattern = re.compile(rf"^\s*{re.escape(key)}\s*=")
    matches = [index for index in range(start + 1, end) if pattern.match(lines[index])]
    if len(matches) > 1:
        raise ValueError(f"duplicate TOML key: {table}.{key}")
    if matches:
        del lines[matches[0]]
    rendered = "\n".join(lines)
    return rendered + ("\n" if final_newline else "")


def desired_config(text: str) -> str:
    tomllib.loads(text)
    text = remove_table_key(text, "agents", LEGACY_AGENT_THREAD_KEY)
    text = remove_table_key(text, "features.multi_agent_v2", LEGACY_NATIVE_THREAD_KEY)
    text = upsert_table_integer(text, "agents", PUBLIC_THREAD_CAP_KEY, SAFE_THREAD_CAP)
    parsed = tomllib.loads(text)
    if parsed["agents"][PUBLIC_THREAD_CAP_KEY] != SAFE_THREAD_CAP:
        raise ValueError(f"agents.{PUBLIC_THREAD_CAP_KEY} repair failed")
    if LEGACY_AGENT_THREAD_KEY in parsed["agents"]:
        raise ValueError(f"agents.{LEGACY_AGENT_THREAD_KEY} removal failed")
    if (
        LEGACY_NATIVE_THREAD_KEY
        in parsed.get("features", {}).get("multi_agent_v2", {})
    ):
        raise ValueError("native session thread cap removal failed")
    return text


def desired_profile_config(text: str, profile_name: str) -> str:
    parsed = tomllib.loads(text)
    agents = parsed.get("agents")
    if not isinstance(agents, dict):
        raise ValueError(f"{profile_name}: missing agents table")
    has_legacy = LEGACY_AGENT_THREAD_KEY in agents
    has_public = PUBLIC_THREAD_CAP_KEY in agents
    if has_legacy and has_public:
        raise ValueError(f"{profile_name}: duplicate agent thread cap keys")
    if has_legacy:
        value = validate_profile_thread_cap(agents[LEGACY_AGENT_THREAD_KEY], profile_name)
        text = remove_table_key(text, "agents", LEGACY_AGENT_THREAD_KEY)
        return upsert_table_integer(text, "agents", PUBLIC_THREAD_CAP_KEY, value)
    if has_public:
        validate_profile_thread_cap(agents[PUBLIC_THREAD_CAP_KEY], profile_name)
        return text
    raise ValueError(f"{profile_name}: missing agent thread cap")


def validate_profile_thread_cap(value: object, profile_name: str) -> int:
    expected = PROFILE_THREAD_CAPS[profile_name]
    if type(value) is not int:
        raise ValueError(f"{profile_name}: agent thread cap must be an integer")
    if not 1 <= value <= SAFE_THREAD_CAP:
        raise ValueError(f"{profile_name}: agent thread cap must be in 1..20")
    if value != expected:
        raise ValueError(f"{profile_name}: agent thread cap must be {expected}")
    return value


def desired_agents(text: str) -> str:
    start_count = text.count(POLICY_START)
    end_count = text.count(POLICY_END)
    if (start_count, end_count) == (0, 0):
        return text.rstrip() + "\n\n" + POLICY_BLOCK + "\n"
    if (start_count, end_count) != (1, 1):
        raise ValueError("managed AGENTS.md block markers are inconsistent")
    start = text.index(POLICY_START)
    end = text.index(POLICY_END, start) + len(POLICY_END)
    return text[:start] + POLICY_BLOCK + text[end:]


def desired_hooks_json(text: str, policy_path: Path) -> str:
    document = strict_json_loads(text) if text.strip() else {}
    if not isinstance(document, dict):
        raise ValueError("hooks.json must contain an object")
    hooks = document.setdefault("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("hooks.json hooks field must contain an object")
    managed_policy_paths = known_managed_policy_paths(policy_path)
    for event in HOOK_EVENTS:
        entries = hooks.setdefault(event, [])
        if not isinstance(entries, list):
            raise ValueError(f"hooks.json event must contain a list: {event}")
        managed_entry = autonomous_policy_hook_entry(policy_path, event)
        managed_hook = managed_entry["hooks"][0]
        replacement_done = False
        preserved_entries = []
        for entry in entries:
            replaced_entry, replaced = hook_entry_with_autonomous_policy_replaced(
                entry,
                managed_hook,
                managed_policy_paths,
                replace=not replacement_done,
            )
            if replaced:
                replacement_done = True
            if replaced_entry is not None:
                preserved_entries.append(replaced_entry)
        if not replacement_done:
            preserved_entries.append(managed_entry)
        hooks[event] = preserved_entries
    return strict_json_dumps(document) + "\n"


def strict_json_loads(text: str) -> object:
    return json.loads(text, parse_constant=reject_json_constant)


def reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON value is unsupported: {value}")


def strict_json_dumps(document: object) -> str:
    return json.dumps(document, ensure_ascii=False, indent=2, allow_nan=False)


def autonomous_policy_hook_entry(policy_path: Path, event: str) -> dict[str, object]:
    timeout = (
        SESSION_END_HOOK_TIMEOUT_SECONDS
        if event == "SessionEnd"
        else SHORT_HOOK_TIMEOUT_SECONDS
    )
    return {
        "hooks": [
            {
                "type": "command",
                "command": autonomous_policy_command(policy_path, event),
                "timeout": timeout,
                "statusMessage": "Проверка общей ёмкости Codex",
            }
        ]
    }


def autonomous_policy_command(policy_path: Path, event: str) -> str:
    return " ".join(("/usr/bin/python3", shlex.quote(str(policy_path)), shlex.quote(event)))


def hook_entry_with_autonomous_policy_replaced(
    entry: object,
    managed_hook: object,
    managed_policy_paths: set[Path],
    *,
    replace: bool,
) -> tuple[object | None, bool]:
    if not isinstance(entry, dict):
        return entry, False
    nested_hooks = entry.get("hooks")
    if not isinstance(nested_hooks, list):
        return entry, False
    kept_hooks = []
    replaced = False
    for hook in nested_hooks:
        if not isinstance(hook, dict):
            kept_hooks.append(hook)
            continue
        command = hook.get("command")
        if isinstance(command, str) and hook_command_is_autonomous_policy(command, managed_policy_paths):
            if replace and not replaced:
                kept_hooks.append(managed_hook)
                replaced = True
            continue
        kept_hooks.append(hook)
    if not kept_hooks:
        return None, replaced
    stripped = dict(entry)
    stripped["hooks"] = kept_hooks
    return stripped, replaced


def known_managed_policy_paths(policy_path: Path) -> set[Path]:
    current = policy_path.expanduser().resolve(strict=False)
    hooks_root = current.parent
    return {
        current,
        (hooks_root / "old" / "autonomous_policy.py").resolve(strict=False),
        (hooks_root / "legacy" / "autonomous_policy.py").resolve(strict=False),
    }


def hook_command_is_autonomous_policy(command: str, managed_policy_paths: set[Path]) -> bool:
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    for token in tokens:
        candidate = Path(token).expanduser()
        if not candidate.is_absolute():
            continue
        if candidate.resolve(strict=False) in managed_policy_paths:
            return True
    return False


def normalize_existing_path(path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        expanded = Path.cwd() / expanded
    return expanded.resolve(strict=False)


def normalize_managed_path(path: Path) -> Path:
    expanded = path.expanduser()
    candidate = (expanded if expanded.is_absolute() else Path.cwd() / expanded).absolute()
    validate_managed_parent(candidate)
    return candidate


def path_group_or_world_writable(mode: int) -> bool:
    return bool(mode & 0o022)


def allowed_system_symlink_parent(path: Path) -> bool:
    return path in {Path("/tmp"), Path("/var")}


def allowed_system_writable_parent(path: Path, mode: int, uid: int) -> bool:
    return path in {Path("/private/tmp"), Path("/tmp")} and uid == 0 and bool(mode & stat.S_ISVTX)


def state_issues(
    *,
    config_path: Path,
    installed_doctor: Path,
    source_doctor: Path,
    installed_highfd: Path,
    source_highfd: Path,
    installed_process_inventory: Path,
    source_process_inventory: Path,
    installed_manifest_validator: Path,
    source_manifest_validator: Path,
    installed_trusted_registry: Path,
    source_trusted_registry: Path,
    installed_capacity: Path,
    source_capacity: Path,
    installed_capacity_observer: Path,
    source_capacity_observer: Path,
) -> list[str]:
    issues: list[str] = []
    parsed = tomllib.loads(config_path.read_text(encoding="utf-8"))
    agents = parsed.get("agents", {})
    multi_agent_v2 = parsed.get("features", {}).get("multi_agent_v2", {})
    if agents.get(PUBLIC_THREAD_CAP_KEY) != SAFE_THREAD_CAP:
        issues.append("agents_max_concurrent_threads_not_20")
    if LEGACY_AGENT_THREAD_KEY in agents:
        issues.append("agents_max_threads_legacy_present")
    if LEGACY_NATIVE_THREAD_KEY in multi_agent_v2:
        issues.append("native_session_thread_cap_legacy_present")
    if not installed_doctor.is_file() or installed_doctor.read_bytes() != source_doctor.read_bytes():
        issues.append("installed_fd_doctor_drifted")
    if not installed_highfd.is_file() or installed_highfd.read_bytes() != source_highfd.read_bytes():
        issues.append("installed_highfd_drifted")
    if (
        not installed_process_inventory.is_file()
        or installed_process_inventory.read_bytes() != source_process_inventory.read_bytes()
    ):
        issues.append("installed_process_inventory_drifted")
    if (
        not installed_manifest_validator.is_file()
        or installed_manifest_validator.read_bytes() != source_manifest_validator.read_bytes()
    ):
        issues.append("installed_wide_wave_manifest_validator_drifted")
    if (
        not installed_trusted_registry.is_file()
        or installed_trusted_registry.read_bytes() != source_trusted_registry.read_bytes()
    ):
        issues.append("installed_trusted_wide_wave_registry_drifted")
    if not installed_capacity.is_file() or installed_capacity.read_bytes() != source_capacity.read_bytes():
        issues.append("installed_capacity_drifted")
    if (
        not installed_capacity_observer.is_file()
        or installed_capacity_observer.read_bytes() != source_capacity_observer.read_bytes()
    ):
        issues.append("installed_capacity_observer_drifted")
    return issues


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    validate_managed_parent(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    validate_managed_parent(path)
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


def file_mode(path: Path, fallback: int) -> int:
    return stat.S_IMODE(path.stat().st_mode) if path.exists() else fallback


def checked_existing_file(path: Path) -> tuple[bool, int | None]:
    validate_managed_parent(path)
    if path.is_symlink():
        raise SystemExit(f"managed target is a symlink: {path}")
    if path.exists() and not path.is_file():
        raise SystemExit(f"managed target has unexpected type: {path}")
    if not path.exists():
        return False, None
    file_stat = path.stat()
    if file_stat.st_uid != os.getuid():
        raise SystemExit(f"managed target owner is unsafe: {path}")
    if file_stat.st_nlink != 1:
        raise SystemExit(f"managed target hardlink count is unsafe: {path}")
    return True, stat.S_IMODE(file_stat.st_mode)


def validate_managed_parent(path: Path) -> None:
    current = path.parent
    ancestors: list[Path] = []
    while True:
        if current.exists() or current.is_symlink():
            ancestors.append(current)
        if current.parent == current:
            break
        current = current.parent
    for parent in reversed(ancestors):
        parent_stat = parent.lstat()
        if stat.S_ISLNK(parent_stat.st_mode):
            if allowed_system_symlink_parent(parent):
                continue
            raise SystemExit(f"managed target parent is a symlink: {parent}")
        if not stat.S_ISDIR(parent_stat.st_mode):
            raise SystemExit(f"managed target parent has unexpected type: {parent}")
        if parent_stat.st_uid not in {os.getuid(), 0}:
            raise SystemExit(f"managed target parent owner is unsafe: {parent}")
        if path_group_or_world_writable(parent_stat.st_mode) and not allowed_system_writable_parent(
            parent,
            parent_stat.st_mode,
            parent_stat.st_uid,
        ):
            raise SystemExit(f"managed target parent permissions are unsafe: {parent}")


def validate_managed_directory(path: Path) -> None:
    if path.is_symlink():
        raise SystemExit(f"managed directory is a symlink: {path}")
    if not path.is_dir():
        raise SystemExit(f"managed directory has unexpected type: {path}")
    directory_stat = path.stat()
    if directory_stat.st_uid != os.getuid():
        raise SystemExit(f"managed directory owner is unsafe: {path}")
    if path_group_or_world_writable(directory_stat.st_mode):
        raise SystemExit(f"managed directory permissions are unsafe: {path}")


def create_managed_directory(path: Path, mode: int) -> None:
    if path.is_symlink():
        raise SystemExit(f"managed directory is a symlink: {path}")
    validate_managed_parent(path)
    path.mkdir(parents=True, mode=mode)
    validate_managed_parent(path)
    validate_managed_directory(path)
    path.chmod(mode)
    validate_managed_directory(path)


def create_fd_guardrails_backup(
    backup: Path,
    *,
    target_paths: dict[str, Path],
    desired_artifacts: dict[str, tuple[bytes, int]],
    source_commit: str,
    created_at: str,
) -> None:
    if backup.exists():
        raise SystemExit(f"backup already exists: {backup}")
    create_managed_directory(backup, 0o700)
    targets = []
    expected_ids = {target_id for target_id, _ in FD_GUARDRAILS_TARGETS}
    if not expected_ids.issubset(target_paths) or set(desired_artifacts) != expected_ids:
        raise SystemExit("managed backup targets are incomplete")
    for write_index, (target_id, backup_name) in enumerate(FD_GUARDRAILS_TARGETS, start=1):
        target = target_paths[target_id]
        existed, mode = checked_existing_file(target)
        data = target.read_bytes() if existed else None
        installed_data, installed_mode = desired_artifacts[target_id]
        targets.append(
            {
                "id": target_id,
                "backup": backup_name,
                "existed": existed,
                "mode": f"0o{mode:03o}" if mode is not None else None,
                "sha256": hashlib.sha256(data).hexdigest() if data is not None else None,
                "target_path": str(target.resolve(strict=False)),
                "installed_mode": f"0o{installed_mode:03o}",
                "installed_sha256": hashlib.sha256(installed_data).hexdigest(),
                "source_sha256": hashlib.sha256(installed_data).hexdigest(),
                "compensation_order": len(FD_GUARDRAILS_TARGETS) - write_index + 1,
            }
        )
        if existed:
            backup_file = backup / backup_name
            assert data is not None
            atomic_write(backup_file, data, 0o600)
    manifest = {
        "kind": FD_GUARDRAILS_MANIFEST_KIND,
        "version": FD_GUARDRAILS_MANIFEST_VERSION,
        "source_commit": source_commit,
        "created_at": created_at,
        "targets": targets,
    }
    manifest_path = backup / FD_GUARDRAILS_MANIFEST
    atomic_write(
        manifest_path,
        (json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        0o600,
    )


def rollback_after_failed_apply(
    *,
    backup: Path,
    target_paths: dict[str, Path],
    cause: BaseException,
) -> None:
    try:
        with contextlib.redirect_stdout(io.StringIO()):
            handle_fd_guardrails_backup(backup, True, target_paths=target_paths)
    except BaseException as rollback_error:
        marker = backup / ".rollback-failed"
        atomic_write(marker, str(rollback_error).encode("utf-8"), 0o600)
        raise SystemExit(
            f"apply failed after mutation and automatic rollback failed: {rollback_error}; original error: {cause}"
        ) from rollback_error
    raise SystemExit(f"apply failed after mutation; automatic rollback applied: {cause}") from cause


def migrate_legacy_partial_backup(codex_home: Path, suffix: str) -> Path:
    if not re.fullmatch(r"[0-9]{8}-[0-9]{4}(?:[0-9]{2})?", suffix):
        raise SystemExit("invalid legacy backup suffix: expected YYYYMMDD-HHMM[SS]")
    backup_root = codex_home / "backups"
    source = backup_root / f"runtime-fd-{suffix}"
    destination = backup_root / f"fd-guardrails-{suffix}"
    validate_managed_parent(backup_root / ".migration-probe")
    validate_managed_directory(backup_root)
    validate_managed_parent(destination)
    if source.is_symlink() or not source.is_dir():
        raise SystemExit(f"legacy partial backup is missing or unsafe: {source}")
    entries = list(source.iterdir())
    entry_names = {entry.name for entry in entries}
    if not LEGACY_PARTIAL_REQUIRED_FILES.issubset(entry_names) or not entry_names.issubset(
        LEGACY_PARTIAL_REQUIRED_FILES | LEGACY_PARTIAL_OPTIONAL_FILES
    ):
        raise SystemExit(f"legacy partial backup has unexpected contents: {source}")
    if any(entry.is_symlink() or not entry.is_file() for entry in entries):
        raise SystemExit(f"legacy partial backup contains unsafe entries: {source}")
    if destination.exists():
        raise SystemExit(f"migrated backup already exists: {destination}")
    source.chmod(0o700)
    (source / "config.toml").chmod(0o600)
    os.replace(source, destination)
    return destination


def run_git(
    args: list[str],
    *,
    cwd: Path,
    text: bool = True,
) -> subprocess.CompletedProcess[str] | subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "-C", str(cwd), *args],
            text=text,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise SystemExit("cannot verify managed source commit: git is unavailable") from exc


def resolve_source_commit(explicit: str | None) -> str:
    if explicit is not None:
        source_commit = explicit.strip()
    else:
        completed = run_git(["rev-parse", "HEAD"], cwd=SOURCE_ROOT)
        if completed.returncode != 0:
            raise SystemExit(f"cannot resolve source commit: {completed.stderr.strip()}")
        source_commit = completed.stdout.strip()
    if not re.fullmatch(r"[0-9a-f]{40}", source_commit):
        raise SystemExit("invalid source commit: expected 40 lowercase hexadecimal characters")
    return source_commit


def managed_source_paths(
    *,
    source_doctor: Path,
    source_highfd: Path,
    source_process_inventory: Path,
    source_manifest_validator: Path,
    source_trusted_registry: Path,
    source_capacity: Path,
    source_capacity_observer: Path,
) -> dict[str, Path]:
    return {
        "codex_fd_doctor.sh": source_doctor,
        "codex-highfd": source_highfd,
        "codex_process_inventory.py": source_process_inventory,
        "validate_wide_wave_manifest.py": source_manifest_validator,
        "trusted-wide-wave-skills.json": source_trusted_registry,
        "codex_capacity.py": source_capacity,
        "codex_capacity_observer.py": source_capacity_observer,
    }


def verify_managed_sources_at_commit(
    source_paths: dict[str, Path],
    source_commit: str,
) -> tuple[list[str], dict[str, bytes]]:
    issues: list[str] = []
    source_bytes: dict[str, bytes] = {}
    if set(source_paths) != set(MANAGED_SOURCE_IDS):
        raise SystemExit("managed source set is incomplete")
    roots_by_id: dict[str, Path] = {}
    relpaths_by_id: dict[str, str] = {}
    for source_id in MANAGED_SOURCE_IDS:
        source_path = source_paths[source_id]
        root_result = run_git(["rev-parse", "--show-toplevel"], cwd=source_path.parent)
        if root_result.returncode != 0:
            issues.append(f"managed_source_git_root_missing:{source_id}")
            continue
        repo_root = Path(root_result.stdout.strip()).resolve(strict=False)
        resolved_source = source_path.resolve(strict=False)
        try:
            relpath = resolved_source.relative_to(repo_root).as_posix()
        except ValueError:
            issues.append(f"managed_source_outside_git:{source_id}")
            continue
        roots_by_id[source_id] = repo_root
        relpaths_by_id[source_id] = relpath
    for repo_root in sorted(set(roots_by_id.values())):
        head_result = run_git(["rev-parse", "--verify", "HEAD^{commit}"], cwd=repo_root)
        if head_result.returncode != 0:
            issues.append(f"managed_source_head_missing:{repo_root}")
        commit_result = run_git(["cat-file", "-e", f"{source_commit}^{{commit}}"], cwd=repo_root)
        if commit_result.returncode != 0:
            issues.append(f"managed_source_commit_missing:{repo_root}")
    if issues:
        return issues, {}
    for source_id in MANAGED_SOURCE_IDS:
        source_path = source_paths[source_id]
        repo_root = roots_by_id[source_id]
        relpath = relpaths_by_id[source_id]
        status_result = run_git(["status", "--porcelain=v1", "--", relpath], cwd=repo_root)
        if status_result.returncode != 0:
            issues.append(f"managed_source_status_unavailable:{source_id}")
            continue
        status_lines = [line for line in status_result.stdout.splitlines() if line]
        if any(line.startswith(("??", "!!")) for line in status_lines):
            issues.append(f"managed_source_untracked:{source_id}")
            continue
        if status_lines:
            issues.append(f"managed_source_status_dirty:{source_id}")
        committed_result = run_git(["show", f"{source_commit}:{relpath}"], cwd=repo_root, text=False)
        if committed_result.returncode != 0:
            issues.append(f"managed_source_commit_file_missing:{source_id}")
            continue
        current = source_path.read_bytes()
        if current != committed_result.stdout:
            issues.append(f"managed_source_drifted:{source_id}")
            continue
        source_bytes[source_id] = current
    if issues:
        return issues, {}
    return [], source_bytes


def installation_receipt_issues(
    *,
    codex_home: Path,
    target_paths: dict[str, Path],
    source_commit: str,
) -> list[str]:
    candidates = sorted(
        backup
        for backup in (codex_home / "backups").glob("fd-guardrails-*")
        if (backup / FD_GUARDRAILS_MANIFEST).exists()
    )
    if not candidates:
        return ["installation_receipt_v2_missing"]
    try:
        receipt = read_fd_guardrails_manifest(candidates[-1])
    except SystemExit:
        return ["installation_receipt_invalid"]
    if receipt["version"] != FD_GUARDRAILS_MANIFEST_VERSION:
        return ["installation_receipt_v2_missing"]
    issues: list[str] = []
    expected_ids = tuple(target_id for target_id, _backup_name in FD_GUARDRAILS_TARGETS)
    observed_ids = tuple(entry.get("id") for entry in receipt["targets"])
    if observed_ids != expected_ids:
        return ["installation_receipt_target_set_drifted"]
    if receipt["source_commit"] != source_commit:
        issues.append("installation_receipt_source_commit_drifted")
    for entry in receipt["targets"]:
        target = target_paths[entry["id"]]
        if entry["target_path"] != str(target.resolve(strict=False)):
            issues.append(f"installation_receipt_target_path_drifted:{entry['id']}")
            continue
        if target.is_symlink() or not target.is_file():
            issues.append(f"installation_receipt_target_missing:{entry['id']}")
            continue
        if hashlib.sha256(target.read_bytes()).hexdigest() != entry["installed_sha256"]:
            issues.append(f"installation_receipt_target_hash_drifted:{entry['id']}")
        if entry.get("source_sha256") != entry["installed_sha256"]:
            issues.append(f"installation_receipt_source_hash_drifted:{entry['id']}")
        if stat.S_IMODE(target.stat().st_mode) != int(entry["installed_mode"], 8):
            issues.append(f"installation_receipt_target_mode_drifted:{entry['id']}")
    return issues


def issues_require_hook_trust_review(issues: list[str]) -> bool:
    prefixes = (
        "installed_hooks_json",
        "installed_autonomous_policy",
        "installed_capacity",
        "installed_capacity_observer",
        "installation_receipt",
    )
    return any(issue.startswith(prefixes) for issue in issues)


def main() -> int:
    args = parse_args()
    if args.timestamp is not None and not re.fullmatch(r"[0-9]{8}-[0-9]{6}", args.timestamp):
        raise SystemExit("invalid timestamp: expected YYYYMMDD-HHMMSS")
    codex_home = normalize_managed_path(args.codex_home)
    installed_doctor = normalize_managed_path(args.installed_doctor)
    source_doctor = normalize_existing_path(args.source_doctor)
    installed_highfd = normalize_managed_path(args.installed_highfd)
    source_highfd = normalize_existing_path(args.source_highfd)
    source_process_inventory = normalize_existing_path(args.source_process_inventory)
    source_capacity = normalize_existing_path(args.source_capacity)
    source_capacity_observer = normalize_existing_path(args.source_capacity_observer)
    source_manifest_validator = normalize_existing_path(args.source_manifest_validator)
    source_trusted_registry = normalize_existing_path(args.source_trusted_registry)
    config_path = codex_home / "config.toml"
    installed_trusted_registry = (
        normalize_managed_path(args.installed_trusted_registry)
        if args.installed_trusted_registry is not None
        else codex_home / "config" / "trusted-wide-wave-skills.json"
    )
    installed_manifest_validator = (
        normalize_managed_path(args.installed_manifest_validator)
        if args.installed_manifest_validator is not None
        else installed_doctor.parent / "validate_wide_wave_manifest.py"
    )
    installed_process_inventory = (
        normalize_managed_path(args.installed_process_inventory)
        if args.installed_process_inventory is not None
        else installed_doctor.parent / "codex_process_inventory.py"
    )
    installed_capacity = (
        normalize_managed_path(args.installed_capacity)
        if args.installed_capacity is not None
        else installed_doctor.parent / "codex_capacity.py"
    )
    installed_capacity_observer = (
        normalize_managed_path(args.installed_capacity_observer)
        if args.installed_capacity_observer is not None
        else installed_doctor.parent / "codex_capacity_observer.py"
    )
    target_paths = fd_guardrails_target_paths(
        codex_home=codex_home,
        installed_doctor=installed_doctor,
        installed_highfd=installed_highfd,
        installed_process_inventory=installed_process_inventory,
        installed_manifest_validator=installed_manifest_validator,
        installed_trusted_registry=installed_trusted_registry,
        installed_capacity=installed_capacity,
        installed_capacity_observer=installed_capacity_observer,
    )
    source_commit = resolve_source_commit(args.source_commit)
    source_paths = managed_source_paths(
        source_doctor=source_doctor,
        source_highfd=source_highfd,
        source_process_inventory=source_process_inventory,
        source_manifest_validator=source_manifest_validator,
        source_trusted_registry=source_trusted_registry,
        source_capacity=source_capacity,
        source_capacity_observer=source_capacity_observer,
    )
    for path in (config_path,):
        if not path.is_file():
            raise SystemExit(f"required file is missing: {path}")
    missing_source_ids = [
        source_id for source_id, path in source_paths.items() if not path.is_file()
    ]
    if missing_source_ids:
        print("status=BLOCK")
        print("issues=" + ",".join(f"managed_source_bundle_missing:{source_id}" for source_id in missing_source_ids))
        return 2
    source_issues, source_bytes = verify_managed_sources_at_commit(source_paths, source_commit)
    if args.apply and source_issues:
        print("status=BLOCK")
        print(f"issues={','.join(source_issues)}")
        return 2

    migrated_backup: Path | None = None
    if args.migrate_legacy_backup is not None:
        if not args.apply:
            raise SystemExit("--migrate-legacy-backup requires --apply")
        migrated_backup = migrate_legacy_partial_backup(
            codex_home,
            args.migrate_legacy_backup,
        )

    issues = state_issues(
        config_path=config_path,
        installed_doctor=installed_doctor,
        source_doctor=source_doctor,
        installed_highfd=installed_highfd,
        source_highfd=source_highfd,
        installed_process_inventory=installed_process_inventory,
        source_process_inventory=source_process_inventory,
        installed_manifest_validator=installed_manifest_validator,
        source_manifest_validator=source_manifest_validator,
        installed_trusted_registry=installed_trusted_registry,
        source_trusted_registry=source_trusted_registry,
        installed_capacity=installed_capacity,
        source_capacity=source_capacity,
        installed_capacity_observer=installed_capacity_observer,
        source_capacity_observer=source_capacity_observer,
    )
    issues.extend(source_issues)
    issues.extend(
        installation_receipt_issues(
            codex_home=codex_home,
            target_paths=target_paths,
            source_commit=source_commit,
        )
    )
    if not issues:
        print("status=APPLIED" if migrated_backup is not None else "status=OK")
        print("issues=none")
        if migrated_backup is not None:
            print(f"migrated_backup={migrated_backup}")
        return 0
    if not args.apply:
        print("status=BLOCK")
        print(f"issues={','.join(issues)}")
        return 2
    config_bytes = desired_config(config_path.read_text(encoding="utf-8")).encode()
    doctor_bytes = source_bytes["codex_fd_doctor.sh"]
    highfd_bytes = source_bytes["codex-highfd"]
    process_inventory_bytes = source_bytes["codex_process_inventory.py"]
    capacity_bytes = source_bytes["codex_capacity.py"]
    capacity_observer_bytes = source_bytes["codex_capacity_observer.py"]
    manifest_validator_bytes = source_bytes["validate_wide_wave_manifest.py"]
    trusted_registry_bytes = source_bytes["trusted-wide-wave-skills.json"]
    timestamp = args.timestamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = codex_home / "backups" / f"fd-guardrails-{timestamp}"
    writes = [
        ("config.toml", config_path, config_bytes, file_mode(config_path, 0o600)),
        ("codex_fd_doctor.sh", installed_doctor, doctor_bytes, 0o755),
        ("codex-highfd", installed_highfd, highfd_bytes, 0o755),
        ("codex_process_inventory.py", installed_process_inventory, process_inventory_bytes, 0o755),
        ("validate_wide_wave_manifest.py", installed_manifest_validator, manifest_validator_bytes, 0o755),
        ("trusted-wide-wave-skills.json", installed_trusted_registry, trusted_registry_bytes, 0o600),
        ("codex_capacity.py", installed_capacity, capacity_bytes, 0o755),
        ("codex_capacity_observer.py", installed_capacity_observer, capacity_observer_bytes, 0o755),
    ]
    desired_artifacts = {
        target_id: (data, mode)
        for target_id, _path, data, mode in writes
    }
    create_fd_guardrails_backup(
        backup,
        target_paths=target_paths,
        desired_artifacts=desired_artifacts,
        source_commit=source_commit,
        created_at=datetime.now(timezone.utc).isoformat(),
    )
    try:
        for index, (_target_id, path, data, mode) in enumerate(writes, start=1):
            checked_existing_file(path)
            atomic_write(path, data, mode)
            if args.fail_after_atomic_write == index:
                raise RuntimeError(f"injected failure after atomic write {index}")

        remaining = state_issues(
            config_path=config_path,
            installed_doctor=installed_doctor,
            source_doctor=source_doctor,
            installed_highfd=installed_highfd,
            source_highfd=source_highfd,
            installed_process_inventory=installed_process_inventory,
            source_process_inventory=source_process_inventory,
            installed_manifest_validator=installed_manifest_validator,
            source_manifest_validator=source_manifest_validator,
            installed_trusted_registry=installed_trusted_registry,
            source_trusted_registry=source_trusted_registry,
            installed_capacity=installed_capacity,
            source_capacity=source_capacity,
            installed_capacity_observer=installed_capacity_observer,
            source_capacity_observer=source_capacity_observer,
        )
        if remaining:
            raise RuntimeError(f"post-apply verification failed: {','.join(remaining)}")
        receipt_remaining = installation_receipt_issues(
            codex_home=codex_home,
            target_paths=target_paths,
            source_commit=source_commit,
        )
        if receipt_remaining:
            raise RuntimeError(
                f"post-apply receipt verification failed: {','.join(receipt_remaining)}"
            )
    except BaseException as exc:
        rollback_after_failed_apply(backup=backup, target_paths=target_paths, cause=exc)
    print("status=APPLIED")
    print("issues=none")
    print(f"backup_dir={backup}")
    if migrated_backup is not None:
        print(f"migrated_backup={migrated_backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
