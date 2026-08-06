#!/usr/bin/env python3
"""Проверить и применить ограничители истощения ресурсов Codex."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import tempfile
import tomllib
from datetime import datetime
from pathlib import Path


SAFE_THREAD_CAP = 20
PUBLIC_THREAD_CAP_KEY = "max_concurrent_threads_per_session"
LEGACY_AGENT_THREAD_KEY = "max_threads"
LEGACY_NATIVE_THREAD_KEY = "max_concurrent_threads_per_session"
SOURCE_ROOT = Path(__file__).resolve().parents[1]
SOURCE_MANIFEST_VALIDATOR = SOURCE_ROOT / "scripts" / "validate_wide_wave_manifest.py"
SOURCE_TRUSTED_WIDE_WAVE_REGISTRY = SOURCE_ROOT / "config" / "trusted-wide-wave-skills.json"
POLICY_START = "<!-- codex-runtime-fd-guardrails:start -->"
POLICY_END = "<!-- codex-runtime-fd-guardrails:end -->"
LEGACY_PARTIAL_REQUIRED_FILES = {
    "AGENTS.md",
    "config.toml",
}
LEGACY_PARTIAL_OPTIONAL_FILES = {"codex_fd_doctor.sh"}
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
        "--migrate-legacy-backup",
        metavar="YYYYMMDD-HHMM[SS]",
        help="rename a legacy partial runtime-fd backup outside the rollback namespace",
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
    if parsed.get("features", {}).get("multi_agent_v2", {}).get("enabled") is not True:
        raise ValueError("features.multi_agent_v2.enabled must stay true")
    return text


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


def state_issues(
    *,
    config_path: Path,
    agents_path: Path,
    installed_doctor: Path,
    source_doctor: Path,
    installed_manifest_validator: Path,
    source_manifest_validator: Path,
    installed_trusted_registry: Path,
    source_trusted_registry: Path,
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
    if (
        multi_agent_v2.get("enabled") is not True
    ):
        issues.append("multi_agent_v2_enabled_not_true")
    agents_text = agents_path.read_text(encoding="utf-8")
    if POLICY_BLOCK not in agents_text:
        issues.append("agents_resource_policy_missing_or_drifted")
    if not installed_doctor.is_file() or installed_doctor.read_bytes() != source_doctor.read_bytes():
        issues.append("installed_fd_doctor_drifted")
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
    return issues


def atomic_write(path: Path, data: bytes, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
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


def migrate_legacy_partial_backup(codex_home: Path, suffix: str) -> Path:
    if not re.fullmatch(r"[0-9]{8}-[0-9]{4}(?:[0-9]{2})?", suffix):
        raise SystemExit("invalid legacy backup suffix: expected YYYYMMDD-HHMM[SS]")
    backup_root = codex_home / "backups"
    source = backup_root / f"runtime-fd-{suffix}"
    destination = backup_root / f"fd-guardrails-{suffix}"
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


def main() -> int:
    args = parse_args()
    if args.timestamp is not None and not re.fullmatch(r"[0-9]{8}-[0-9]{6}", args.timestamp):
        raise SystemExit("invalid timestamp: expected YYYYMMDD-HHMMSS")
    config_path = args.codex_home / "config.toml"
    agents_path = args.codex_home / "AGENTS.md"
    installed_trusted_registry = (
        args.installed_trusted_registry
        if args.installed_trusted_registry is not None
        else args.codex_home / "config" / "trusted-wide-wave-skills.json"
    )
    installed_manifest_validator = (
        args.installed_manifest_validator
        if args.installed_manifest_validator is not None
        else args.installed_doctor.parent / "validate_wide_wave_manifest.py"
    )
    for path in (
        config_path,
        agents_path,
        args.source_doctor,
        args.source_manifest_validator,
        args.source_trusted_registry,
    ):
        if not path.is_file():
            raise SystemExit(f"required file is missing: {path}")

    migrated_backup: Path | None = None
    if args.migrate_legacy_backup is not None:
        if not args.apply:
            raise SystemExit("--migrate-legacy-backup requires --apply")
        migrated_backup = migrate_legacy_partial_backup(
            args.codex_home,
            args.migrate_legacy_backup,
        )

    issues = state_issues(
        config_path=config_path,
        agents_path=agents_path,
        installed_doctor=args.installed_doctor,
        source_doctor=args.source_doctor,
        installed_manifest_validator=installed_manifest_validator,
        source_manifest_validator=args.source_manifest_validator,
        installed_trusted_registry=installed_trusted_registry,
        source_trusted_registry=args.source_trusted_registry,
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

    timestamp = args.timestamp or datetime.now().strftime("%Y%m%d-%H%M%S")
    backup = args.codex_home / "backups" / f"fd-guardrails-{timestamp}"
    if backup.exists():
        raise SystemExit(f"backup already exists: {backup}")
    backup.mkdir(parents=True, mode=0o700)
    backup.chmod(0o700)
    shutil.copy2(config_path, backup / "config.toml")
    (backup / "config.toml").chmod(0o600)
    shutil.copy2(agents_path, backup / "AGENTS.md")
    if args.installed_doctor.exists():
        shutil.copy2(args.installed_doctor, backup / "codex_fd_doctor.sh")
    if installed_manifest_validator.exists():
        shutil.copy2(installed_manifest_validator, backup / "validate_wide_wave_manifest.py")
    if installed_trusted_registry.exists():
        shutil.copy2(installed_trusted_registry, backup / "trusted-wide-wave-skills.json")

    config_bytes = desired_config(config_path.read_text(encoding="utf-8")).encode()
    agents_bytes = desired_agents(agents_path.read_text(encoding="utf-8")).encode()
    doctor_bytes = args.source_doctor.read_bytes()
    manifest_validator_bytes = args.source_manifest_validator.read_bytes()
    trusted_registry_bytes = args.source_trusted_registry.read_bytes()
    atomic_write(config_path, config_bytes, file_mode(config_path, 0o600))
    atomic_write(agents_path, agents_bytes, file_mode(agents_path, 0o644))
    atomic_write(args.installed_doctor, doctor_bytes, 0o755)
    atomic_write(installed_manifest_validator, manifest_validator_bytes, 0o755)
    atomic_write(installed_trusted_registry, trusted_registry_bytes, 0o600)

    remaining = state_issues(
        config_path=config_path,
        agents_path=agents_path,
        installed_doctor=args.installed_doctor,
        source_doctor=args.source_doctor,
        installed_manifest_validator=installed_manifest_validator,
        source_manifest_validator=args.source_manifest_validator,
        installed_trusted_registry=installed_trusted_registry,
        source_trusted_registry=args.source_trusted_registry,
    )
    if remaining:
        raise SystemExit(f"post-apply verification failed: {','.join(remaining)}")
    print("status=APPLIED")
    print("issues=none")
    print(f"backup_dir={backup}")
    if migrated_backup is not None:
        print(f"migrated_backup={migrated_backup}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
