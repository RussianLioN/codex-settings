#!/usr/bin/env python3
"""Rollback helper for the Codex autonomous workflow setup."""

from __future__ import annotations

import argparse
import shutil
from datetime import datetime, timezone
from pathlib import Path


HOME = Path.home()
CODEX_HOME = HOME / ".codex"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backup",
        type=Path,
        help="Runtime backup directory or legacy config backup. Defaults to the latest available backup.",
    )
    parser.add_argument("--apply", action="store_true", help="Apply rollback. Without this flag, only print planned actions.")
    args = parser.parse_args()

    backup = args.backup or latest_backup()
    if backup.is_dir():
        return handle_runtime_backup(backup, args.apply)

    return handle_legacy_backup(backup, args.apply)


def handle_runtime_backup(backup: Path, apply: bool) -> int:
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
        f"restore {required['config.toml']} -> {CODEX_HOME / 'config.toml'}",
        f"restore {required['codex-autonomous-aliases.zsh']} -> {CODEX_HOME / 'codex-autonomous-aliases.zsh'}",
        f"restore {required['autonomous_policy.py']} -> {CODEX_HOME / 'hooks/autonomous_policy.py'}",
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

    shutil.copy2(required["config.toml"], CODEX_HOME / "config.toml")
    shutil.copy2(required["codex-autonomous-aliases.zsh"], CODEX_HOME / "codex-autonomous-aliases.zsh")
    shutil.copy2(required["autonomous_policy.py"], CODEX_HOME / "hooks/autonomous_policy.py")
    restore_skills(required["home-skills"], CODEX_HOME / "skills")
    restore_skills(required["consilium-skills"], consilium_skills_root())
    replace_tree(required["browser-cache"], CODEX_HOME / "plugins/cache/openai-bundled/browser")
    replace_tree(
        required["openai-bundled-marketplace"],
        CODEX_HOME / ".tmp/bundled-marketplaces/openai-bundled",
    )
    print("\n".join(actions))
    return 0


def handle_legacy_backup(backup: Path, apply: bool) -> int:
    alias_file = CODEX_HOME / "codex-autonomous-aliases.zsh"
    disabled_alias_file = CODEX_HOME / f"codex-autonomous-aliases.zsh.disabled.{timestamp()}"
    config = CODEX_HOME / "config.toml"

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


def consilium_skills_root() -> Path:
    roots = sorted((CODEX_HOME / "plugins/cache/agents-skills/consilium").glob("*/skills"))
    if not roots:
        raise SystemExit("installed Consilium runtime is missing")
    return roots[-1]


def latest_backup() -> Path:
    runtime_backups = sorted((CODEX_HOME / "backups").glob("runtime-fd-*"))
    if runtime_backups:
        return runtime_backups[-1]
    backups = sorted((CODEX_HOME / "backups").glob("config.toml.*.bak"))
    if not backups:
        raise SystemExit("no config backups found under ~/.codex/backups")
    return backups[-1]


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


if __name__ == "__main__":
    raise SystemExit(main())
