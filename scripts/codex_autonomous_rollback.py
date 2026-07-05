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
    parser.add_argument("--backup", type=Path, help="Config backup to restore. Defaults to latest ~/.codex/backups/config.toml.*.bak.")
    parser.add_argument("--apply", action="store_true", help="Apply rollback. Without this flag, only print planned actions.")
    args = parser.parse_args()

    backup = args.backup or latest_backup()
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

    if not args.apply:
        print("\n".join(actions))
        return 0

    if not backup.exists():
        raise SystemExit(f"backup does not exist: {backup}")
    shutil.copy2(backup, config)
    if alias_file.exists():
        alias_file.rename(disabled_alias_file)
    print("\n".join(actions))
    return 0


def latest_backup() -> Path:
    backups = sorted((CODEX_HOME / "backups").glob("config.toml.*.bak"))
    if not backups:
        raise SystemExit("no config backups found under ~/.codex/backups")
    return backups[-1]


def timestamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


if __name__ == "__main__":
    raise SystemExit(main())
