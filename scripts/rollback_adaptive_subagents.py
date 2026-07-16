#!/usr/bin/env python3
"""Тонкая оболочка доказанного отката adaptive subagents v2."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence


REPO = Path(__file__).resolve().parents[1]
PLUGIN_SRC = (
    REPO
    / "plugins"
    / "codex-smart-subagents"
    / "src"
)
if str(PLUGIN_SRC) not in sys.path:
    sys.path.insert(0, str(PLUGIN_SRC))

from codex_smart_subagents.installation_rollback import (  # noqa: E402
    RollbackContext,
    RollbackError,
    RollbackPreflight,
    apply_rollback,
    plan_rollback,
    probe_rollback_preflight,
)


def rollback(
    layout: Any,
    *,
    apply: bool,
    extra_environment: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    environment = dict(extra_environment or {})
    state_home = Path(
        environment.get(
            "XDG_STATE_HOME",
            str(Path.home() / ".local" / "state"),
        )
    ).expanduser().resolve()
    context = RollbackContext.from_installation(
        codex_home=Path(layout.codex_home).resolve(),
        codex_binary=Path(layout.codex_binary).resolve(),
        state_home=state_home,
    )
    preflight = probe_rollback_preflight(
        context,
        environment={
            **os.environ,
            **environment,
        },
    )
    if apply:
        return apply_rollback(
            context,
            preflight=preflight,
            extra_environment=extra_environment,
        )
    return plan_rollback(
        context,
        preflight=preflight,
        extra_environment=extra_environment,
    )


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--codex-home")
    parser.add_argument("--state-home")
    parser.add_argument("--codex-binary", default="codex")
    parser.add_argument(
        "--source-root",
        help="Совместимый устаревший параметр; содержимое не используется.",
    )
    parser.add_argument(
        "--bin-dir",
        help="Совместимый устаревший параметр; пути берутся из манифеста.",
    )
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--json", action="store_true")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        codex_home = Path(
            args.codex_home
            or os.environ.get("CODEX_HOME", str(Path.home() / ".codex"))
        ).expanduser().resolve()
        state_home = Path(
            args.state_home
            or os.environ.get(
                "XDG_STATE_HOME",
                str(Path.home() / ".local" / "state"),
            )
        ).expanduser().resolve()
        binary = _resolve_binary(args.codex_binary)
        context = RollbackContext.from_installation(
            codex_home=codex_home,
            codex_binary=binary,
            state_home=state_home,
        )
        preflight = probe_rollback_preflight(context)
        if args.apply:
            result = apply_rollback(
                context,
                preflight=preflight,
            )
        else:
            result = plan_rollback(
                context,
                preflight=preflight,
            )
    except RollbackError as exc:
        result = {
            "ok": False,
            "code": exc.code,
            "message": exc.message,
        }
        _print_result(result, as_json=args.json)
        return 1
    _print_result(result, as_json=args.json)
    return 0


def _resolve_binary(raw: str) -> Path:
    value = Path(raw).expanduser()
    if value.is_absolute():
        return value.resolve()
    found = shutil.which(raw)
    if found is None:
        raise RollbackError(
            "ROLLBACK_CODEX_BINARY_MISSING",
            f"не найден исполняемый файл Codex: {raw}",
        )
    return Path(found).resolve()


def _print_result(result: Mapping[str, Any], *, as_json: bool) -> None:
    if as_json:
        print(
            json.dumps(
                result,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    elif "actions" in result:
        print("\n".join(str(action) for action in result["actions"]))
        preflight = result.get("preflight")
        if isinstance(preflight, Mapping) and not preflight.get("ready"):
            print(
                "Откат заблокирован до завершения внешнего допуска: "
                + ", ".join(str(item) for item in preflight["blockers"])
            )
    else:
        print(json.dumps(result, ensure_ascii=False, indent=2, sort_keys=True))


if __name__ == "__main__":
    raise SystemExit(main())
