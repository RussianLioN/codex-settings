"""Точка входа свежего сторожа, запущенного через ``posix_spawn``."""

from __future__ import annotations

import sys
from pathlib import Path


if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from codex_smart_subagents.child_guard_v2 import (  # noqa: E402
    _child_guard_process_entrypoint_v2,
)


if __name__ == "__main__":
    raise SystemExit(_child_guard_process_entrypoint_v2())
