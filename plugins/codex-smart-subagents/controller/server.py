"""Bundled controller service entrypoint."""

from __future__ import annotations

import os
import sys
from pathlib import Path


PLUGIN_ROOT = Path(__file__).resolve().parents[1]
SOURCE = PLUGIN_ROOT / "src"
if str(SOURCE) not in sys.path:
    sys.path.insert(0, str(SOURCE))

from codex_smart_subagents.daemon import ControllerProcessConfig  # noqa: E402
from codex_smart_subagents.production import (  # noqa: E402
    build_production_runtime,
    install_signal_handlers,
)


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments != ["--serve"]:
        sys.stderr.write(
            "codex-smart-subagents-controller: поддерживается только --serve\n"
        )
        return 2
    try:
        config = ControllerProcessConfig.from_environ(
            os.environ,
            plugin_root=PLUGIN_ROOT,
        )
        runtime = build_production_runtime(config)
        install_signal_handlers(runtime)
        runtime.serve_forever()
    except Exception as exc:
        sys.stderr.write(
            "codex-smart-subagents-controller: "
            f"{getattr(exc, 'code', 'START_FAILED')}: "
            f"{getattr(exc, 'message', str(exc))}\n"
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
