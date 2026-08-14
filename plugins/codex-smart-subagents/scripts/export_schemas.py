#!/usr/bin/env python3
"""Export the public MCP tool schemas from their Python source of truth."""

from __future__ import annotations

import sys
from pathlib import Path


sys.dont_write_bytecode = True

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.contracts import export_tool_schemas  # noqa: E402


if __name__ == "__main__":
    export_tool_schemas(PLUGIN_ROOT / "schemas")
