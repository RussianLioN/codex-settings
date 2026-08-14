#!/usr/bin/env python3
"""Собирает готовый planInput из короткого смыслового описания."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path


sys.dont_write_bytecode = True

PLUGIN_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PLUGIN_ROOT / "src"))

from codex_smart_subagents.plan_input_builder_v2 import (  # noqa: E402
    PlanInputBuilderV2Error,
    build_plan_input_v2,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--spec-json", required=True)
    arguments = parser.parse_args()
    try:
        specification = json.loads(arguments.spec_json)
        plan_input = build_plan_input_v2(specification)
    except (json.JSONDecodeError, PlanInputBuilderV2Error) as exc:
        print(f"PLAN_INPUT_INVALID: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            plan_input,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
