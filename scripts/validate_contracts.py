#!/usr/bin/env python3
"""Единая точка запуска проверок договоров."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def run_validator(relative_path: str, *arguments: str) -> int:
    result = subprocess.run(
        [sys.executable, str(ROOT / relative_path), *arguments],
        cwd=ROOT,
        check=False,
    )
    return result.returncode


def main() -> int:
    if result := run_validator("scripts/validate_task1_contract_vectors.py", "--all"):
        return result
    print("TASK1_CONTRACTS_OK", flush=True)
    if result := run_validator("scripts/validate_semantic_routing_vectors.py"):
        return result
    print("SEMANTIC_ROUTING_CONTRACTS_OK", flush=True)
    if result := run_validator(
        "scripts/validate_protocol_v2_contract_vectors.py",
        "--all",
    ):
        return result
    print("PROTOCOL_V2_CONTRACTS_OK", flush=True)
    if result := run_validator("scripts/validate_state_schema_artifacts.py"):
        return result
    print("STATE_SCHEMA_ARTIFACTS_OK", flush=True)
    if result := run_validator("scripts/validate_lifecycle_contract_vectors.py"):
        return result
    print("LIFECYCLE_CONTRACTS_OK", flush=True)
    if result := run_validator(
        "scripts/validate_lifecycle_command_result_vectors.py"
    ):
        return result
    print("LIFECYCLE_COMMAND_RESULT_CONTRACTS_OK", flush=True)
    if result := run_validator(
        "scripts/validate_activation_preparation_vectors.py"
    ):
        return result
    print("ACTIVATION_PREPARATION_CONTRACTS_OK", flush=True)
    if result := run_validator(
        "scripts/validate_transient_process_ownership_vectors.py"
    ):
        return result
    print("TRANSIENT_PROCESS_OWNERSHIP_CONTRACTS_OK", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
