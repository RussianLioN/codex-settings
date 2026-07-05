#!/usr/bin/env python3
"""Validate the Codex autonomous workflow setup described by the plan."""

from __future__ import annotations

import json
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Any


HOME = Path.home()
CODEX_HOME = Path.home() / ".codex"
REPO = Path(__file__).resolve().parents[1]
PLAN = REPO / "docs/plans/codex-autonomous-subagents-profiles-workers-plan.md"
PROFILES = {
    "small": ("gpt-5.4-mini", "medium", "workspace-write", "on-request", 2, 1, None),
    "standard": ("gpt-5.5", "high", "workspace-write", "on-request", 4, 1, None),
    "deep-review": ("gpt-5.5", "xhigh", "read-only", "on-request", 4, 1, None),
    "safe-readonly": ("gpt-5.5", "high", "read-only", "never", 2, 1, None),
    "wide-readers": ("gpt-5.4-mini", "medium", "read-only", "never", 8, 1, 1800),
    "wide-readers-16": ("gpt-5.4-mini", "medium", "read-only", "never", 16, 1, 1800),
    "batch-workers": ("gpt-5.4-mini", "medium", "workspace-write", "never", 1, 1, 1800),
    "full-access": ("gpt-5.5", "xhigh", "danger-full-access", "never", 4, 1, None),
}
AGENTS = {
    "repo-reader",
    "docs-reader",
    "reviewer",
    "risk-auditor",
    "test-runner",
    "implementation-worker",
    "batch-worker",
}
SKILLS = {
    "project-intake",
    "parallel-review-wave",
    "batch-task-authoring",
    "worktree-worker-handoff",
    "quality-gate",
    "safe-cleanup",
}
HOOK_EVENTS = {"PreToolUse", "PermissionRequest", "PostToolUse", "SubagentStart", "SubagentStop", "Stop"}
WRITER_FIELDS = {
    "mission",
    "owned write scope",
    "allowed read scope",
    "do not touch",
    "validation commands",
    "done criteria",
    "expected artifact",
    "stop condition",
}


def main() -> int:
    checks = [
        check_plan,
        check_base_config,
        check_profiles,
        check_agents,
        check_hooks,
        check_skills,
        check_aliases,
        check_repo_scripts,
    ]
    failures: list[str] = []
    for check in checks:
        try:
            check()
            print(f"ok {check.__name__}")
        except AssertionError as exc:
            failures.append(f"{check.__name__}: {exc}")
            print(f"not ok {check.__name__}: {exc}", file=sys.stderr)
    if failures:
        print("\n".join(failures), file=sys.stderr)
        return 1
    return 0


def check_plan() -> None:
    assert PLAN.exists(), f"missing plan: {PLAN}"


def check_base_config() -> None:
    config = load_toml(CODEX_HOME / "config.toml")
    agents = config.get("agents", {})
    if agents:
        assert agents.get("max_threads", 6) <= 6, "base config raises agents.max_threads above 6"
        assert agents.get("max_depth", 1) == 1, "base config agents.max_depth is not 1"
    plugin = config.get("plugins", {}).get("codex-security@openai-curated", {})
    assert plugin.get("enabled") is True, "Codex Security plugin is not enabled"


def check_profiles() -> None:
    for name, expected in PROFILES.items():
        path = CODEX_HOME / f"{name}.config.toml"
        data = load_toml(path)
        model, effort, sandbox, approval, threads, depth, runtime = expected
        assert data.get("model") == model, f"{path} model mismatch"
        assert data.get("model_reasoning_effort") == effort, f"{path} effort mismatch"
        assert data.get("sandbox_mode") == sandbox, f"{path} sandbox mismatch"
        assert data.get("approval_policy") == approval, f"{path} approval mismatch"
        agents = data.get("agents", {})
        assert agents.get("max_threads") == threads, f"{path} max_threads mismatch"
        assert agents.get("max_depth") == depth, f"{path} max_depth mismatch"
        if runtime is not None:
            assert agents.get("job_max_runtime_seconds") == runtime, f"{path} runtime mismatch"
        assert_no_unlimited(data, str(path))


def check_agents() -> None:
    for name in AGENTS:
        path = CODEX_HOME / "agents" / f"{name}.toml"
        data = load_toml(path)
        for field in ("name", "description", "developer_instructions"):
            assert data.get(field), f"{path} missing {field}"
        assert data["name"] == name, f"{path} name mismatch"
        if name in {"implementation-worker", "batch-worker"}:
            instructions = data["developer_instructions"].lower()
            missing = sorted(field for field in WRITER_FIELDS if field not in instructions)
            assert not missing, f"{path} writer prompt fields missing: {missing}"


def check_hooks() -> None:
    hooks_path = CODEX_HOME / "hooks.json"
    policy_path = CODEX_HOME / "hooks" / "autonomous_policy.py"
    hooks = json.loads(hooks_path.read_text(encoding="utf-8"))
    configured = set(hooks.get("hooks", {}))
    assert HOOK_EVENTS <= configured, f"hooks missing events: {sorted(HOOK_EVENTS - configured)}"
    assert policy_path.exists(), f"missing hook policy: {policy_path}"
    blocked = run_hook(policy_path, "PreToolUse", {"tool_name": "Bash", "tool_input": {"command": "git push origin HEAD"}})
    assert blocked.returncode != 0, "hook did not block git push"
    allowed = run_hook(policy_path, "PreToolUse", {"tool_name": "Bash", "tool_input": {"command": "git status --short"}})
    assert allowed.returncode == 0, "hook blocked safe git status"


def check_skills() -> None:
    for name in SKILLS:
        path = CODEX_HOME / "skills" / name / "SKILL.md"
        text = path.read_text(encoding="utf-8")
        assert f"name: {name}" in text, f"{path} missing name frontmatter"
        assert "description:" in text, f"{path} missing description"
        assert str(PLAN) in text, f"{path} does not point to source plan"


def check_aliases() -> None:
    aliases = (CODEX_HOME / "codex-autonomous-aliases.zsh").read_text(encoding="utf-8")
    zshrc = (HOME / ".zshrc").read_text(encoding="utf-8")
    for alias in ("codexs", "codexro", "codexwide", "codexfa"):
        assert f"alias {alias}=" in aliases, f"missing alias: {alias}"
    assert "wide-readers-16" not in aliases, "wide-readers-16 must not have a shell alias"
    assert "codex-autonomous-aliases.zsh" in zshrc, "~/.zshrc does not source alias file"


def check_repo_scripts() -> None:
    for path in (
        REPO / "scripts/codex_batch_queue.py",
        REPO / "scripts/codex_autonomous_rollback.py",
        REPO / "scripts/validate_autonomous_workflow.py",
    ):
        assert path.exists(), f"missing script: {path}"
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    schema = json.loads((REPO / "schemas/codex-batch-task.schema.json").read_text(encoding="utf-8"))
    required = set(schema.get("required", []))
    assert required >= {
        "repo",
        "base_sha",
        "goal",
        "validation_commands",
        "owned_write_scope",
        "expected_artifact",
        "stop_condition",
    }, "batch task schema missing required worker fields"


def load_toml(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def assert_no_unlimited(value: Any, where: str) -> None:
    if value in (0, -1, "unlimited"):
        raise AssertionError(f"{where} contains forbidden unlimited sentinel: {value!r}")
    if isinstance(value, dict):
        for key, child in value.items():
            assert_no_unlimited(child, f"{where}.{key}")
    if isinstance(value, list):
        for index, child in enumerate(value):
            assert_no_unlimited(child, f"{where}[{index}]")


def run_hook(policy_path: Path, event: str, payload: dict[str, Any]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(policy_path), event],
        input=json.dumps(payload),
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )


if __name__ == "__main__":
    raise SystemExit(main())
