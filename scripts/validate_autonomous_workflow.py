#!/usr/bin/env python3
"""Validate the Codex autonomous workflow setup described by the plan."""

from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import subprocess
import sys
import tempfile
import tomllib
from contextlib import redirect_stdout
from pathlib import Path
from typing import Any


HOME = Path.home()
CODEX_HOME = Path.home() / ".codex"
REPO = Path(__file__).resolve().parents[1]
PLAN = REPO / "docs/plans/codex-autonomous-subagents-profiles-workers-plan.md"
RUNTIME_PLAN = HOME / "coding/projects/codex-settings/docs/plans/codex-autonomous-subagents-profiles-workers-plan.md"
FD_DOCTOR = REPO / "scripts/codex_fd_doctor.sh"
HIGHFD_TEMPLATE = REPO / "scripts/codex-highfd"
HOOK_POLICY = REPO / "scripts/autonomous_policy.py"
HIGHFD_WRAPPER = HOME / ".local/bin/codex-highfd"
INSTALLED_FD_DOCTOR = HOME / ".local/libexec/codex_fd_doctor.sh"
CHATGPT_RESOURCES = Path("/Applications/ChatGPT.app/Contents/Resources")
DEFAULT_WAVE_SIZE = 6
MAX_BASE_THREADS = 20
HIGH_FD_LIMIT = 4096
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
        check_mcp_runtime,
        check_profiles,
        check_agents,
        check_fd_guardrails,
        check_hooks,
        check_skills,
        check_consilium_runtime,
        check_aliases,
        check_rollback,
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
        threads = agents.get("max_threads", DEFAULT_WAVE_SIZE)
        assert 1 <= threads <= MAX_BASE_THREADS, f"base config agents.max_threads must be in 1..{MAX_BASE_THREADS}"
        assert agents.get("max_depth", 1) == 1, "base config agents.max_depth is not 1"
    plugin = config.get("plugins", {}).get("codex-security@openai-curated", {})
    assert plugin.get("enabled") is True, "Codex Security plugin is not enabled"


def check_mcp_runtime() -> None:
    config = load_toml(CODEX_HOME / "config.toml")
    marketplace = config.get("marketplaces", {}).get("openai-bundled", {})
    expected_marketplace = CHATGPT_RESOURCES / "plugins/openai-bundled"
    assert Path(marketplace.get("source", "")) == expected_marketplace, "openai-bundled marketplace is not bound to ChatGPT.app"

    server = config.get("mcp_servers", {}).get("node_repl", {})
    command = Path(server.get("command", ""))
    env = server.get("env", {})
    expected_paths = {
        "command": CHATGPT_RESOURCES / "cua_node/bin/node_repl",
        "NODE_REPL_NODE_MODULE_DIRS": CHATGPT_RESOURCES / "cua_node/lib/node_modules",
        "NODE_REPL_NODE_PATH": CHATGPT_RESOURCES / "cua_node/bin/node",
        "CODEX_CLI_PATH": CHATGPT_RESOURCES / "codex",
    }
    assert command == expected_paths["command"], "node_repl command does not use ChatGPT.app"
    for name, expected in expected_paths.items():
        actual = command if name == "command" else Path(env.get(name, ""))
        assert actual == expected, f"{name} does not use ChatGPT.app"
        assert actual.exists(), f"{name} path does not exist: {actual}"

    manifest = json.loads((expected_marketplace / "plugins/browser/.codex-plugin/plugin.json").read_text(encoding="utf-8"))
    browser_version = manifest["version"]
    browser_client = expected_marketplace / "plugins/browser/scripts/browser-client.mjs"
    browser_hash = hashlib.sha256(browser_client.read_bytes()).hexdigest()
    assert env.get("BROWSER_USE_CODEX_APP_VERSION") == browser_version, "browser runtime version is stale"
    trusted_hashes = {
        value.strip()
        for value in str(env.get("NODE_REPL_TRUSTED_BROWSER_CLIENT_SHA256S", "")).split(",")
        if value.strip()
    }
    assert browser_hash in trusted_hashes, "browser client trust hash is stale"

    responses = run_mcp_smoke(command, env)
    initialize = responses.get(1, {})
    tool_call = responses.get(2, {})
    assert "error" not in initialize and initialize.get("result"), "node_repl MCP initialize failed"
    assert initialize["result"].get("serverInfo", {}).get("name") == "rmcp", "node_repl returned an unexpected server"
    assert "error" not in tool_call and tool_call.get("result"), "node_repl js tool call failed"
    assert tool_call["result"].get("isError") is False, "node_repl js tool reported an error"
    content = tool_call["result"].get("content", [])
    assert any("chromium: true" in item.get("text", "") for item in content), "playwright import smoke did not expose Chromium"


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
    assert HOOK_POLICY.read_bytes() == policy_path.read_bytes(), "installed hook policy differs from tracked source"
    allowed_main_push = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": "git push origin HEAD"}},
    )
    assert allowed_main_push.returncode == 0, "hook blocked an interactive main-session git push"
    blocked = run_hook(
        policy_path,
        "PreToolUse",
        {
            "agent_type": "implementation-worker",
            "tool_name": "Bash",
            "tool_input": {"command": "git push origin HEAD"},
        },
    )
    assert blocked.returncode != 0, "hook did not block an autonomous worker git push"
    blocked_push_with_option = run_hook(
        policy_path,
        "PreToolUse",
        {
            "agent_type": "implementation-worker",
            "tool_name": "Bash",
            "tool_input": {"command": " ".join(("/usr/bin/git", "-C", ".", "push", "origin", "HEAD"))},
        },
    )
    assert blocked_push_with_option.returncode != 0, "hook did not block a global-option VCS push"
    blocked_merge = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": "gh pr merge 42 --squash"}},
    )
    assert blocked_merge.returncode != 0, "hook did not block gh pr merge"
    blocked_merge_with_option = run_hook(
        policy_path,
        "PreToolUse",
        {
            "tool_name": "Bash",
            "tool_input": {"command": " ".join(("gh", "--repo", "example/project", "pr", "merge", "42", "--squash"))},
        },
    )
    assert blocked_merge_with_option.returncode != 0, "hook did not block a global-option PR merge"
    blocked_reset = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": "/usr/bin/git reset --hard HEAD"}},
    )
    assert blocked_reset.returncode != 0, "hook did not block an absolute-path git reset --hard"
    blocked_copy = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": "cp README.md /tmp/codex-hook-outside"}},
    )
    assert blocked_copy.returncode != 0, "hook did not block a copy outside the worktree"
    blocked_chmod = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": "chmod 600 /tmp/codex-hook-outside"}},
    )
    assert blocked_chmod.returncode != 0, "hook did not block chmod outside the worktree"
    blocked_git_metadata = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": " ".join(("touch", ".git"))}},
    )
    assert blocked_git_metadata.returncode != 0, "hook did not block a write to Git metadata"
    blocked_relative_copy = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": " ".join(("cp", "README.md", "../codex-hook-outside"))}},
    )
    assert blocked_relative_copy.returncode != 0, "hook did not resolve a relative write outside the worktree"
    blocked_redirect = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": "".join(("printf ok ", ">", "/tmp/codex-hook-outside"))}},
    )
    assert blocked_redirect.returncode != 0, "hook did not block an outside shell redirection"
    allowed = run_hook(policy_path, "PreToolUse", {"tool_name": "Bash", "tool_input": {"command": "git status --short"}})
    assert allowed.returncode == 0, "hook blocked safe git status"
    allowed_dev_null = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": "".join(("git status ", "2>", "/dev/null"))}},
    )
    assert allowed_dev_null.returncode == 0, "hook blocked safe stderr redirection to the null device"
    allowed_patch = "\n".join(
        (
            "*** Begin Patch",
            "*** Update File: scripts/autonomous_policy.py",
            "@@",
            "-git status --short",
            "+git push origin HEAD",
            "*** End Patch",
        )
    )
    allowed_patch_result = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "apply_patch", "tool_input": {"command": allowed_patch}},
    )
    assert allowed_patch_result.returncode == 0, "hook treated in-worktree patch content as a shell command"
    outside_patch = "\n".join(("*** Begin Patch", "*** Add File: /tmp/codex-outside", "+blocked", "*** End Patch"))
    outside_patch_result = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "apply_patch", "tool_input": {"command": outside_patch}},
    )
    assert outside_patch_result.returncode != 0, "hook allowed apply_patch outside the worktree"
    git_metadata_patch = "\n".join(("*** Begin Patch", "*** Add File: .git/codex-test", "+blocked", "*** End Patch"))
    git_metadata_result = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "apply_patch", "tool_input": {"command": git_metadata_patch}},
    )
    assert git_metadata_result.returncode != 0, "hook allowed apply_patch inside Git metadata"
    move_patch = "\n".join(
        (
            "*** Begin Patch",
            "*** Update File: scripts/autonomous_policy.py",
            "*** Move to: /tmp/codex-moved-policy.py",
            "@@",
            "-old",
            "+new",
            "*** End Patch",
        )
    )
    move_patch_result = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "apply_patch", "tool_input": {"command": move_patch}},
    )
    assert move_patch_result.returncode != 0, "hook allowed apply_patch move outside the worktree"
    allowed_copy = run_hook(
        policy_path,
        "PreToolUse",
        {"tool_name": "Bash", "tool_input": {"command": f"cp /tmp/codex-hook-input {REPO / 'codex-hook-output'}"}},
    )
    assert allowed_copy.returncode == 0, "hook blocked an outside read copied into the worktree"


def check_skills() -> None:
    for name in SKILLS:
        path = CODEX_HOME / "skills" / name / "SKILL.md"
        text = path.read_text(encoding="utf-8")
        assert f"name: {name}" in text, f"{path} missing name frontmatter"
        assert "description:" in text, f"{path} missing description"
        assert str(RUNTIME_PLAN) in text, f"{path} does not point to source plan"
    parallel = (CODEX_HOME / "skills/parallel-review-wave/SKILL.md").read_text(encoding="utf-8")
    for required in (
        "default wave size: 6",
        "$HOME/.local/bin/codex-highfd --fd-doctor",
        "FD preflight",
        "close_agent",
        "agent thread limit reached",
        "session-exit cleanup",
        "environment limitation",
    ):
        assert required in parallel, f"parallel-review-wave missing policy marker: {required}"


def check_fd_guardrails() -> None:
    for path in (FD_DOCTOR, HIGHFD_TEMPLATE, HIGHFD_WRAPPER, INSTALLED_FD_DOCTOR):
        assert path.exists(), f"missing FD guardrail: {path}"
        assert os.access(path, os.X_OK), f"FD guardrail is not executable: {path}"
    assert HIGHFD_TEMPLATE.read_bytes() == HIGHFD_WRAPPER.read_bytes(), "installed codex-highfd differs from tracked template"
    assert FD_DOCTOR.read_bytes() == INSTALLED_FD_DOCTOR.read_bytes(), "installed FD doctor differs from tracked source"

    ok = run_fd_doctor(DEFAULT_WAVE_SIZE, soft_limit=HIGH_FD_LIMIT, fd_count=32)
    assert ok.returncode == 0, f"FD doctor rejected safe default wave: {ok.stdout}{ok.stderr}"
    assert "status=OK" in ok.stdout, "FD doctor did not report status=OK"
    blocked = run_fd_doctor(DEFAULT_WAVE_SIZE + 2, soft_limit=256, fd_count=32)
    assert blocked.returncode == 2, "FD doctor did not block a wide wave under soft limit 256"
    stale_runtime = run_fd_doctor(DEFAULT_WAVE_SIZE, soft_limit=HIGH_FD_LIMIT, fd_count=32, stale_count=1)
    assert stale_runtime.returncode == 1, "FD doctor did not warn about a stale node_repl executable"
    assert "stale_node_repl_executable_paths" in stale_runtime.stdout, "FD doctor omitted the stale runtime reason"

    preserved = subprocess.run(
        [
            "/bin/zsh",
            "-c",
            'ulimit -n 1024 || exit 2; CODEX_NOFILE_LIMIT=256 "$1" --self-test',
            "codex-highfd-preserve-test",
            str(HIGHFD_TEMPLATE),
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert preserved.returncode == 0, f"codex-highfd preserve test failed: {preserved.stderr}"
    assert "soft_limit=1024" in preserved.stdout, "codex-highfd lowered an existing higher soft limit"


def check_consilium_runtime() -> None:
    root = CODEX_HOME / "plugins/cache/agents-skills/consilium"
    versions = sorted(root.glob("*/skills"))
    assert versions, "installed Consilium runtime is missing"
    skills_root = versions[-1]
    for name in ("consilium", "expert-consilium", "consilium-lean"):
        path = skills_root / name / "SKILL.md"
        text = path.read_text(encoding="utf-8")
        for required in (
            "maximum live wave: 6",
            "$HOME/.local/bin/codex-highfd --fd-doctor",
            "close_agent",
            "agent thread limit reached",
            "session-exit cleanup",
            "environment limitation",
        ):
            assert required in text, f"{path} missing bounded-wave marker: {required}"


def check_aliases() -> None:
    aliases = (CODEX_HOME / "codex-autonomous-aliases.zsh").read_text(encoding="utf-8")
    zshrc = (HOME / ".zshrc").read_text(encoding="utf-8")
    for alias in ("codex", "codexs", "codexro", "codexwide", "codexfa", "codexfd"):
        assert f"alias {alias}=" in aliases, f"missing alias: {alias}"
    assert "wide-readers-16" not in aliases, "wide-readers-16 must not have a shell alias"
    assert "codex-autonomous-aliases.zsh" in zshrc, "~/.zshrc does not source alias file"


def check_rollback() -> None:
    backups = sorted((CODEX_HOME / "backups").glob("runtime-fd-*"))
    assert backups, "runtime FD backup set is missing"
    result = subprocess.run(
        [sys.executable, str(REPO / "scripts/codex_autonomous_rollback.py"), "--backup", str(backups[-1])],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    assert result.returncode == 0, f"rollback dry-run failed: {result.stderr}"
    for marker in ("config.toml", "codex-autonomous-aliases.zsh", "autonomous_policy.py", "home-skills", "consilium-skills", "browser-cache"):
        assert marker in result.stdout, f"rollback dry-run missing restore marker: {marker}"
    check_runtime_rollback_apply(REPO / "scripts/codex_autonomous_rollback.py")


def check_runtime_rollback_apply(script: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="codex-rollback-test-") as temp_dir:
        root = Path(temp_dir)
        codex_home = root / ".codex"
        backup = root / "runtime-fd-test"

        fixtures = {
            backup / "config.toml": "backup config\n",
            backup / "codex-autonomous-aliases.zsh": "backup aliases\n",
            backup / "autonomous_policy.py": "backup policy\n",
            backup / "home-skills/project-intake.SKILL.md": "backup home skill\n",
            backup / "consilium-skills/consilium.SKILL.md": "backup consilium skill\n",
            backup / "browser-cache/old-version/marker.txt": "backup browser\n",
            backup / "openai-bundled-marketplace/plugins/old/marker.txt": "backup marketplace\n",
            codex_home / "config.toml": "current config\n",
            codex_home / "codex-autonomous-aliases.zsh": "current aliases\n",
            codex_home / "hooks/autonomous_policy.py": "current policy\n",
            codex_home / "skills/project-intake/SKILL.md": "current home skill\n",
            codex_home / "plugins/cache/agents-skills/consilium/0.1.0/skills/consilium/SKILL.md": "current consilium skill\n",
            codex_home / "plugins/cache/openai-bundled/browser/new-version/stale.txt": "stale browser\n",
            codex_home / ".tmp/bundled-marketplaces/openai-bundled/plugins/new/stale.txt": "stale marketplace\n",
        }
        for path, content in fixtures.items():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding="utf-8")

        spec = importlib.util.spec_from_file_location("codex_rollback_apply_test", script)
        assert spec and spec.loader, "could not load rollback module"
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        module.CODEX_HOME = codex_home
        with redirect_stdout(io.StringIO()):
            assert module.handle_runtime_backup(backup, True) == 0

        browser_target = codex_home / "plugins/cache/openai-bundled/browser"
        marketplace_target = codex_home / ".tmp/bundled-marketplaces/openai-bundled"
        assert (browser_target / "old-version/marker.txt").read_text(encoding="utf-8") == "backup browser\n"
        assert not (browser_target / "new-version/stale.txt").exists(), "rollback retained stale browser cache files"
        assert (marketplace_target / "plugins/old/marker.txt").read_text(encoding="utf-8") == "backup marketplace\n"
        assert not (marketplace_target / "plugins/new/stale.txt").exists(), "rollback retained stale marketplace files"
        assert (codex_home / "skills/project-intake/SKILL.md").read_text(encoding="utf-8") == "backup home skill\n"
        consilium = codex_home / "plugins/cache/agents-skills/consilium/0.1.0/skills/consilium/SKILL.md"
        assert consilium.read_text(encoding="utf-8") == "backup consilium skill\n"


def check_repo_scripts() -> None:
    for path in (
        REPO / "scripts/codex_batch_queue.py",
        REPO / "scripts/codex_autonomous_rollback.py",
        HOOK_POLICY,
        REPO / "scripts/validate_autonomous_workflow.py",
    ):
        assert path.exists(), f"missing script: {path}"
        compile(path.read_text(encoding="utf-8"), str(path), "exec")
    for path in (FD_DOCTOR, HIGHFD_TEMPLATE):
        assert path.exists(), f"missing script: {path}"
        result = subprocess.run(["/bin/zsh", "-n", str(path)], text=True, capture_output=True)
        assert result.returncode == 0, f"shell syntax failed for {path}: {result.stderr}"
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


def run_fd_doctor(
    wave_size: int,
    *,
    soft_limit: int,
    fd_count: int,
    orphan_count: int = 0,
    stale_count: int = 0,
) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    env.update(
        {
            "CODEX_FD_DOCTOR_SOFT_LIMIT": str(soft_limit),
            "CODEX_FD_DOCTOR_HARD_LIMIT": "unlimited",
            "CODEX_FD_DOCTOR_LAUNCHD_SOFT_LIMIT": "256",
            "CODEX_FD_DOCTOR_CODEX_FD_COUNT": str(fd_count),
            "CODEX_FD_DOCTOR_CODEX_PROCESS_COUNT": "2",
            "CODEX_FD_DOCTOR_NODE_REPL_PROCESS_COUNT": "2",
            "CODEX_FD_DOCTOR_ORPHAN_NODE_REPL_COUNT": str(orphan_count),
            "CODEX_FD_DOCTOR_STALE_NODE_REPL_COUNT": str(stale_count),
            "CODEX_FD_DOCTOR_MCP_COMMAND": str(CHATGPT_RESOURCES / "cua_node/bin/node_repl"),
        }
    )
    return subprocess.run(
        [str(FD_DOCTOR), "--wave-size", str(wave_size)],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=env,
    )


def run_mcp_smoke(command: Path, server_env: dict[str, Any]) -> dict[int, dict[str, Any]]:
    messages = [
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "codex-settings-validator", "version": "1.0.0"},
            },
        },
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "js",
                "arguments": {
                    "code": 'var runtimeSmoke = await import("playwright"); nodeRepl.write({chromium: typeof runtimeSmoke.chromium.launch === "function"});',
                    "title": "Validate Playwright runtime",
                    "timeout_ms": 10000,
                },
            },
        },
    ]
    env = os.environ.copy()
    env.update({str(key): str(value) for key, value in server_env.items()})
    try:
        result = subprocess.run(
            [str(command)],
            input="\n".join(json.dumps(message) for message in messages) + "\n",
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=20,
        )
    except subprocess.TimeoutExpired as exc:
        raise AssertionError("node_repl MCP smoke timed out") from exc
    assert result.returncode == 0, f"node_repl MCP smoke failed: {result.stderr}"

    responses: dict[int, dict[str, Any]] = {}
    for line in result.stdout.splitlines():
        try:
            payload = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(payload.get("id"), int):
            responses[payload["id"]] = payload
    return responses


if __name__ == "__main__":
    raise SystemExit(main())
