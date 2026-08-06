#!/usr/bin/env python3
"""Fail-closed Codex hook policy for autonomous workflow profiles."""

from __future__ import annotations

import hashlib
import inspect
import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import codex_capacity as capacity_core
import codex_capacity_observer as capacity_observer
from codex_capacity import DEFAULT_CAPACITY, MAX_CAPACITY, CapacityStore, request_hash
from codex_capacity_observer import observe as observe_capacity


HOME = Path.home().resolve()
CODEX_HOME = Path(os.environ.get("CODEX_HOME", HOME / ".codex")).expanduser().resolve()
AUDIT_LOG = CODEX_HOME / "audit" / "hooks.jsonl"
FAIL_CLOSED_EVENTS = {"PreToolUse", "PermissionRequest"}
KNOWN_EVENTS = {
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "SubagentStart",
    "SubagentStop",
    "Stop",
    "SessionEnd",
}
CAPACITY_ENFORCEMENT_ENV = "CODEX_CAPACITY_ENFORCEMENT"
CAPACITY_OBSERVER_SNAPSHOT_ENV = "CODEX_CAPACITY_OBSERVER_SNAPSHOT"
CAPACITY_OBSERVER_TEST_MODE_ENV = "CODEX_CAPACITY_OBSERVER_TEST_MODE"
CAPACITY_HOOK_DEADLINE_MS_ENV = "CODEX_CAPACITY_HOOK_DEADLINE_MS"
CAPACITY_QUEUED = "CAPACITY_QUEUED"
CAPACITY_DEADLINE_EXHAUSTED = "CAPACITY_DEADLINE_EXHAUSTED"
CAPACITY_HOOK_DEADLINE_SECONDS = 0.95
CAPACITY_MIN_STAGE_SECONDS = 0.005
CAPACITY_AFTER_SNAPSHOT_RESERVE_SECONDS = 0.58
CAPACITY_AFTER_OBSERVER_RESERVE_SECONDS = 0.08
CAPACITY_AFTER_ACQUIRE_RESERVE_SECONDS = 0.02
SENSITIVE_PAYLOAD_KEYS = {"message", "messages", "task", "task_name", "taskName", "tool_input", "toolInput"}
KNOWN_AGENTS = {
    "default",
    "worker",
    "explorer",
    "repo-reader",
    "docs-reader",
    "reviewer",
    "risk-auditor",
    "test-runner",
    "implementation-worker",
    "batch-worker",
}
READ_LIKE_TOOL = re.compile(r"(read|get|list|search|find|fetch|view|open|inspect|query|status|show)", re.I)
SIDE_EFFECT_TOOL = re.compile(
    r"(create|update|delete|remove|trash|archive|label|send|draft|reply|forward|merge|push|"
    r"write|edit|apply|run|exec|execute|mutate|upload|download|move|copy|share|permission)",
    re.I,
)
SECRET_ASSIGNMENT = re.compile(r"(?i)(api[_-]?key|secret|token|password|credential)\s*=\s*['\"]?[^'\"\s]+")
SECRET_REFERENCE = re.compile(r"(?i)(cat|sed|awk|rg|grep|less|more)\s+.*(\.env|id_rsa|id_ed25519|auth\.json|credentials?)")
COMMAND_PREFIX = r"(?:^|[\s;&|])(?:[^\s;&|]*/)?"
DANGEROUS_SHELL = [
    (re.compile(COMMAND_PREFIX + r"gh\s+pr\s+merge(?:\s|$)"), "gh pr merge is outside autonomous worker scope"),
    (re.compile(COMMAND_PREFIX + r"git\s+reset\s+--hard(?:\s|$)"), "git reset --hard is destructive"),
    (re.compile(COMMAND_PREFIX + r"git\s+checkout\s+--(?:\s|$)"), "git checkout -- can discard changes"),
    (re.compile(COMMAND_PREFIX + r"git\s+clean\s+-[A-Za-z]*[dfx]"), "git clean with delete flags is destructive"),
    (re.compile(COMMAND_PREFIX + r"rm\s+-[A-Za-z]*r[A-Za-z]*f|" + COMMAND_PREFIX + r"rm\s+-[A-Za-z]*f[A-Za-z]*r"), "rm -rf is destructive"),
    (re.compile(COMMAND_PREFIX + r"find\s+.+\s+-delete(?:\s|$)"), "find -delete is destructive"),
    (re.compile(COMMAND_PREFIX + r"sudo(?:\s|$)"), "sudo is outside autonomous worker scope"),
    (re.compile(COMMAND_PREFIX + r"(?:ssh|scp|rsync)(?:\s|$)"), "ssh/scp/rsync are side-effect capable"),
    (re.compile(r"(curl|wget)[^|;&]*\|\s*(sh|bash|zsh|python|ruby|perl)(\s|$)"), "download-to-shell is blocked"),
    (re.compile(COMMAND_PREFIX + r"bash\s+<\s*\((?:curl|wget)"), "process substitution from network is blocked"),
    (re.compile(COMMAND_PREFIX + r"(?:mkfs|diskutil\s+erase|dd\s+.+of=)(?:\s|$)"), "disk destructive command is blocked"),
]
WRITE_VERBS = {"cp", "mv", "rm", "touch", "mkdir", "chmod", "chown", "ln", "tee", "install"}
COMMAND_SEPARATORS = {";", "&&", "||", "|", "&", "(", ")"}
REDIRECT_OPERATORS = {">", ">>", "&>", "&>>"}
OPTION_VALUE_FLAGS = {
    "cp": {"-S", "--suffix", "--context", "-t", "--target-directory"},
    "mv": {"-S", "--suffix", "--context", "-t", "--target-directory"},
    "ln": {"-S", "--suffix", "-t", "--target-directory"},
    "install": {"-g", "--group", "-m", "--mode", "-o", "--owner", "-S", "--suffix", "-t", "--target-directory"},
    "touch": {"-d", "--date", "-r", "--reference", "-t", "--time"},
    "mkdir": {"-m", "--mode", "-Z", "--context"},
    "chmod": {"--reference"},
    "chown": {"--from", "--reference"},
}
GIT_GLOBAL_VALUE_FLAGS = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--config-env"}
GH_GLOBAL_VALUE_FLAGS = {"-R", "--repo", "--hostname"}


def main() -> int:
    started = time.perf_counter()
    deadline = started + capacity_hook_deadline_seconds()
    event = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CODEX_HOOK_EVENT", "")
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        return deny(event, {}, f"invalid hook JSON: {exc}")

    try:
        decision, reason, details = evaluate(event, payload, deadline=deadline)
        details["hook_elapsed_ms"] = round((time.perf_counter() - started) * 1000, 3)
        write_audit(event, decision, reason, payload, details)
    except Exception as exc:  # pragma: no cover - fail closed by design
        fallback_payload = payload if isinstance(payload, dict) else {}
        reason = f"hook policy error: {exc}"
        try:
            write_audit(event, "block", reason, fallback_payload, {})
        except Exception:
            pass
        if event in FAIL_CLOSED_EVENTS or not event:
            print(reason, file=sys.stderr)
            return 2
        print(reason, file=sys.stderr)
        return 0

    if decision == "block":
        print(reason, file=sys.stderr)
        return 2
    return 0


def evaluate(event: str, payload: dict[str, Any], *, deadline: float | None = None) -> tuple[str, str, dict[str, Any]]:
    if event not in KNOWN_EVENTS:
        return "block", "unknown hook event", {}

    tool_name = find_first(payload, ("tool_name", "toolName", "tool", "name", "subagent_type", "agent", "agent_name"))
    tool_name = str(tool_name or "")
    command = extract_command(payload)
    details = {
        "tool": tool_name,
        "command_sha256": stable_hash(command) if command else "",
    }
    autonomous_agent = bool(find_first(payload, ("agent_id", "agentId", "agent_type", "agentType")))
    if autonomous_agent:
        details["agent_type"] = str(find_first(payload, ("agent_type", "agentType")) or "unknown")

    if event == "PostToolUse":
        return handle_post_tool_use(payload, tool_name, details)

    if event == "SubagentStop":
        return handle_subagent_stop(payload, details)

    if event == "Stop":
        return handle_stop(payload, details)

    if event == "SessionEnd":
        return handle_session_end(payload, details)

    if event == "SubagentStart":
        return handle_subagent_start(payload, tool_name, details)

    if is_side_effect_mcp_or_app(tool_name):
        return "block", f"side-effect capable MCP/app tool is blocked: {tool_name}", details

    if is_apply_patch_tool(tool_name):
        patch_decision = evaluate_patch(command)
        if patch_decision:
            return "block", patch_decision, details
        return "allow", "apply_patch targets stay inside current worktree", details

    if command:
        shell_decision = evaluate_shell(command, autonomous_agent=autonomous_agent)
        if shell_decision:
            return "block", shell_decision, details

    if event in FAIL_CLOSED_EVENTS and not tool_name and not command:
        return "block", "fail-closed event lacked tool or command identity", details

    if event == "PreToolUse" and is_spawn_agent_tool(tool_name):
        role_decision = evaluate_spawn_role(payload, tool_name)
        details.update(role_decision[2])
        if role_decision[0] == "block":
            return role_decision[0], role_decision[1], details
        return handle_spawn_capacity(payload, details, deadline=deadline)

    return "allow", "policy allowed", details


def handle_spawn_capacity(payload: dict[str, Any], details: dict[str, Any], *, deadline: float | None = None) -> tuple[str, str, dict[str, Any]]:
    request = capacity_request(payload)
    details.update(request.audit_details)
    if request.error:
        return "block", request.error, details
    if not capacity_enforcement_enabled():
        details["capacity_state"] = "BYPASS"
        details["capacity_enforcement"] = "disabled"
        return "allow", "capacity enforcement bypass", details

    snapshot_budget, deadline_reason = capacity_stage_budget(
        deadline,
        reserve_seconds=CAPACITY_AFTER_SNAPSHOT_RESERVE_SECONDS,
        details=details,
        stage="snapshot",
    )
    if deadline_reason:
        return "block", deadline_reason, details

    base_store = capacity_store(capacity=DEFAULT_CAPACITY, max_operation_seconds=snapshot_budget)
    capacity_limit, wave_limit, observer_reason, root_identity = observed_capacity_limit(base_store, details, deadline=deadline)
    if observer_reason:
        return "block", observer_reason, details

    acquire_budget, deadline_reason = capacity_stage_budget(
        deadline,
        reserve_seconds=CAPACITY_AFTER_ACQUIRE_RESERVE_SECONDS,
        details=details,
        stage="acquire",
    )
    if deadline_reason:
        return "block", deadline_reason, details

    result = capacity_store(capacity=capacity_limit, max_operation_seconds=acquire_budget).acquire_or_queue(
        session_id=request.session_id,
        turn_id=request.turn_id,
        task_name=request.task_name,
        wave_limit=wave_limit,
        root_pid=root_identity[0] if root_identity else None,
        root_start_marker=root_identity[1] if root_identity else None,
    )
    details["capacity"] = sanitize_capacity_result(result)
    state = str(result.get("state") or "")
    if state == "LEASED":
        return "allow", "capacity leased", details
    if state == CAPACITY_QUEUED:
        return "block", capacity_queue_deny_json(result), details
    if state == "ERROR":
        reason = str(result.get("reason") or "unknown_capacity_error")
        return "block", f"capacity error: {reason}", details
    return "block", f"unexpected capacity state: {state or 'missing'}", details


def observed_capacity_limit(store: CapacityStore, details: dict[str, Any], *, deadline: float | None = None) -> tuple[int, Optional[int], str, tuple[int, str] | None]:
    snapshot_result = store.snapshot()
    if snapshot_result.get("state") == "ERROR":
        details["capacity_snapshot"] = sanitize_capacity_result(snapshot_result)
        return 0, 0, f"capacity error: {snapshot_result.get('reason') or 'snapshot_failed'}", None

    _, deadline_reason = capacity_stage_budget(
        deadline,
        reserve_seconds=CAPACITY_AFTER_OBSERVER_RESERVE_SECONDS,
        details=details,
        stage="observer",
    )
    if deadline_reason:
        return 0, 0, deadline_reason, None

    managed_active = int(snapshot_result.get("active_count") or 0)
    managed_reserved = int(snapshot_result.get("reserved_count") or managed_active)
    managed_slots = max(managed_active, managed_reserved)
    details["capacity_snapshot"] = {"active_count": managed_active, "reserved_count": managed_reserved}
    snapshot = observer_snapshot_from_env(details)
    root_identity = root_identity_from_snapshot(snapshot) if snapshot is not None else None
    if snapshot is None:
        try:
            snapshot = capacity_observer.collect_snapshot(
                state_dir=store.state_dir,
                deadline=deadline,
                managed_root_identities=store.managed_root_identities(),
            )
            raw_identity = snapshot.get("current_codex_root_identity")
            if isinstance(raw_identity, (list, tuple)) and len(raw_identity) == 2:
                root_identity = normalize_root_identity(raw_identity[0], raw_identity[1])
        except Exception as exc:
            observation = capacity_observer.fail_closed_output(str(exc))
            details["capacity_observer"] = sanitize_observer_result(observation)
            return 0, 0, capacity_observer_deny_json(observation), None
    if snapshot is not None:
        snapshot["active_slots"] = managed_slots
        snapshot = observer_public_snapshot(snapshot)
    observer_budget, deadline_reason = capacity_stage_budget(
        deadline,
        reserve_seconds=CAPACITY_AFTER_OBSERVER_RESERVE_SECONDS,
        details=details,
        stage="observer_run",
    )
    if deadline_reason:
        return 0, 0, deadline_reason, root_identity
    observation = observe_capacity_with_budget(
        snapshot=snapshot,
        state_dir=store.state_dir,
        active_slots=managed_slots,
        max_operation_seconds=observer_budget,
    )
    details["capacity_observer"] = sanitize_observer_result(observation)
    status = str(observation.get("status") or "RED")
    if status == "RED":
        return 0, 0, capacity_observer_deny_json(observation), root_identity
    measurements = observation.get("measurements") if isinstance(observation.get("measurements"), dict) else {}
    external_roots = max(0, int(float(measurements.get("external_codex_roots") or 0)))
    admission = max(0, min(MAX_CAPACITY, int(observation.get("admission_capacity") or 0)))
    max_wave = max(0, min(MAX_CAPACITY, int(observation.get("max_wave_size") or 0)))
    if status == "YELLOW":
        capacity_limit = max(0, min(DEFAULT_CAPACITY, admission) - external_roots)
        wave_limit: Optional[int] = max(0, min(2, max_wave, capacity_limit))
    else:
        capacity_limit = max(0, admission - external_roots)
        wave_limit = None
    details["capacity_external_codex_roots"] = external_roots
    details["capacity_limit"] = capacity_limit
    if wave_limit is not None:
        details["capacity_wave_limit"] = wave_limit
    return capacity_limit, wave_limit, "", root_identity


def root_identity_from_snapshot(snapshot: dict[str, Any] | None) -> tuple[int, str] | None:
    if not isinstance(snapshot, dict):
        return None
    return normalize_root_identity(
        snapshot.get("current_codex_root_pid"),
        snapshot.get("current_codex_root_start_marker"),
    )


def normalize_root_identity(pid: Any, marker: Any) -> tuple[int, str] | None:
    if pid in (None, "") or marker in (None, ""):
        return None
    try:
        root_pid = int(pid)
    except (TypeError, ValueError):
        return None
    start_marker = str(marker).strip()
    if root_pid <= 0 or not start_marker:
        return None
    return root_pid, start_marker


def observer_public_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    cleaned = dict(snapshot)
    cleaned.pop("current_codex_root_identity", None)
    cleaned.pop("current_codex_root_pid", None)
    cleaned.pop("current_codex_root_start_marker", None)
    return cleaned


def capacity_observer_deny_json(observation: dict[str, Any]) -> str:
    payload = {
        "decision": "deny",
        "permissionDecision": "deny",
        "reason": "CAPACITY_OBSERVER_RED",
        "code": "CAPACITY_OBSERVER_RED",
        "status": observation.get("status") or "RED",
        "reasons": observation.get("reasons") or [],
        "admission_capacity": observation.get("admission_capacity") or 0,
        "max_wave_size": observation.get("max_wave_size") or 0,
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def observer_snapshot_from_env(details: dict[str, Any]) -> Optional[dict[str, Any]]:
    path = os.getenv(CAPACITY_OBSERVER_SNAPSHOT_ENV)
    if not path:
        details["capacity_observer_snapshot_env"] = "unset"
        return None
    if os.getenv(CAPACITY_OBSERVER_TEST_MODE_ENV) != "1":
        details["capacity_observer_snapshot_env"] = "ignored_without_test_mode"
        return None
    details["capacity_observer_snapshot_env"] = "test_mode"
    with Path(path).open("r", encoding="utf-8") as handle:
        snapshot = json.load(handle)
    if not isinstance(snapshot, dict):
        raise ValueError("capacity observer snapshot must be a JSON object")
    return snapshot


def capacity_hook_deadline_seconds() -> float:
    raw = os.getenv(CAPACITY_HOOK_DEADLINE_MS_ENV)
    if raw in (None, ""):
        return CAPACITY_HOOK_DEADLINE_SECONDS
    try:
        milliseconds = float(raw)
    except ValueError:
        return CAPACITY_HOOK_DEADLINE_SECONDS
    return max(0.001, min(1.0, milliseconds / 1000.0))


def capacity_stage_budget(
    deadline: float | None,
    *,
    reserve_seconds: float,
    details: dict[str, Any],
    stage: str,
) -> tuple[float, str]:
    if deadline is None:
        return CAPACITY_HOOK_DEADLINE_SECONDS, ""
    remaining = deadline - time.perf_counter()
    details[f"capacity_{stage}_remaining_ms"] = round(max(0.0, remaining) * 1000, 3)
    budget = remaining - max(0.0, reserve_seconds)
    if budget < CAPACITY_MIN_STAGE_SECONDS:
        return 0.0, capacity_deadline_deny_json(stage, remaining)
    return max(CAPACITY_MIN_STAGE_SECONDS, budget), ""


def capacity_deadline_deny_json(stage: str, remaining_seconds: float) -> str:
    payload = {
        "decision": "deny",
        "permissionDecision": "deny",
        "reason": CAPACITY_DEADLINE_EXHAUSTED,
        "code": CAPACITY_DEADLINE_EXHAUSTED,
        "stage": stage,
        "remaining_ms": round(max(0.0, remaining_seconds) * 1000, 3),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def capacity_store(*, capacity: int, max_operation_seconds: float | None = None) -> CapacityStore:
    if capacity_store_accepts_operation_budget():
        return CapacityStore(capacity=capacity, max_operation_seconds=max_operation_seconds)
    if max_operation_seconds is None:
        return CapacityStore(capacity=capacity)
    original = getattr(capacity_core, "MAX_OPERATION_SECONDS", None)
    if original is not None:
        capacity_core.MAX_OPERATION_SECONDS = max_operation_seconds
    return CapacityStore(capacity=capacity)


def capacity_store_accepts_operation_budget() -> bool:
    try:
        return "max_operation_seconds" in inspect.signature(CapacityStore).parameters
    except (TypeError, ValueError):
        return False


def observe_capacity_with_budget(
    *,
    snapshot: dict[str, Any] | None,
    state_dir: Path,
    active_slots: int,
    max_operation_seconds: float,
) -> dict[str, Any]:
    original = capacity_observer.OBSERVE_TIMEOUT_SECONDS
    capacity_observer.OBSERVE_TIMEOUT_SECONDS = max(CAPACITY_MIN_STAGE_SECONDS, max_operation_seconds)
    try:
        return observe_capacity(snapshot=snapshot, state_dir=state_dir, active_slots=active_slots)
    finally:
        capacity_observer.OBSERVE_TIMEOUT_SECONDS = original


def sanitize_observer_result(result: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "status",
        "reasons",
        "effective_capacity",
        "admission_capacity",
        "max_wave_size",
        "capacity_mode",
        "successful_observations",
        "clean_cycles",
    }
    sanitized = {key: result[key] for key in sorted(allowed) if key in result}
    measurements = result.get("measurements")
    if isinstance(measurements, dict):
        sanitized["measurements"] = {
            key: measurements[key]
            for key in ("active_slots", "codex_root_count", "external_codex_roots", "root_fd_state", "memory_pressure", "memory_free_percent")
            if key in measurements
        }
    return sanitized


def handle_post_tool_use(
    payload: dict[str, Any],
    tool_name: str,
    details: dict[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    if not is_spawn_agent_tool(tool_name):
        return "allow", "audit-only event", details
    if not tool_response_failed(payload.get("tool_response")):
        details["capacity_release"] = "not_failed"
        return "allow", "spawn succeeded or failure was not proven", details

    request = capacity_request(payload)
    details.update(request.audit_details)
    if request.error:
        details["capacity_release_error"] = request.error
        return "allow", "spawn failure could not be mapped to capacity request", details
    result = CapacityStore(capacity=DEFAULT_CAPACITY).release_request(
        request.request_id,
        expected_state="PROVISIONAL",
    )
    details["capacity"] = sanitize_capacity_result(result)
    if result.get("state") == "ERROR":
        details["capacity_release_error"] = str(result.get("reason") or "unknown_capacity_error")
    return "allow", "failed spawn provisional release attempted", details


def handle_subagent_start(
    payload: dict[str, Any],
    tool_name: str,
    details: dict[str, Any],
) -> tuple[str, str, dict[str, Any]]:
    role_decision = evaluate_spawn_role(payload, tool_name)
    details.update(role_decision[2])
    session_id = hook_string(payload, "session_id")
    turn_id = hook_string(payload, "turn_id")
    agent_id = hook_string(payload, "agent_id")
    if not session_id or not turn_id or not agent_id:
        details["capacity_lifecycle_error"] = "missing_session_turn_or_agent_id"
        return "allow", "subagent start lifecycle identity incomplete", details
    result = CapacityStore(capacity=DEFAULT_CAPACITY).activate_next(
        session_id=session_id,
        turn_id=turn_id,
        agent_id=agent_id,
    )
    details["capacity"] = sanitize_capacity_result(result)
    return "allow", "subagent start capacity activation attempted", details


def handle_subagent_stop(payload: dict[str, Any], details: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    session_id = hook_string(payload, "session_id")
    agent_id = hook_string(payload, "agent_id")
    if not session_id or not agent_id:
        details["capacity_lifecycle_error"] = "missing_session_or_agent_id"
        return "allow", "subagent stop lifecycle identity incomplete", details
    result = CapacityStore(capacity=DEFAULT_CAPACITY).release_agent(session_id=session_id, agent_id=agent_id)
    details["capacity"] = sanitize_capacity_result(result)
    return "allow", "subagent stop capacity release attempted", details


def handle_stop(payload: dict[str, Any], details: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    session_id = hook_string(payload, "session_id")
    turn_id = hook_string(payload, "turn_id")
    if not session_id or not turn_id:
        details["capacity_lifecycle_error"] = "missing_session_or_turn_id"
        return "allow", "stop lifecycle identity incomplete", details
    result = CapacityStore(capacity=DEFAULT_CAPACITY).cancel_turn(session_id=session_id, turn_id=turn_id)
    details["capacity"] = sanitize_capacity_result(result)
    return "allow", "turn capacity cancellation attempted", details


def handle_session_end(payload: dict[str, Any], details: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    session_id = hook_string(payload, "session_id")
    if not session_id:
        details["capacity_lifecycle_error"] = "missing_session_id"
        return "allow", "session end lifecycle identity incomplete", details
    store = CapacityStore(capacity=DEFAULT_CAPACITY)
    canceled = store.cancel_session(session_id=session_id)
    reconciled = store.reconcile(session_id=session_id)
    details["capacity_cancel_session"] = sanitize_capacity_result(canceled)
    details["capacity_reconcile"] = sanitize_capacity_result(reconciled)
    return "allow", "session capacity cleanup attempted", details


class CapacityRequest:
    def __init__(
        self,
        *,
        session_id: str = "",
        turn_id: str = "",
        task_name: str = "",
        request_id: str = "",
        error: str = "",
    ) -> None:
        self.session_id = session_id
        self.turn_id = turn_id
        self.task_name = task_name
        self.request_id = request_id
        self.error = error

    @property
    def audit_details(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "turn_id": self.turn_id,
            "request_id": self.request_id,
            "task_name_present": bool(self.task_name),
        }


def capacity_request(payload: dict[str, Any]) -> CapacityRequest:
    session_id = hook_string(payload, "session_id")
    turn_id = hook_string(payload, "turn_id")
    tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
    task_name = ""
    if isinstance(tool_input, dict):
        task_name = str(tool_input.get("task_name") or tool_input.get("taskName") or "")
    if not session_id or not turn_id:
        return CapacityRequest(session_id=session_id, turn_id=turn_id, task_name=task_name, error="capacity request lacked session_id or turn_id")
    if not task_name:
        return CapacityRequest(session_id=session_id, turn_id=turn_id, task_name=task_name, error="capacity request lacked task_name")
    request_id = request_hash(session_id, turn_id, task_name)
    return CapacityRequest(session_id=session_id, turn_id=turn_id, task_name=task_name, request_id=request_id)


def hook_string(payload: dict[str, Any], key: str) -> str:
    value = payload.get(key)
    return str(value) if value not in (None, "") else ""


def capacity_enforcement_enabled() -> bool:
    return os.getenv(CAPACITY_ENFORCEMENT_ENV, "1") != "0"


def capacity_queue_deny_json(result: dict[str, Any]) -> str:
    payload = {
        "decision": "deny",
        "permissionDecision": "deny",
        "reason": CAPACITY_QUEUED,
        "code": CAPACITY_QUEUED,
        "request_id": result.get("request_id"),
        "ticket_id": result.get("ticket_id"),
        "ticket_position": result.get("ticket_position"),
        "retry_delay_ms": result.get("retry_delay_ms"),
        "wait_command": result.get("wait_command"),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def sanitize_capacity_result(result: dict[str, Any]) -> dict[str, Any]:
    allowed = {
        "state",
        "reason",
        "request_id",
        "lease_id",
        "fencing_epoch",
        "lease_state",
        "ticket_id",
        "ticket_state",
        "ticket_position",
        "retry_delay_ms",
        "wait_command",
        "session_id",
        "turn_id",
        "agent_id",
        "canceled",
        "canceled_tickets",
        "leases_marked",
        "tickets_canceled",
        "ttl_released",
    }
    return {key: value for key, value in result.items() if key in allowed}


def tool_response_failed(value: Any) -> bool:
    if isinstance(value, dict):
        for key in ("error", "exception", "failure"):
            if value.get(key):
                return True
        for key in ("is_error", "isError", "failed"):
            if value.get(key) is True:
                return True
        for key in ("ok", "success"):
            if value.get(key) is False:
                return True
        for key in ("status", "state", "result"):
            status = str(value.get(key) or "").strip().lower()
            if status in {"error", "failed", "failure", "denied", "blocked"}:
                return True
        for key in ("exit_code", "exitCode", "returncode", "return_code"):
            code = value.get(key)
            if isinstance(code, int) and code != 0:
                return True
        return False
    if isinstance(value, str):
        text_value = value.strip()
        if not text_value:
            return False
        try:
            decoded = json.loads(text_value)
        except json.JSONDecodeError:
            return text_value.lower().startswith(("error:", "failed:", "failure:"))
        return tool_response_failed(decoded)
    return False


def evaluate_spawn_role(
    payload: dict[str, Any],
    tool_name: str,
) -> tuple[str, str, dict[str, Any]]:
    raw_agent_type = find_first(payload, ("agent_type", "agentType", "agent_type_override", "agentTypeOverride"))
    if raw_agent_type in (None, ""):
        tool_input = payload.get("tool_input") if isinstance(payload.get("tool_input"), dict) else {}
        if isinstance(tool_input, dict):
            raw_agent_type = tool_input.get("agent_type") or tool_input.get("agentType")
    agent_type = normalize_agent(str(raw_agent_type or tool_name or ""))
    details = {"agent_type": agent_type}
    if not agent_type:
        return "block", "subagent start payload did not identify agent type", details
    if agent_type not in KNOWN_AGENTS and not is_spawn_agent_tool(tool_name):
        return "block", f"subagent type is not in the approved role set: {agent_type}", details
    if is_spawn_agent_tool(tool_name) and raw_agent_type not in (None, "") and agent_type not in KNOWN_AGENTS:
        return "block", f"subagent type is not in the approved role set: {agent_type}", details
    return "allow", "approved subagent role", details


def is_spawn_agent_tool(tool_name: str) -> bool:
    lower = tool_name.strip().lower()
    if not lower:
        return False
    parts = [part for part in re.split(r"[^a-z0-9]+", lower) if part]
    collapsed = "".join(parts)
    if collapsed in {"agent", "spawnagent", "collaborationspawnagent"}:
        return True
    if len(parts) >= 2 and parts[-2:] == ["spawn", "agent"]:
        return True
    if len(parts) >= 2 and parts[-1] == "agent" and parts[-2].startswith("collaboration") and parts[-2].endswith("spawn"):
        return True
    return False


def is_apply_patch_tool(tool_name: str) -> bool:
    return "apply_patch" in tool_name.lower()


def evaluate_patch(patch: str) -> str | None:
    if not patch:
        return "apply_patch payload is empty"
    targets = re.findall(
        r"^\*\*\* (?:(?:Add|Update|Delete) File|Move to): (.+)$",
        patch,
        re.MULTILINE,
    )
    if not targets:
        return "apply_patch payload has no file headers"
    root = worktree_root()
    for target in targets:
        candidate = Path(target.strip())
        if not candidate.is_absolute():
            candidate = Path.cwd() / candidate
        try:
            resolved = candidate.resolve(strict=False)
        except OSError:
            resolved = candidate.absolute()
        if not is_relative_to(resolved, root):
            return f"apply_patch target is outside current worktree: {resolved}"
        if ".git" in resolved.parts:
            return f"apply_patch target is inside protected Git metadata: {resolved}"
    return None


def evaluate_shell(command: str, *, autonomous_agent: bool = False) -> str | None:
    normalized = " ".join(command.split())
    vcs_decision = dangerous_vcs_command(normalized, autonomous_agent=autonomous_agent)
    if vcs_decision:
        return vcs_decision
    for pattern, reason in DANGEROUS_SHELL:
        if pattern.search(normalized):
            return reason
    if SECRET_ASSIGNMENT.search(normalized):
        return "secret-like assignment in command is blocked"
    if SECRET_REFERENCE.search(normalized):
        return "secret-like file read is blocked"
    if writes_protected_path(normalized):
        return "write or destructive command targets protected path"
    outside = first_write_outside_worktree(normalized)
    if outside:
        return f"write target is outside current worktree: {outside}"
    return None


def writes_protected_path(command: str) -> bool:
    protected = [
        str(CODEX_HOME),
        str(HOME / ".ssh"),
        "~/.codex",
        "~/.ssh",
    ]
    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()
    if not tokens:
        return False
    write_intent = any(command_basename(token) in WRITE_VERBS for token in tokens) or ">" in tokens or ">>" in tokens
    if not write_intent:
        return False
    return (
        any(path in command for path in protected)
        or ".git/" in command
        or command.endswith("/.git")
        or command.endswith(" .git")
    )


def first_write_outside_worktree(command: str) -> str | None:
    root = worktree_root()
    try:
        tokens = shell_tokens(command)
    except ValueError:
        tokens = command.split()
    for target in write_targets(tokens):
        if target.startswith("-"):
            continue
        expanded_text = os.path.expandvars(os.path.expanduser(target))
        if "$" in expanded_text or "`" in expanded_text:
            return f"unresolved target: {target}"
        expanded = Path(expanded_text)
        if not expanded.is_absolute():
            expanded = Path.cwd() / expanded
        try:
            resolved = expanded.resolve(strict=False)
        except OSError:
            resolved = expanded.absolute()
        if resolved == Path("/dev/null"):
            continue
        if not is_relative_to(resolved, root):
            return str(resolved)
    return None


def shell_tokens(command: str) -> list[str]:
    lexer = shlex.shlex(command.replace("\n", " ; "), posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    return list(lexer)


def write_targets(tokens: list[str]) -> list[str]:
    targets: list[str] = []
    for index, token in enumerate(tokens):
        if token in REDIRECT_OPERATORS and index + 1 < len(tokens):
            targets.append(tokens[index + 1])
            continue
        verb = command_basename(token)
        if verb not in WRITE_VERBS:
            continue
        targets.extend(targets_for_command(verb, command_arguments(tokens, index + 1)))
    return targets


def command_arguments(tokens: list[str], start: int) -> list[str]:
    arguments: list[str] = []
    index = start
    while index < len(tokens) and tokens[index] not in COMMAND_SEPARATORS:
        if tokens[index] in REDIRECT_OPERATORS:
            index += 2
            continue
        arguments.append(tokens[index])
        index += 1
    return arguments


def dangerous_vcs_command(command: str, *, autonomous_agent: bool = False) -> str | None:
    try:
        tokens = shell_tokens(command)
    except ValueError:
        return None
    for index, token in enumerate(tokens):
        executable = command_basename(token)
        if executable not in {"git", "gh"}:
            continue
        arguments = command_arguments(tokens, index + 1)
        if executable == "git":
            command_index, subcommand = find_subcommand(arguments, GIT_GLOBAL_VALUE_FLAGS, {"-C", "-c"})
            remainder = arguments[command_index + 1 :] if command_index is not None else []
            if subcommand == "push" and autonomous_agent:
                return "git " + "push is outside autonomous worker scope"
            if subcommand == "reset" and "--hard" in remainder:
                return "git " + "reset --hard is destructive"
            if subcommand == "checkout" and "--" in remainder:
                return "git " + "checkout -- can discard changes"
            if subcommand == "clean" and any(is_git_clean_delete_flag(arg) for arg in remainder):
                return "git " + "clean with delete flags is destructive"
        else:
            command_index, subcommand = find_subcommand(arguments, GH_GLOBAL_VALUE_FLAGS, {"-R"})
            remainder = arguments[command_index + 1 :] if command_index is not None else []
            _, nested = find_subcommand(remainder, GH_GLOBAL_VALUE_FLAGS, {"-R"})
            if subcommand == "pr" and nested == "merge":
                return "gh " + "pr merge is outside autonomous worker scope"
    return None


def find_subcommand(
    arguments: list[str],
    value_flags: set[str],
    compact_value_flags: set[str],
) -> tuple[int | None, str | None]:
    parse_options = True
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if parse_options and argument == "--":
            parse_options = False
            index += 1
            continue
        if parse_options and argument in value_flags:
            index += 2
            continue
        if parse_options and any(argument.startswith(f"{flag}=") for flag in value_flags if flag.startswith("--")):
            index += 1
            continue
        if parse_options and any(argument.startswith(flag) and len(argument) > len(flag) for flag in compact_value_flags):
            index += 1
            continue
        if parse_options and argument.startswith("-"):
            index += 1
            continue
        return index, argument
    return None, None


def is_git_clean_delete_flag(argument: str) -> bool:
    if argument == "--force":
        return True
    return argument.startswith("-") and not argument.startswith("--") and any(flag in argument[1:] for flag in "dfx")


def targets_for_command(verb: str, arguments: list[str]) -> list[str]:
    target_directory = find_target_directory(arguments)
    operands = positional_operands(arguments, OPTION_VALUE_FLAGS.get(verb, set()))

    if verb == "mv":
        return ([target_directory] if target_directory else []) + operands
    if verb in {"cp", "ln"}:
        return [target_directory] if target_directory else operands[-1:]
    if verb == "install":
        if "-d" in arguments or "--directory" in arguments:
            return operands
        return [target_directory] if target_directory else operands[-1:]
    if verb in {"touch", "mkdir", "rm", "tee"}:
        return operands
    if verb in {"chmod", "chown"}:
        uses_reference = any(arg == "--reference" or arg.startswith("--reference=") for arg in arguments)
        return operands if uses_reference else operands[1:]
    return []


def find_target_directory(arguments: list[str]) -> str | None:
    for index, argument in enumerate(arguments):
        if argument in {"-t", "--target-directory"} and index + 1 < len(arguments):
            return arguments[index + 1]
        if argument.startswith("--target-directory="):
            return argument.split("=", 1)[1]
        if argument.startswith("-t") and len(argument) > 2:
            return argument[2:]
    return None


def positional_operands(arguments: list[str], value_flags: set[str]) -> list[str]:
    operands: list[str] = []
    parse_options = True
    index = 0
    while index < len(arguments):
        argument = arguments[index]
        if parse_options and argument == "--":
            parse_options = False
            index += 1
            continue
        if parse_options and argument in value_flags:
            index += 2
            continue
        if parse_options and any(argument.startswith(f"{flag}=") for flag in value_flags if flag.startswith("--")):
            index += 1
            continue
        if parse_options and argument.startswith("-") and argument != "-":
            index += 1
            continue
        operands.append(argument)
        index += 1
    return operands


def command_basename(token: str) -> str:
    if token.startswith("-") or "=" in token:
        return token
    return Path(token).name


def is_side_effect_mcp_or_app(tool_name: str) -> bool:
    if not tool_name:
        return False
    lower = tool_name.lower()
    if not (lower.startswith("mcp__") or lower.startswith("app.") or lower.startswith("github.") or "connector" in lower):
        return False
    if SIDE_EFFECT_TOOL.search(tool_name) and not READ_LIKE_TOOL.search(tool_name):
        return True
    if SIDE_EFFECT_TOOL.search(tool_name) and not lower.startswith(("mcp__filesystem__read", "mcp__filesystem__list")):
        return True
    return False


def extract_command(payload: Any) -> str:
    for key in ("command", "cmd", "shell_command", "bash_command"):
        value = recursive_find(payload, key)
        if isinstance(value, str):
            return value
    return ""


def find_first(payload: Any, keys: tuple[str, ...]) -> Any:
    for key in keys:
        value = recursive_find(payload, key)
        if value not in (None, ""):
            return value
    return None


def recursive_find(value: Any, key: str) -> Any:
    if isinstance(value, dict):
        if key in value:
            return value[key]
        for child in value.values():
            found = recursive_find(child, key)
            if found is not None:
                return found
    elif isinstance(value, list):
        for child in value:
            found = recursive_find(child, key)
            if found is not None:
                return found
    return None


def worktree_root() -> Path:
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=Path.cwd(),
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=2,
        )
        return Path(result.stdout.strip()).resolve()
    except Exception:
        return Path.cwd().resolve()


def normalize_agent(value: str) -> str:
    return value.strip().lower().replace("_", "-")


def redact(value: str) -> str:
    value = SECRET_ASSIGNMENT.sub(lambda match: match.group(1) + "=<redacted>", value)
    value = re.sub(r"(?i)(bearer\s+)[a-z0-9._~+/=-]+", r"\1<redacted>", value)
    return value


def stable_hash(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def write_audit(event: str, decision: str, reason: str, payload: dict[str, Any], details: dict[str, Any]) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "decision": decision,
        "reason": reason,
        "cwd": str(Path.cwd()),
        "details": details,
        "payload_keys": [key for key in sorted(payload.keys()) if key not in SENSITIVE_PAYLOAD_KEYS],
    }
    with AUDIT_LOG.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(record, sort_keys=True) + "\n")


def is_relative_to(path: Path, parent: Path) -> bool:
    try:
        path.relative_to(parent)
        return True
    except ValueError:
        return False


def deny(event: str, payload: dict[str, Any], reason: str) -> int:
    try:
        write_audit(event, "block", reason, payload, {})
    except Exception:
        pass
    print(reason, file=sys.stderr)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
