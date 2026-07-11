#!/usr/bin/env python3
"""Fail-closed Codex hook policy for autonomous workflow profiles."""

from __future__ import annotations

import json
import os
import re
import shlex
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


HOME = Path.home().resolve()
CODEX_HOME = Path(os.environ.get("CODEX_HOME", HOME / ".codex")).expanduser().resolve()
AUDIT_LOG = CODEX_HOME / "audit" / "hooks.jsonl"
FAIL_CLOSED_EVENTS = {"PreToolUse", "PermissionRequest", "SubagentStart"}
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
    (re.compile(COMMAND_PREFIX + r"git\s+push(?:\s|$)"), "git push is outside autonomous worker scope"),
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
    event = sys.argv[1] if len(sys.argv) > 1 else os.environ.get("CODEX_HOOK_EVENT", "")
    raw = sys.stdin.read()
    try:
        payload = json.loads(raw) if raw.strip() else {}
    except json.JSONDecodeError as exc:
        return deny(event, {}, f"invalid hook JSON: {exc}")

    try:
        decision, reason, details = evaluate(event, payload)
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
        return 1

    if decision == "block":
        print(reason, file=sys.stderr)
        return 2
    return 0


def evaluate(event: str, payload: dict[str, Any]) -> tuple[str, str, dict[str, Any]]:
    if event not in {"PreToolUse", "PermissionRequest", "PostToolUse", "SubagentStart", "SubagentStop", "Stop"}:
        return "block", "unknown hook event", {}

    tool_name = find_first(payload, ("tool_name", "toolName", "tool", "name", "subagent_type", "agent", "agent_name"))
    tool_name = str(tool_name or "")
    command = extract_command(payload)
    details = {
        "tool": tool_name,
        "command_excerpt": redact(command)[:500] if command else "",
    }

    if event in {"PostToolUse", "SubagentStop", "Stop"}:
        return "allow", "audit-only event", details

    if event == "SubagentStart":
        agent_type = normalize_agent(tool_name or str(find_first(payload, ("type", "kind")) or ""))
        details["agent_type"] = agent_type
        if not agent_type:
            return "block", "subagent start payload did not identify agent type", details
        if agent_type not in KNOWN_AGENTS:
            return "block", f"subagent type is not in the approved role set: {agent_type}", details
        return "allow", "approved subagent role", details

    if is_side_effect_mcp_or_app(tool_name):
        return "block", f"side-effect capable MCP/app tool is blocked: {tool_name}", details

    if command:
        shell_decision = evaluate_shell(command)
        if shell_decision:
            return "block", shell_decision, details

    if event in FAIL_CLOSED_EVENTS and not tool_name and not command:
        return "block", "fail-closed event lacked tool or command identity", details

    return "allow", "policy allowed", details


def evaluate_shell(command: str) -> str | None:
    normalized = " ".join(command.split())
    vcs_decision = dangerous_vcs_command(normalized)
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


def dangerous_vcs_command(command: str) -> str | None:
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
            if subcommand == "push":
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


def write_audit(event: str, decision: str, reason: str, payload: dict[str, Any], details: dict[str, Any]) -> None:
    AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "event": event,
        "decision": decision,
        "reason": reason,
        "cwd": str(Path.cwd()),
        "details": details,
        "payload_keys": sorted(payload.keys()),
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
