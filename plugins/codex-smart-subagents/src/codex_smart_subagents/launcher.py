"""Conservative launcher classification for adaptive interactive Codex runs."""

from __future__ import annotations

import base64
import json
import os
import re
import secrets
import stat
import subprocess
import sys
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Callable, Mapping, Sequence

from .compatibility import codex_version_supported, parse_stable_codex_version

_VERSION_PATTERN = re.compile(r"^codex-cli ([0-9]+\.[0-9]+\.[0-9]+)\n?$")
_SUBCOMMANDS = frozenset(
    {
        "a",
        "app",
        "app-server",
        "apply",
        "archive",
        "cloud",
        "cloud-tasks",
        "completion",
        "debug",
        "delete",
        "doctor",
        "e",
        "exec",
        "exec-server",
        "execpolicy",
        "features",
        "fork",
        "help",
        "login",
        "logout",
        "mcp",
        "mcp-server",
        "plugin",
        "remote-control",
        "review",
        "sandbox",
        "unarchive",
        "update",
    }
)
_RESUME_BOOLEAN_OPTIONS = frozenset(
    {"--last", "--all", "--include-non-interactive"}
)
_SUPPORTED_VALUE_OPTIONS = frozenset({"-C", "--cd", "-i", "--image"})
_SUPPORTED_BOOLEAN_OPTIONS = frozenset(
    {"--search", "--no-alt-screen", "--strict-config"}
)
_BYPASS_LONG_OPTIONS = frozenset(
    {
        "--add-dir",
        "--ask-for-approval",
        "--config",
        "--dangerously-bypass-approvals-and-sandbox",
        "--dangerously-bypass-hook-trust",
        "--disable",
        "--enable",
        "--help",
        "--ignore-user-config",
        "--local-provider",
        "--model",
        "--oss",
        "--profile",
        "--remote",
        "--remote-auth-token-env",
        "--sandbox",
        "--version",
        "--yolo",
    }
)
_BYPASS_SHORT_PREFIXES = ("-a", "-c", "-m", "-p", "-s")
_ROOT_VALUE_OPTIONS = _SUPPORTED_VALUE_OPTIONS | frozenset(
    {
        "--add-dir",
        "--ask-for-approval",
        "--config",
        "--disable",
        "--enable",
        "--local-provider",
        "--model",
        "--profile",
        "--remote",
        "--remote-auth-token-env",
        "--sandbox",
    }
)
_ROOT_SHORT_VALUE_OPTIONS = frozenset({"-a", "-m", "-p", "-s"})
_MODEL_REASONING_EFFORT_ASSIGNMENT = re.compile(
    r"^\s*model_reasoning_effort\s*=\s*(.*?)\s*$"
)


@dataclass
class LauncherError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


class InvocationKind(str, Enum):
    MANAGED_NEW = "managed-new"
    MANAGED_RESUME = "managed-resume"
    NATIVE_SERVICE = "native-service"
    REJECTED_MANAGED = "rejected-managed"


@dataclass(frozen=True)
class InvocationDecision:
    adaptive: bool
    reason: str
    kind: InvocationKind = InvocationKind.REJECTED_MANAGED


@dataclass(frozen=True)
class ManagedInvocation:
    decision: InvocationDecision
    separator_index: int | None
    coordinator_control: bool


def _model_reasoning_effort_value(assignment: str) -> str | None:
    match = _MODEL_REASONING_EFFORT_ASSIGNMENT.fullmatch(assignment)
    return None if match is None else match.group(1)


def is_native_ultra_invocation(arguments: Sequence[str]) -> bool:
    """Return whether the final root reasoning-effort assignment is Ultra."""

    separator_index = next(
        (index for index, token in enumerate(arguments) if token == "--"),
        len(arguments),
    )
    effective_value: str | None = None
    index = 0
    while index < separator_index:
        token = arguments[index]
        if token in _ROOT_VALUE_OPTIONS or token in _ROOT_SHORT_VALUE_OPTIONS:
            index += 2
            continue
        if token == "-c":
            if index + 1 >= separator_index:
                break
            assignment = arguments[index + 1]
            index += 2
        elif token.startswith("-c"):
            assignment = token[2:]
            index += 1
        else:
            index += 1
            continue
        value = _model_reasoning_effort_value(assignment)
        if value is not None:
            effective_value = value
    return effective_value in {"ultra", "\"ultra\"", "'ultra'"}


def classify_invocation(arguments: Sequence[str]) -> InvocationDecision:
    """Classify an unambiguous new or resumed local interactive session."""

    positional: list[str] = []
    root_positional: list[str] = []
    index = 0
    after_separator = False
    while index < len(arguments):
        token = arguments[index]
        if after_separator:
            index += 1
            continue
        if token == "--":
            after_separator = True
            index += 1
            continue
        if token in _SUPPORTED_VALUE_OPTIONS:
            if index + 1 >= len(arguments) or arguments[index + 1] == "":
                return InvocationDecision(False, f"missing value for {token}")
            index += 2
            continue
        if token.startswith("--cd=") or token.startswith("--image="):
            if token.split("=", 1)[1] == "":
                return InvocationDecision(False, f"missing value for {token}")
            index += 1
            continue
        if token.startswith("-C") and token != "-C":
            index += 1
            continue
        if token.startswith("-i") and token != "-i":
            index += 1
            continue
        if token in _SUPPORTED_BOOLEAN_OPTIONS:
            index += 1
            continue
        if token in _RESUME_BOOLEAN_OPTIONS:
            index += 1
            continue
        matched_boolean = next(
            (
                option
                for option in _SUPPORTED_BOOLEAN_OPTIONS
                if token.startswith(option + "=")
            ),
            None,
        )
        if matched_boolean is not None:
            if token.split("=", 1)[1] not in {"true", "false"}:
                return InvocationDecision(
                    False,
                    f"unsupported boolean value for {matched_boolean}",
                )
            index += 1
            continue
        long_name = token.split("=", 1)[0] if token.startswith("--") else ""
        if token in {"-h", "-V"} or long_name in {"--help", "--version"}:
            return InvocationDecision(
                False,
                f"service control {token}",
                InvocationKind.NATIVE_SERVICE,
            )
        if long_name in _BYPASS_LONG_OPTIONS:
            return InvocationDecision(
                False,
                f"explicit control {long_name}",
                InvocationKind.REJECTED_MANAGED,
            )
        if any(token.startswith(prefix) for prefix in _BYPASS_SHORT_PREFIXES):
            return InvocationDecision(False, f"explicit control {token}")
        if token.startswith("-") and token != "-":
            return InvocationDecision(False, f"unknown option {token}")
        positional.append(token)
        root_positional.append(token)
        index += 1

    if root_positional and root_positional[0] == "resume":
        if len(positional) > 3:
            return InvocationDecision(
                False,
                "resume accepts at most session and prompt positionals",
                InvocationKind.REJECTED_MANAGED,
            )
        return InvocationDecision(
            True,
            "supported resumed interactive invocation",
            InvocationKind.MANAGED_RESUME,
        )
    if any(token in _RESUME_BOOLEAN_OPTIONS for token in arguments):
        return InvocationDecision(
            False,
            "resume selector without resume subcommand",
            InvocationKind.REJECTED_MANAGED,
        )
    if len(positional) > 1:
        return InvocationDecision(False, "multiple positional arguments")
    if root_positional and root_positional[0] in _SUBCOMMANDS:
        return InvocationDecision(
            False,
            f"subcommand {root_positional[0]}",
            InvocationKind.NATIVE_SERVICE,
        )
    return InvocationDecision(
        True,
        "supported interactive invocation",
        InvocationKind.MANAGED_NEW,
    )


def parse_managed_invocation(arguments: Sequence[str]) -> ManagedInvocation:
    """Parse root controls once and preserve the first ``--`` boundary."""

    separator_index = next(
        (index for index, token in enumerate(arguments) if token == "--"),
        None,
    )
    root_end = len(arguments) if separator_index is None else separator_index
    remaining: list[str] = []
    coordinator_control = False
    index = 0
    while index < root_end:
        token = arguments[index]
        if token in {"--model", "-m"}:
            if index + 1 >= root_end or not arguments[index + 1]:
                return ManagedInvocation(
                    InvocationDecision(False, f"missing value for {token}"),
                    separator_index,
                    coordinator_control,
                )
            coordinator_control = True
            index += 2
            continue
        if token.startswith("--model="):
            if not token.split("=", 1)[1]:
                return ManagedInvocation(
                    InvocationDecision(False, "missing value for --model"),
                    separator_index,
                    coordinator_control,
                )
            coordinator_control = True
            index += 1
            continue
        if token.startswith("-m") and token != "-m":
            if not token[2:]:
                return ManagedInvocation(
                    InvocationDecision(False, "missing value for -m"),
                    separator_index,
                    coordinator_control,
                )
            coordinator_control = True
            index += 1
            continue
        if token == "-c":
            if index + 1 >= root_end:
                return ManagedInvocation(
                    InvocationDecision(False, "missing value for -c"),
                    separator_index,
                    coordinator_control,
                )
            assignment = arguments[index + 1].lstrip()
            if assignment.startswith("model=") or (
                _model_reasoning_effort_value(assignment) is not None
            ):
                coordinator_control = True
                index += 2
                continue
            remaining.extend((token, arguments[index + 1]))
            index += 2
            continue
        if token.startswith("-c") and token != "-c":
            assignment = token[2:].lstrip()
            if assignment.startswith("model=") or (
                _model_reasoning_effort_value(assignment) is not None
            ):
                coordinator_control = True
                index += 1
                continue
        remaining.append(token)
        index += 1
    if separator_index is not None:
        remaining.extend(arguments[separator_index:])
    return ManagedInvocation(
        classify_invocation(remaining),
        separator_index,
        coordinator_control,
    )


def classify_managed_invocation(arguments: Sequence[str]) -> InvocationDecision:
    """Classify without treating root model controls as native bypasses."""

    return parse_managed_invocation(arguments).decision


def parse_codex_version(output: str) -> str:
    match = _VERSION_PATTERN.fullmatch(output)
    if match is None:
        raise LauncherError(
            "VERSION_OUTPUT_INVALID",
            "Codex version output has an unexpected format",
        )
    version = match.group(1)
    try:
        parse_stable_codex_version(version)
    except ValueError as exc:
        raise LauncherError(
            "VERSION_OUTPUT_INVALID",
            "Codex version output is not canonical stable SemVer",
        ) from exc
    return version


def probe_codex_version(binary: Path) -> str:
    result = subprocess.run(
        [str(binary), "--version"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )
    if result.returncode != 0:
        raise LauncherError(
            "VERSION_PROBE_FAILED",
            result.stderr.strip()[:1000] or "Codex version probe failed",
        )
    return parse_codex_version(result.stdout)


def build_adaptive_environment(
    source: Mapping[str, str],
) -> dict[str, str]:
    environment = dict(source)
    token = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    environment["CODEX_ADAPTIVE_SESSION_ID"] = f"cas1_{token}"
    environment["CODEX_SMART_LAUNCHER_ACTIVE"] = "1"
    return environment


def clean_ordinary_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Remove every launcher-owned value before an ordinary execution."""

    result: dict[str, str] = {}
    for name, value in source.items():
        if (
            name.startswith("CODEX_SMART_")
            or name.startswith("CODEX_ADAPTIVE_")
            or name.startswith("CODEX_COORDINATOR_")
            or name == "CODEX_REAL_BIN"
        ):
            continue
        result[name] = value
    return result


def apply_coordinator_defaults(
    arguments: Sequence[str],
    coordinator: Mapping[str, str],
) -> list[str]:
    """Append one validated coordinator pair to an invocation without explicit controls."""

    if set(coordinator) != {"model", "reasoning_effort"}:
        raise LauncherError(
            "COORDINATOR_PAIR_INVALID",
            "coordinator pair must contain exactly model and reasoning_effort",
        )
    model = coordinator["model"]
    effort = coordinator["reasoning_effort"]
    for name, value in (("model", model), ("reasoning_effort", effort)):
        if (
            not isinstance(value, str)
            or not value
            or len(value.encode("utf-8")) > 128
            or "\0" in value
            or "\n" in value
            or "\r" in value
        ):
            raise LauncherError(
                "COORDINATOR_PAIR_INVALID",
                f"coordinator {name} is invalid",
            )
    separator_index = next(
        (index for index, token in enumerate(arguments) if token == "--"),
        len(arguments),
    )
    return [
        *arguments[:separator_index],
        "--model",
        model,
        "-c",
        f"model_reasoning_effort={json.dumps(effort)}",
        *arguments[separator_index:],
    ]


def validate_real_binary(binary: Path, wrapper: Path) -> Path:
    if not binary.is_absolute():
        raise LauncherError(
            "REAL_CODEX_NOT_ABSOLUTE",
            "the real Codex path must be absolute",
        )
    resolved = binary.expanduser().resolve()
    try:
        info = resolved.stat()
    except OSError as exc:
        raise LauncherError(
            "REAL_CODEX_UNAVAILABLE",
            f"cannot inspect real Codex: {exc}",
        ) from exc
    if not stat.S_ISREG(info.st_mode) or not os.access(resolved, os.X_OK):
        raise LauncherError(
            "REAL_CODEX_UNAVAILABLE",
            "the real Codex path is not an executable regular file",
        )
    try:
        same = os.path.samefile(resolved, wrapper.expanduser().resolve())
    except OSError:
        same = resolved == wrapper.expanduser().resolve()
    if same:
        raise LauncherError(
            "LAUNCHER_RECURSION",
            "the real Codex binary resolves to the launcher",
        )
    return resolved


def run_launcher(
    arguments: Sequence[str],
    *,
    real_binary: Path,
    wrapper: Path,
    environment: Mapping[str, str] | None = None,
    coordinator: Mapping[str, str] | None = None,
    ensure_controller: Callable[[Mapping[str, str]], None] | None = None,
    execve: Callable[[str, Sequence[str], Mapping[str, str]], object] = os.execve,
) -> int:
    """Probe, optionally prepare adaptive mode, then replace the wrapper."""

    source_environment = dict(os.environ if environment is None else environment)
    real = validate_real_binary(real_binary, wrapper)
    command = [str(real), *arguments]
    if source_environment.get("CODEX_SMART_LAUNCHER_ACTIVE") == "1":
        execve(str(real), command, clean_ordinary_environment(source_environment))
        raise AssertionError("execve unexpectedly returned")

    try:
        version = probe_codex_version(real)
    except LauncherError as exc:
        print(f"codex-smart: {exc}", file=sys.stderr)
        execve(
            str(real),
            command,
            clean_ordinary_environment(source_environment),
        )
        raise AssertionError("execve unexpectedly returned")

    decision = classify_invocation(arguments)
    if not codex_version_supported(version):
        print(
            "codex-smart: умный режим отключён для неподдерживаемой "
            f"версии Codex {version}",
            file=sys.stderr,
        )
        execve(
            str(real),
            command,
            clean_ordinary_environment(source_environment),
        )
        raise AssertionError("execve unexpectedly returned")
    if not decision.adaptive:
        execve(
            str(real),
            command,
            clean_ordinary_environment(source_environment),
        )
        raise AssertionError("execve unexpectedly returned")

    adaptive_environment = build_adaptive_environment(source_environment)
    if ensure_controller is not None:
        try:
            ensure_controller(adaptive_environment)
        except Exception:
            print(
                "codex-smart: контроллер недоступен, запускается обычный Codex",
                file=sys.stderr,
            )
            execve(
                str(real),
                command,
                clean_ordinary_environment(source_environment),
            )
            raise AssertionError("execve unexpectedly returned")
    if coordinator is not None:
        command = [
            str(real),
            *apply_coordinator_defaults(arguments, coordinator),
        ]
    execve(str(real), command, adaptive_environment)
    raise AssertionError("execve unexpectedly returned")
