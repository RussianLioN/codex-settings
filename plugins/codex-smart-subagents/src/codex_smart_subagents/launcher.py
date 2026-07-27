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
        "resume",
        "review",
        "sandbox",
        "unarchive",
        "update",
    }
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


@dataclass
class LauncherError(RuntimeError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class InvocationDecision:
    adaptive: bool
    reason: str


def classify_invocation(arguments: Sequence[str]) -> InvocationDecision:
    """Enable only an unambiguous new local interactive session."""

    positional: list[str] = []
    index = 0
    after_separator = False
    while index < len(arguments):
        token = arguments[index]
        if after_separator:
            positional.append(token)
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
        if long_name in _BYPASS_LONG_OPTIONS:
            return InvocationDecision(False, f"explicit control {long_name}")
        if token in {"-h", "-V"} or any(
            token.startswith(prefix) for prefix in _BYPASS_SHORT_PREFIXES
        ):
            return InvocationDecision(False, f"explicit control {token}")
        if token.startswith("-") and token != "-":
            return InvocationDecision(False, f"unknown option {token}")
        positional.append(token)
        index += 1

    if len(positional) > 1:
        return InvocationDecision(False, "multiple positional arguments")
    if positional and not after_separator and positional[0] in _SUBCOMMANDS:
        return InvocationDecision(False, f"subcommand {positional[0]}")
    return InvocationDecision(True, "supported interactive invocation")


def classify_managed_invocation(arguments: Sequence[str]) -> InvocationDecision:
    """Classify a managed launch without treating root model controls as bypasses."""

    remaining: list[str] = []
    index = 0
    while index < len(arguments):
        token = arguments[index]
        if token in {"--model", "-m"}:
            if index + 1 >= len(arguments) or not arguments[index + 1]:
                return InvocationDecision(False, f"missing value for {token}")
            index += 2
            continue
        if token.startswith("--model="):
            if not token.split("=", 1)[1]:
                return InvocationDecision(False, "missing value for --model")
            index += 1
            continue
        if token.startswith("-m") and token != "-m":
            if not token[2:]:
                return InvocationDecision(False, "missing value for -m")
            index += 1
            continue
        if token == "-c":
            if index + 1 >= len(arguments):
                return InvocationDecision(False, "missing value for -c")
            assignment = arguments[index + 1].lstrip()
            if assignment.startswith("model=") or assignment.startswith(
                "model_reasoning_effort="
            ):
                index += 2
                continue
            remaining.extend((token, arguments[index + 1]))
            index += 2
            continue
        if token.startswith("-c") and token != "-c":
            assignment = token[2:].lstrip()
            if assignment.startswith("model=") or assignment.startswith(
                "model_reasoning_effort="
            ):
                index += 1
                continue
        remaining.append(token)
        index += 1
    return classify_invocation(remaining)


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
    return [
        *arguments,
        "--model",
        model,
        "-c",
        f"model_reasoning_effort={json.dumps(effort)}",
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
        execve(str(real), command, source_environment)
        raise AssertionError("execve unexpectedly returned")

    try:
        version = probe_codex_version(real)
    except LauncherError as exc:
        print(f"codex-smart: {exc}", file=sys.stderr)
        execve(str(real), command, source_environment)
        raise AssertionError("execve unexpectedly returned")

    decision = classify_invocation(arguments)
    if not codex_version_supported(version):
        print(
            "codex-smart: умный режим отключён для неподдерживаемой "
            f"версии Codex {version}",
            file=sys.stderr,
        )
        execve(str(real), command, source_environment)
        raise AssertionError("execve unexpectedly returned")
    if not decision.adaptive:
        execve(str(real), command, source_environment)
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
            execve(str(real), command, source_environment)
            raise AssertionError("execve unexpectedly returned")
    if coordinator is not None:
        command = [
            str(real),
            *apply_coordinator_defaults(arguments, coordinator),
        ]
    execve(str(real), command, adaptive_environment)
    raise AssertionError("execve unexpectedly returned")
