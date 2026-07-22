"""Доказательство пользовательской политики и живого bundled MCP версии 2."""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tomllib
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator, Mapping, Sequence

from . import finite_file_lock_v2
from .canonical_json import canonical_json_bytes, domain_fingerprint
from .child_guard_v2 import system_process_start_marker_v2
from .mcp_contracts_v2 import get_tool_definitions_v2
from .mcp_server_v2 import MCP_PROTOCOL, SERVER_NAME, SERVER_VERSION


PLUGIN_ID_V2 = "codex-smart-subagents@codex-settings-adaptive"
MCP_SERVER_ID_V2 = "codex-smart-subagents"
REQUIRED_MCP_TOOLS_V2 = (
    "smart_plan",
    "route_start",
    "smart_wait",
    "smart_cancel",
)
USER_MCP_POLICY_PROOF_ENV_V2 = "CODEX_SMART_USER_MCP_POLICY_PROOF"
MCP_SESSION_NONCE_ENV_V2 = "CODEX_SMART_MCP_SESSION_NONCE"

_POLICY_DOMAIN = "codex-smart/user-mcp-policy-proof/v2"
_ATTESTATION_DOMAIN = "codex-smart/mcp-runtime-attestation/v2"
_ATTESTATION_PATH_DOMAIN = "codex-smart/mcp-runtime-attestation-path/v2"
_TOOL_DEFINITIONS_DOMAIN = "codex-smart/mcp-tool-definitions/v2"
_ATTESTATION_DIRECTORY = "mcp-runtime-attestations-v2"
_MAX_CONFIG_BYTES = 1_048_576
_MAX_PROOF_BYTES = 64 * 1024
_MAX_ATTESTATION_BYTES = 64 * 1024
_MAX_MCP_MANIFEST_BYTES = 64 * 1024
_SESSION_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_NONCE_PATTERN = re.compile(r"^mcpn2_[0-9a-f]{64}$")
_ACTIVATION_PATTERN = re.compile(r"^act2_[0-9a-f]{64}$")
_SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
_UNCONDITIONAL_APPROVAL_MODES = frozenset({"approve"})
_APP_TOOL_APPROVAL_MODES = frozenset({"approve", "auto", "prompt", "writes"})
_PLUGIN_CONFIG_FIELDS = frozenset({"enabled", "mcp_servers"})
_PLUGIN_MCP_SERVER_FIELDS = frozenset(
    {
        "enabled",
        "default_tools_approval_mode",
        "enabled_tools",
        "disabled_tools",
        "tools",
    }
)
_PLUGIN_TOOL_FIELDS = frozenset({"approval_mode"})
_BUNDLED_MCP_SERVER_FIELDS = frozenset(
    {
        "command",
        "args",
        "cwd",
        "env_vars",
        "startup_timeout_sec",
        "tool_timeout_sec",
        "required",
        "enabled",
        "enabled_tools",
        "disabled_tools",
        "default_tools_approval_mode",
        "tools",
    }
)
_BUNDLED_MCP_ENV_VARS = frozenset(
    {
        "CODEX_ADAPTIVE_SESSION_ID",
        "CODEX_ADAPTIVE_CATALOG",
        "CODEX_HOME",
        "CODEX_SMART_LAUNCHER_ACTIVE",
        "CODEX_SMART_STATE_HOME",
        "CODEX_SMART_GATEWAY_PATH",
        "CODEX_SMART_ACTIVATION_ID",
        "CODEX_SMART_GATE_FINGERPRINT",
        MCP_SESSION_NONCE_ENV_V2,
        USER_MCP_POLICY_PROOF_ENV_V2,
        "HOME",
        "TMPDIR",
    }
)
_POLICY_FIELDS = frozenset(
    {
        "schemaVersion",
        "proofKind",
        "configPath",
        "rawSha256",
        "fileIdentity",
        "policy",
        "proofFingerprint",
    }
)
_ATTESTATION_FIELDS = frozenset(
    {
        "schemaVersion",
        "attestationKind",
        "shellSessionId",
        "sessionNonce",
        "activationId",
        "gateFingerprint",
        "basePolicyProofFingerprint",
        "serverName",
        "serverVersion",
        "protocolVersion",
        "toolDefinitionsFingerprint",
        "pid",
        "processStartMarker",
        "tools",
        "attestationFingerprint",
    }
)


class MCPRuntimeProofV2Error(RuntimeError):
    """Закрытый отказ при недоказанной политике или личности MCP."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


def build_user_mcp_policy_proof_v2(codex_home: Path) -> str:
    """Читает неизменный base config и возвращает каноническое доказательство."""

    config_path = _config_path(codex_home)
    raw, identity = _read_stable_owned_file(
        config_path,
        maximum_bytes=_MAX_CONFIG_BYTES,
        required_mode=None,
        code="USER_MCP_POLICY_UNPROVED",
    )
    try:
        document = tomllib.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise MCPRuntimeProofV2Error(
            "USER_MCP_POLICY_UNPROVED",
            "config.toml нельзя разобрать",
        ) from exc
    policy = _project_user_mcp_policy(document)
    unsigned = {
        "schemaVersion": 2,
        "proofKind": "codex-user-mcp-policy-v2",
        "configPath": str(config_path),
        "rawSha256": hashlib.sha256(raw).hexdigest(),
        "fileIdentity": _identity_value(identity),
        "policy": policy,
    }
    value = {
        **unsigned,
        "proofFingerprint": domain_fingerprint(_POLICY_DOMAIN, unsigned),
    }
    return canonical_json_bytes(value).decode("utf-8")


def verify_user_mcp_policy_proof_v2(
    codex_home: Path,
    encoded_proof: str | None,
) -> Mapping[str, Any]:
    """Повторно читает config.toml и требует побайтово то же доказательство."""

    if (
        type(encoded_proof) is not str
        or not encoded_proof
        or len(encoded_proof.encode("utf-8")) > _MAX_PROOF_BYTES
    ):
        raise MCPRuntimeProofV2Error(
            "USER_MCP_POLICY_PROOF_MISSING",
            "доказательство пользовательской политики отсутствует",
        )
    try:
        expected = build_user_mcp_policy_proof_v2(codex_home)
    except MCPRuntimeProofV2Error as exc:
        raise MCPRuntimeProofV2Error(
            "USER_MCP_POLICY_PROOF_MISMATCH",
            "текущая пользовательская политика не доказана",
        ) from exc
    if not hmac.compare_digest(expected, encoded_proof):
        raise MCPRuntimeProofV2Error(
            "USER_MCP_POLICY_PROOF_MISMATCH",
            "config.toml изменился после запуска",
        )
    try:
        value = json.loads(expected)
    except json.JSONDecodeError as exc:  # pragma: no cover - канонический кодировщик
        raise MCPRuntimeProofV2Error(
            "USER_MCP_POLICY_PROOF_MISMATCH",
            "внутреннее доказательство повреждено",
        ) from exc
    if type(value) is not dict or frozenset(value) != _POLICY_FIELDS:
        raise MCPRuntimeProofV2Error(
            "USER_MCP_POLICY_PROOF_MISMATCH",
            "доказательство имеет неверную форму",
        )
    return value


def require_bundled_mcp_manifest_v2(plugin_root: Path) -> Mapping[str, Any]:
    """Доказывает закрытый bundled .mcp.json, от которого наследуется policy."""

    root = Path(plugin_root)
    if not root.is_absolute():
        _manifest_failure("корень расширения должен быть абсолютным")
    try:
        root = root.resolve(strict=True)
        root_info = os.lstat(root)
    except OSError as exc:
        raise MCPRuntimeProofV2Error(
            "MCP_MANIFEST_UNPROVED",
            "корень расширения недоступен",
        ) from exc
    if not stat.S_ISDIR(root_info.st_mode) or root_info.st_uid != os.getuid():
        _manifest_failure("корень расширения небезопасен")
    raw, _identity = _read_stable_owned_file(
        root / ".mcp.json",
        maximum_bytes=_MAX_MCP_MANIFEST_BYTES,
        required_mode=None,
        code="MCP_MANIFEST_UNPROVED",
    )
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCPRuntimeProofV2Error(
            "MCP_MANIFEST_UNPROVED",
            "bundled .mcp.json нельзя разобрать",
        ) from exc
    if type(value) is not dict or set(value) != {"mcpServers"}:
        _manifest_failure("корень bundled .mcp.json имеет неверную форму")
    servers = value["mcpServers"]
    if type(servers) is not dict or set(servers) != {MCP_SERVER_ID_V2}:
        _manifest_failure("bundled .mcp.json содержит неверный server id")
    server = servers[MCP_SERVER_ID_V2]
    if (
        type(server) is not dict
        or not set(server).issubset(_BUNDLED_MCP_SERVER_FIELDS)
        or not {
            "command",
            "args",
            "cwd",
            "env_vars",
            "startup_timeout_sec",
            "tool_timeout_sec",
            "required",
            "enabled_tools",
            "default_tools_approval_mode",
        }.issubset(server)
    ):
        _manifest_failure("bundled MCP содержит неизвестные или неполные поля")
    if (
        server["command"] != "./bin/codex-smart-subagents-mcp"
        or server["args"] != ["--stdio"]
        or server["cwd"] != "."
        or type(server["required"]) is not bool
        or server["required"] is not True
        or type(server["startup_timeout_sec"]) is not int
        or server["startup_timeout_sec"] <= 0
        or type(server["tool_timeout_sec"]) is not int
        or server["tool_timeout_sec"] < 420
    ):
        _manifest_failure("bundled MCP не соответствует обязательному запуску")
    if "enabled" in server and (
        type(server["enabled"]) is not bool or server["enabled"] is not True
    ):
        _manifest_failure("bundled MCP выключен")
    enabled_tools = server["enabled_tools"]
    if (
        type(enabled_tools) is not list
        or any(type(name) is not str for name in enabled_tools)
        or len(enabled_tools) != len(REQUIRED_MCP_TOOLS_V2)
        or set(enabled_tools) != set(REQUIRED_MCP_TOOLS_V2)
    ):
        _manifest_failure("bundled MCP имеет неверный enabled_tools")
    disabled_tools = server.get("disabled_tools", [])
    if type(disabled_tools) is not list or disabled_tools:
        _manifest_failure("bundled MCP имеет непустой disabled_tools")
    env_vars = server["env_vars"]
    if (
        type(env_vars) is not list
        or any(type(name) is not str for name in env_vars)
        or len(env_vars) != len(_BUNDLED_MCP_ENV_VARS)
        or set(env_vars) != _BUNDLED_MCP_ENV_VARS
    ):
        _manifest_failure("bundled MCP наследует неверное окружение")
    if server["default_tools_approval_mode"] != "approve":
        _manifest_failure("bundled MCP не имеет default approve")
    tools = server.get("tools", {})
    if type(tools) is not dict or not set(tools).issubset(REQUIRED_MCP_TOOLS_V2):
        _manifest_failure("bundled MCP имеет неверные tool overrides")
    for name, tool in tools.items():
        if (
            type(tool) is not dict
            or not set(tool).issubset(_PLUGIN_TOOL_FIELDS)
            or tool.get("approval_mode", "approve") != "approve"
        ):
            _manifest_failure(f"bundled MCP tool {name} не имеет effective approve")
    return value


def _manifest_failure(message: str) -> None:
    raise MCPRuntimeProofV2Error("MCP_MANIFEST_UNPROVED", message)


def mcp_runtime_attestation_path_v2(environ: Mapping[str, str]) -> Path:
    """Возвращает непрозрачный путь аттестации для точного сеанса и nonce."""

    binding = _attestation_environment(environ)
    filename = domain_fingerprint(
        _ATTESTATION_PATH_DOMAIN,
        {
            "shellSessionId": binding["shellSessionId"],
            "sessionNonce": binding["sessionNonce"],
            "activationId": binding["activationId"],
            "gateFingerprint": binding["gateFingerprint"],
        },
    )
    return binding["stateHome"] / _ATTESTATION_DIRECTORY / f"{filename}.json"


class MCPRuntimeAttestationPublisherV2:
    """Публикует аттестацию только после фактического ответа tools/list."""

    def __init__(
        self,
        *,
        environ: Mapping[str, str],
        process_start_marker_provider: Callable[[int], str],
    ) -> None:
        if not callable(process_start_marker_provider):
            raise TypeError("process_start_marker_provider must be callable")
        self._environment = dict(environ)
        self._binding = _attestation_environment(self._environment)
        self._path = mcp_runtime_attestation_path_v2(self._environment)
        self._process_start_marker_provider = process_start_marker_provider
        self._published_fingerprint: str | None = None

    @classmethod
    def from_environ(
        cls,
        environ: Mapping[str, str],
        *,
        process_start_marker_provider: Callable[
            [int], str
        ] = system_process_start_marker_v2,
    ) -> "MCPRuntimeAttestationPublisherV2":
        return cls(
            environ=environ,
            process_start_marker_provider=process_start_marker_provider,
        )

    @property
    def path(self) -> Path:
        return self._path

    def publish(
        self,
        tool_definitions: Sequence[Mapping[str, Any]],
        *,
        server_name: str,
        server_version: str,
        protocol_version: str,
    ) -> Path:
        expected_definitions = get_tool_definitions_v2()
        if (
            type(tool_definitions) not in {list, tuple}
            or list(tool_definitions) != expected_definitions
            or server_name != SERVER_NAME
            or server_version != SERVER_VERSION
            or protocol_version != MCP_PROTOCOL
        ):
            raise MCPRuntimeProofV2Error(
                "MCP_ATTESTATION_TOOL_SET_INVALID",
                "tools/list не выдал точный bundled-договор",
            )
        pid = os.getpid()
        try:
            marker = self._process_start_marker_provider(pid)
        except Exception as exc:
            raise MCPRuntimeProofV2Error(
                "MCP_ATTESTATION_PROCESS_UNPROVED",
                "личность процесса MCP недоступна",
            ) from exc
        if (
            type(marker) is not str
            or not marker
            or "\0" in marker
            or len(marker.encode("utf-8")) > 4096
        ):
            raise MCPRuntimeProofV2Error(
                "MCP_ATTESTATION_PROCESS_UNPROVED",
                "маркер старта процесса MCP неверен",
            )
        unsigned = {
            "schemaVersion": 2,
            "attestationKind": "bundled-mcp-tools-list-v2",
            "shellSessionId": self._binding["shellSessionId"],
            "sessionNonce": self._binding["sessionNonce"],
            "activationId": self._binding["activationId"],
            "gateFingerprint": self._binding["gateFingerprint"],
            "basePolicyProofFingerprint": self._binding[
                "basePolicyProofFingerprint"
            ],
            "serverName": server_name,
            "serverVersion": server_version,
            "protocolVersion": protocol_version,
            "toolDefinitionsFingerprint": domain_fingerprint(
                _TOOL_DEFINITIONS_DOMAIN,
                expected_definitions,
            ),
            "pid": pid,
            "processStartMarker": marker,
            "tools": list(REQUIRED_MCP_TOOLS_V2),
        }
        value = {
            **unsigned,
            "attestationFingerprint": domain_fingerprint(
                _ATTESTATION_DOMAIN,
                unsigned,
            ),
        }
        raw = canonical_json_bytes(value)
        directory = _ensure_attestation_directory(self._binding["stateHome"])
        with _attestation_lock(directory, self._path.name):
            _atomic_private_write(self._path, raw)
        self._published_fingerprint = value["attestationFingerprint"]
        return self._path

    def cleanup(self) -> None:
        """Снимает только собственную ещё не заменённую аттестацию."""

        fingerprint = self._published_fingerprint
        if fingerprint is None:
            return
        try:
            directory = _ensure_attestation_directory(self._binding["stateHome"])
            with _attestation_lock(directory, self._path.name):
                raw, identity = _read_stable_owned_file(
                    self._path,
                    maximum_bytes=_MAX_ATTESTATION_BYTES,
                    required_mode=0o600,
                    code="MCP_ATTESTATION_INVALID",
                )
                value = json.loads(raw.decode("utf-8", "strict"))
                if (
                    type(value) is not dict
                    or value.get("attestationFingerprint") != fingerprint
                ):
                    return
                named = os.lstat(self._path)
                if _file_identity(named) != identity:
                    return
                os.unlink(self._path)
                _fsync_directory(directory)
        except Exception:
            return
        finally:
            self._published_fingerprint = None


def verify_mcp_runtime_attestation_v2(
    environ: Mapping[str, str],
    *,
    process_start_marker_provider: Callable[
        [int], str
    ] = system_process_start_marker_v2,
) -> Mapping[str, Any]:
    """Проверяет приватную аттестацию и живую системную личность процесса."""

    if not callable(process_start_marker_provider):
        raise TypeError("process_start_marker_provider must be callable")
    binding = _attestation_environment(environ)
    path = mcp_runtime_attestation_path_v2(environ)
    raw, _identity = _read_stable_owned_file(
        path,
        maximum_bytes=_MAX_ATTESTATION_BYTES,
        required_mode=0o600,
        code="MCP_ATTESTATION_MISSING",
    )
    try:
        value = json.loads(raw.decode("utf-8", "strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MCPRuntimeProofV2Error(
            "MCP_ATTESTATION_INVALID",
            "аттестацию MCP нельзя разобрать",
        ) from exc
    _validate_attestation_value(value, binding)
    pid = value["pid"]
    try:
        observed_marker = process_start_marker_provider(pid)
    except Exception as exc:
        raise MCPRuntimeProofV2Error(
            "MCP_ATTESTATION_PROCESS_DEAD",
            "процесс аттестованного MCP не работает",
        ) from exc
    if observed_marker != value["processStartMarker"]:
        raise MCPRuntimeProofV2Error(
            "MCP_ATTESTATION_PROCESS_REUSED",
            "PID аттестованного MCP принадлежит другому процессу",
        )
    return value


def _project_user_mcp_policy(document: Any) -> dict[str, Any]:
    if type(document) is not dict:
        _policy_failure("корень config.toml имеет неверную форму")
    plugins = document.get("plugins")
    if type(plugins) is not dict:
        _policy_failure("таблица plugins отсутствует или повреждена")
    _validate_plugins_map(plugins)
    plugin = plugins.get(PLUGIN_ID_V2)
    if type(plugin) is not dict or plugin.get("enabled") is not True:
        _policy_failure("целевое расширение не включено")

    raw_mcp_servers = document.get("mcp_servers")
    if raw_mcp_servers is not None:
        if type(raw_mcp_servers) is not dict:
            _policy_failure("верхнеуровневый mcp_servers имеет неверную форму")
        if MCP_SERVER_ID_V2 in raw_mcp_servers:
            _policy_failure("верхнеуровневый MCP конфликтует с расширением")

    server_overlay: Any = None
    mcp_servers = plugin.get("mcp_servers")
    if mcp_servers is not None:
        if type(mcp_servers) is not dict:
            _policy_failure("mcp_servers имеет неверную форму")
        server_overlay = mcp_servers.get(MCP_SERVER_ID_V2)
    overlay_present = server_overlay is not None
    if overlay_present and type(server_overlay) is not dict:
        _policy_failure("overlay целевого MCP имеет неверную форму")

    server_enabled: bool | None = None
    enabled_tools: list[str] | None = None
    disabled_tools: list[str] | None = None
    default_approval: str | None = "approve"
    tool_approvals: dict[str, str | None] = {
        name: "approve" for name in REQUIRED_MCP_TOOLS_V2
    }
    if overlay_present:
        assert type(server_overlay) is dict
        if "enabled" in server_overlay:
            if type(server_overlay["enabled"]) is not bool:
                _policy_failure("enabled целевого MCP имеет неверный тип")
            server_enabled = server_overlay["enabled"]
            if not server_enabled:
                _policy_failure("целевой MCP явно выключен")

        if "enabled_tools" in server_overlay:
            enabled_tools = _string_list(
                server_overlay["enabled_tools"],
                "enabled_tools",
            )
            if (
                len(enabled_tools) != len(REQUIRED_MCP_TOOLS_V2)
                or set(enabled_tools) != set(REQUIRED_MCP_TOOLS_V2)
            ):
                _policy_failure("enabled_tools не равен обязательному набору")
            enabled_tools = list(REQUIRED_MCP_TOOLS_V2)

        if "disabled_tools" in server_overlay:
            disabled_tools = _string_list(
                server_overlay["disabled_tools"],
                "disabled_tools",
            )
            if disabled_tools:
                _policy_failure("disabled_tools должен быть пуст")

        if "default_tools_approval_mode" in server_overlay:
            default_approval = _approval_mode(
                server_overlay["default_tools_approval_mode"],
                "default_tools_approval_mode",
            )
        tool_approvals = {
            name: default_approval for name in REQUIRED_MCP_TOOLS_V2
        }

        tools = server_overlay.get("tools", {})
        if type(tools) is not dict:
            _policy_failure("tools имеет неверную форму")
        for name in REQUIRED_MCP_TOOLS_V2:
            tool = tools.get(name)
            if tool is None:
                continue
            if type(tool) is not dict:
                _policy_failure(f"tools.{name} имеет неверную форму")
            if "approval_mode" in tool:
                tool_approvals[name] = _approval_mode(
                    tool["approval_mode"],
                    f"tools.{name}.approval_mode",
                )

    return {
        "pluginId": PLUGIN_ID_V2,
        "pluginEnabled": True,
        "serverId": MCP_SERVER_ID_V2,
        "serverOverlayPresent": overlay_present,
        "serverEnabled": server_enabled,
        "enabledTools": enabled_tools,
        "disabledTools": disabled_tools,
        "defaultToolsApprovalMode": default_approval,
        "toolApprovalModes": tool_approvals,
        "requiredTools": list(REQUIRED_MCP_TOOLS_V2),
    }


def _approval_mode(value: Any, field: str) -> str:
    if type(value) is not str or value not in _UNCONDITIONAL_APPROVAL_MODES:
        _policy_failure(f"{field} не гарантирует безусловную доступность")
    return value


def _validate_plugins_map(plugins: Mapping[str, Any]) -> None:
    """Повторяет закрытую форму PluginConfig Codex для всей карты."""

    for plugin_id, plugin in plugins.items():
        if (
            type(plugin_id) is not str
            or type(plugin) is not dict
            or not set(plugin).issubset(_PLUGIN_CONFIG_FIELDS)
        ):
            _policy_failure("карта plugins содержит неверную запись")
        if "enabled" in plugin and type(plugin["enabled"]) is not bool:
            _policy_failure(f"plugins.{plugin_id}.enabled имеет неверный тип")
        servers = plugin.get("mcp_servers")
        if servers is None:
            continue
        if type(servers) is not dict:
            _policy_failure(f"plugins.{plugin_id}.mcp_servers повреждён")
        for server_id, overlay in servers.items():
            if (
                type(server_id) is not str
                or type(overlay) is not dict
                or not set(overlay).issubset(_PLUGIN_MCP_SERVER_FIELDS)
            ):
                _policy_failure("plugin MCP overlay содержит неизвестные поля")
            if "enabled" in overlay and type(overlay["enabled"]) is not bool:
                _policy_failure("plugin MCP enabled имеет неверный тип")
            if "default_tools_approval_mode" in overlay:
                mode = overlay["default_tools_approval_mode"]
                if type(mode) is not str or mode not in _APP_TOOL_APPROVAL_MODES:
                    _policy_failure("plugin MCP approval mode неизвестен")
            for field in ("enabled_tools", "disabled_tools"):
                if field in overlay:
                    _string_list(overlay[field], field)
            tools = overlay.get("tools")
            if tools is None:
                continue
            if type(tools) is not dict:
                _policy_failure("plugin MCP tools имеет неверную форму")
            for tool_name, tool in tools.items():
                if (
                    type(tool_name) is not str
                    or type(tool) is not dict
                    or not set(tool).issubset(_PLUGIN_TOOL_FIELDS)
                ):
                    _policy_failure("plugin tool содержит неизвестные поля")
                if "approval_mode" in tool:
                    mode = tool["approval_mode"]
                    if type(mode) is not str or mode not in _APP_TOOL_APPROVAL_MODES:
                        _policy_failure("plugin tool approval mode неизвестен")


def _string_list(value: Any, field: str) -> list[str]:
    if type(value) is not list or any(type(item) is not str for item in value):
        _policy_failure(f"{field} имеет неверный тип")
    return list(value)


def _policy_failure(message: str) -> None:
    raise MCPRuntimeProofV2Error("USER_MCP_POLICY_UNPROVED", message)


def _config_path(codex_home: Path) -> Path:
    path = Path(codex_home)
    if not path.is_absolute():
        raise MCPRuntimeProofV2Error(
            "USER_MCP_POLICY_UNPROVED",
            "CODEX_HOME должен быть абсолютным путём",
        )
    try:
        path = path.resolve(strict=True)
        info = os.lstat(path)
    except OSError as exc:
        raise MCPRuntimeProofV2Error(
            "USER_MCP_POLICY_UNPROVED",
            "CODEX_HOME недоступен",
        ) from exc
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid():
        raise MCPRuntimeProofV2Error(
            "USER_MCP_POLICY_UNPROVED",
            "CODEX_HOME не является каталогом текущего пользователя",
        )
    return path / "config.toml"


def _attestation_environment(environ: Mapping[str, str]) -> dict[str, Any]:
    shell_session_id = environ.get("CODEX_ADAPTIVE_SESSION_ID", "")
    nonce = environ.get(MCP_SESSION_NONCE_ENV_V2, "")
    activation_id = environ.get("CODEX_SMART_ACTIVATION_ID", "")
    gate_fingerprint = environ.get("CODEX_SMART_GATE_FINGERPRINT", "")
    if _SESSION_PATTERN.fullmatch(shell_session_id) is None:
        _attestation_failure("shellSessionId неверен")
    if _NONCE_PATTERN.fullmatch(nonce) is None:
        _attestation_failure("session nonce неверен")
    if _ACTIVATION_PATTERN.fullmatch(activation_id) is None:
        _attestation_failure("activationId неверен")
    if _SHA256_PATTERN.fullmatch(gate_fingerprint) is None:
        _attestation_failure("gateFingerprint неверен")
    codex_home = Path(environ.get("CODEX_HOME", ""))
    policy_proof = verify_user_mcp_policy_proof_v2(
        codex_home,
        environ.get(USER_MCP_POLICY_PROOF_ENV_V2),
    )
    state_home = Path(environ.get("CODEX_SMART_STATE_HOME", ""))
    if not state_home.is_absolute():
        _attestation_failure("state_home должен быть абсолютным")
    try:
        info = os.lstat(state_home)
    except OSError as exc:
        raise MCPRuntimeProofV2Error(
            "MCP_ATTESTATION_INVALID",
            "state_home недоступен",
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _attestation_failure("state_home небезопасен")
    return {
        "shellSessionId": shell_session_id,
        "sessionNonce": nonce,
        "activationId": activation_id,
        "gateFingerprint": gate_fingerprint,
        "basePolicyProofFingerprint": policy_proof["proofFingerprint"],
        "stateHome": state_home,
    }


def _attestation_failure(message: str) -> None:
    raise MCPRuntimeProofV2Error("MCP_ATTESTATION_INVALID", message)


def _validate_attestation_value(
    value: Any,
    binding: Mapping[str, Any],
) -> None:
    if type(value) is not dict or frozenset(value) != _ATTESTATION_FIELDS:
        _attestation_failure("аттестация имеет неверную форму")
    unsigned = {
        name: value[name]
        for name in value
        if name != "attestationFingerprint"
    }
    if (
        value.get("schemaVersion") != 2
        or value.get("attestationKind") != "bundled-mcp-tools-list-v2"
        or value.get("shellSessionId") != binding["shellSessionId"]
        or value.get("sessionNonce") != binding["sessionNonce"]
        or value.get("activationId") != binding["activationId"]
        or value.get("gateFingerprint") != binding["gateFingerprint"]
        or value.get("basePolicyProofFingerprint")
        != binding["basePolicyProofFingerprint"]
        or value.get("serverName") != SERVER_NAME
        or value.get("serverVersion") != SERVER_VERSION
        or value.get("protocolVersion") != MCP_PROTOCOL
        or value.get("toolDefinitionsFingerprint")
        != domain_fingerprint(
            _TOOL_DEFINITIONS_DOMAIN,
            get_tool_definitions_v2(),
        )
        or type(value.get("pid")) is not int
        or value["pid"] <= 0
        or type(value.get("processStartMarker")) is not str
        or not value["processStartMarker"]
        or value.get("tools") != list(REQUIRED_MCP_TOOLS_V2)
        or value.get("attestationFingerprint")
        != domain_fingerprint(_ATTESTATION_DOMAIN, unsigned)
    ):
        _attestation_failure("аттестация не соответствует текущему сеансу MCP")


def _ensure_attestation_directory(state_home: Path) -> Path:
    directory = state_home / _ATTESTATION_DIRECTORY
    try:
        directory.mkdir(mode=0o700, exist_ok=True)
        info = os.lstat(directory)
    except OSError as exc:
        raise MCPRuntimeProofV2Error(
            "MCP_ATTESTATION_INVALID",
            "каталог аттестаций недоступен",
        ) from exc
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        _attestation_failure("каталог аттестаций небезопасен")
    return directory


@contextmanager
def _attestation_lock(directory: Path, target_name: str) -> Iterator[None]:
    lock_path = directory / f".{target_name}.lock"
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as exc:
        raise MCPRuntimeProofV2Error(
            "MCP_ATTESTATION_INVALID",
            "блокировка аттестации недоступна",
        ) from exc
    acquired = False
    try:
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != 0o600
        ):
            _attestation_failure("блокировка аттестации небезопасна")
        try:
            finite_file_lock_v2.acquire_flock_v2(
                descriptor,
                exclusive=True,
                timeout_seconds=(
                    finite_file_lock_v2.LOCAL_FILE_LOCK_TIMEOUT_SECONDS
                ),
                timeout_code="MCP_ATTESTATION_LOCK_TIMEOUT",
            )
        except finite_file_lock_v2.FileLockTimeoutV2 as error:
            raise MCPRuntimeProofV2Error(
                error.code,
                "блокировка аттестации занята до истечения срока",
            ) from error
        acquired = True
        yield
    finally:
        if acquired:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _atomic_private_write(path: Path, raw: bytes) -> None:
    temporary = path.parent / f".{path.name}.{os.getpid()}.{secrets.token_hex(8)}.tmp"
    descriptor = os.open(
        temporary,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    try:
        os.fchmod(descriptor, 0o600)
        offset = 0
        while offset < len(raw):
            offset += os.write(descriptor, raw[offset:])
        os.fsync(descriptor)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise
    finally:
        os.close(descriptor)
    try:
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        try:
            os.unlink(temporary)
        except OSError:
            pass
        raise


def _read_stable_owned_file(
    path: Path,
    *,
    maximum_bytes: int,
    required_mode: int | None,
    code: str,
) -> tuple[bytes, tuple[int, int, int, int]]:
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise MCPRuntimeProofV2Error(code, "требуемый файл недоступен") from exc
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != os.getuid()
        or before.st_nlink != 1
        or before.st_size > maximum_bytes
        or (required_mode is not None and stat.S_IMODE(before.st_mode) != required_mode)
        or (required_mode is None and stat.S_IMODE(before.st_mode) & 0o022)
    ):
        raise MCPRuntimeProofV2Error(code, "требуемый файл небезопасен")
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    try:
        opened = os.fstat(descriptor)
        identity = _file_identity(before)
        if _file_identity(opened) != identity:
            raise MCPRuntimeProofV2Error(code, "файл изменился перед чтением")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(65_536, maximum_bytes + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > maximum_bytes:
                raise MCPRuntimeProofV2Error(code, "файл превышает предел")
        after = os.fstat(descriptor)
        if _file_identity(after) != identity:
            raise MCPRuntimeProofV2Error(code, "файл изменился при чтении")
    finally:
        os.close(descriptor)
    try:
        named = os.lstat(path)
    except OSError as exc:
        raise MCPRuntimeProofV2Error(code, "файл исчез после чтения") from exc
    if _file_identity(named) != identity:
        raise MCPRuntimeProofV2Error(code, "путь файла изменился при чтении")
    return b"".join(chunks), identity


def _file_identity(info: os.stat_result) -> tuple[int, int, int, int]:
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _identity_value(identity: tuple[int, int, int, int]) -> dict[str, str]:
    device, inode, size, mtime_ns = identity
    return {
        "device": str(device),
        "inode": str(inode),
        "size": str(size),
        "mtimeNs": str(mtime_ns),
    }


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


__all__ = [
    "MCPRuntimeAttestationPublisherV2",
    "MCPRuntimeProofV2Error",
    "MCP_SESSION_NONCE_ENV_V2",
    "REQUIRED_MCP_TOOLS_V2",
    "USER_MCP_POLICY_PROOF_ENV_V2",
    "build_user_mcp_policy_proof_v2",
    "mcp_runtime_attestation_path_v2",
    "require_bundled_mcp_manifest_v2",
    "verify_mcp_runtime_attestation_v2",
    "verify_user_mcp_policy_proof_v2",
]
