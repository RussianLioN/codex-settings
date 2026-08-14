"""Строгая нормализация управляемых требований Codex версии 1."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from .canonical_json import MAX_SAFE_INTEGER, CanonicalJsonError, canonical_json_bytes


MAX_DOCUMENT_BYTES = 1_048_576
MAX_TREE_NODES = 4_096
MAX_TREE_DEPTH = 16
MAX_COLLECTION_ITEMS = 2_048

_CONFIG_FIELDS = {
    "allowAppshots",
    "allowManagedHooksOnly",
    "allowRemoteControl",
    "allowedApprovalPolicies",
    "allowedApprovalsReviewers",
    "allowedPermissionProfiles",
    "allowedSandboxModes",
    "allowedWebSearchModes",
    "allowedWindowsSandboxImplementations",
    "computerUse",
    "defaultPermissions",
    "enforceResidency",
    "featureRequirements",
    "hooks",
    "models",
    "network",
}
_SET_FIELDS = {
    "allowedApprovalPolicies",
    "allowedApprovalsReviewers",
    "allowedSandboxModes",
    "allowedWebSearchModes",
    "allowedWindowsSandboxImplementations",
}
_ENUM_FIELDS = {
    "allowedApprovalsReviewers": {"user", "auto_review", "guardian_subagent"},
    "allowedSandboxModes": {"read-only", "workspace-write", "danger-full-access"},
    "allowedWebSearchModes": {"disabled", "cached", "indexed", "live"},
    "allowedWindowsSandboxImplementations": {"elevated", "unelevated"},
}
_NETWORK_SET_FIELDS = {"allowUnixSockets", "allowedDomains", "deniedDomains"}
_TOP_BOOLEAN_FIELDS = {"allowAppshots", "allowManagedHooksOnly", "allowRemoteControl"}
_COMPUTER_USE_FIELDS = {"allowLockedComputerUse"}
_MODELS_FIELDS = {"newThread"}
_NEW_THREAD_FIELDS = {"model", "modelReasoningEffort", "serviceTier"}
_NETWORK_FIELDS = {
    "allowLocalBinding",
    "allowUnixSockets",
    "allowUpstreamProxy",
    "allowedDomains",
    "dangerouslyAllowAllUnixSockets",
    "dangerouslyAllowNonLoopbackProxy",
    "deniedDomains",
    "domains",
    "enabled",
    "httpPort",
    "managedAllowedDomainsOnly",
    "socksPort",
    "unixSockets",
}
_NETWORK_BOOLEAN_FIELDS = {
    "allowLocalBinding",
    "allowUpstreamProxy",
    "dangerouslyAllowAllUnixSockets",
    "dangerouslyAllowNonLoopbackProxy",
    "enabled",
    "managedAllowedDomainsOnly",
}
_HOOK_EVENTS = {
    "PermissionRequest",
    "PostCompact",
    "PostToolUse",
    "PreCompact",
    "PreToolUse",
    "SessionStart",
    "Stop",
    "SubagentStart",
    "SubagentStop",
    "UserPromptSubmit",
}
_HOOK_FIELDS = _HOOK_EVENTS | {"managedDir", "windowsManagedDir"}
_HOOK_GROUP_FIELDS = {"hooks", "matcher"}
_COMMAND_HANDLER_FIELDS = {
    "type",
    "async",
    "command",
    "commandWindows",
    "statusMessage",
    "timeoutSec",
}
_GRANULAR_KEYS = {
    "mcp_elicitations",
    "rules",
    "sandbox_approval",
    "request_permissions",
    "skill_approval",
}
_GRANULAR_REQUIRED_KEYS = {"mcp_elicitations", "rules", "sandbox_approval"}
_GRANULAR_DEFAULT_KEYS = {"request_permissions", "skill_approval"}


@dataclass
class ManagedRequirementsError(ValueError):
    code: str
    phase: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def normalize_managed_requirements(requirements: Any) -> Any:
    """Проверяет и нормализует дерево для защищённого отпечатка."""

    _guard_tree(requirements)
    _validate_source_structure(requirements)
    if requirements is None:
        return None
    network_source = requirements.get("network")
    if type(network_source) is dict and type(network_source.get("domains")) is dict:
        domains = network_source["domains"]
        canonical_allowed = {
            name for name, decision in domains.items() if decision == "allow"
        }
        canonical_denied = {
            name for name, decision in domains.items() if decision == "deny"
        }
        for legacy_field, canonical in (
            ("allowedDomains", canonical_allowed),
            ("deniedDomains", canonical_denied),
        ):
            legacy = network_source.get(legacy_field)
            if legacy is not None and set(legacy) != canonical:
                _fail(
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "normalization",
                    f"network {legacy_field} disagrees with domains",
                )
    if type(network_source) is dict and type(network_source.get("unixSockets")) is dict:
        canonical_sockets = {
            name
            for name, decision in network_source["unixSockets"].items()
            if decision == "allow"
        }
        legacy_sockets = network_source.get("allowUnixSockets")
        if legacy_sockets is not None and set(legacy_sockets) != canonical_sockets:
            _fail(
                "MANAGED_REQUIREMENT_MALFORMED",
                "normalization",
                "network allowUnixSockets disagrees with unixSockets",
            )
    normalized = _remove_optional_nulls(requirements)
    for policy in normalized.get("allowedApprovalPolicies", []):
        if type(policy) is dict:
            granular = policy["granular"]
            for key in sorted(_GRANULAR_DEFAULT_KEYS):
                granular.setdefault(key, False)
    for field in _SET_FIELDS:
        if field in normalized:
            normalized[field] = _normalize_set(normalized[field])
    network = normalized.get("network")
    if type(network) is dict:
        for field in _NETWORK_SET_FIELDS:
            if field in network:
                network[field] = _normalize_set(network[field])
    _guard_tree(normalized)
    return normalized


def verify_managed_requirements_compatibility(
    normalized: Any,
    *,
    profile: dict[str, Any],
    selected_pair: dict[str, str],
    known_features: set[str],
) -> None:
    """Доказывает совместимость нормализованных требований с дочерним профилем."""

    if normalized is None:
        return
    if type(normalized) is not dict:
        raise TypeError("normalized requirements must be an object or null")
    if (
        type(profile) is not dict
        or type(profile.get("sandboxMode")) is not str
        or type(profile.get("permissionProfileId")) is not str
        or type(profile.get("disabledFeatures")) is not list
        or any(type(item) is not str for item in profile["disabledFeatures"])
        or type(selected_pair) is not dict
        or set(selected_pair) != {"model", "reasoningEffort"}
        or any(type(item) is not str or not item for item in selected_pair.values())
        or type(known_features) is not set
        or any(type(item) is not str for item in known_features)
    ):
        raise TypeError("child profile compatibility context is malformed")

    features = normalized.get("featureRequirements", {})
    if any(feature not in known_features for feature in features):
        _fail(
            "MANAGED_REQUIREMENT_UNSUPPORTED",
            "compatibility",
            "managed requirements name an unknown feature",
        )

    incompatible = False
    approvals = normalized.get("allowedApprovalPolicies")
    if approvals is not None and "never" not in approvals:
        incompatible = True
    sandbox_modes = normalized.get("allowedSandboxModes")
    if sandbox_modes is not None and profile["sandboxMode"] not in sandbox_modes:
        incompatible = True
    search_modes = normalized.get("allowedWebSearchModes")
    if search_modes is not None and "disabled" not in search_modes:
        incompatible = True
    permission_profiles = normalized.get("allowedPermissionProfiles")
    if (
        permission_profiles is not None
        and permission_profiles.get(profile["permissionProfileId"]) is not True
    ):
        incompatible = True
    default_permissions = normalized.get("defaultPermissions")
    if (
        default_permissions is not None
        and default_permissions != profile["permissionProfileId"]
    ):
        incompatible = True
    if "enforceResidency" in normalized:
        incompatible = True

    new_thread = normalized.get("models", {}).get("newThread", {})
    if "model" in new_thread and new_thread["model"] != selected_pair["model"]:
        incompatible = True
    if (
        "modelReasoningEffort" in new_thread
        and new_thread["modelReasoningEffort"]
        != selected_pair["reasoningEffort"]
    ):
        incompatible = True
    if new_thread.get("serviceTier"):
        incompatible = True

    hooks = normalized.get("hooks")
    if hooks is not None:
        for name, value in hooks.items():
            if name in {"managedDir", "windowsManagedDir"}:
                if value:
                    incompatible = True
            elif value:
                incompatible = True

    disabled = set(profile["disabledFeatures"])
    if any(
        expected is not (feature not in disabled)
        for feature, expected in features.items()
    ):
        incompatible = True

    network = normalized.get("network", {})
    if any(
        network.get(field) is True
        for field in (
            "enabled",
            "allowLocalBinding",
            "allowUpstreamProxy",
            "dangerouslyAllowAllUnixSockets",
            "dangerouslyAllowNonLoopbackProxy",
        )
    ):
        incompatible = True
    if any(network.get(field, 0) != 0 for field in ("httpPort", "socksPort")):
        incompatible = True
    if incompatible:
        _fail(
            "MANAGED_REQUIREMENT_INCOMPATIBLE",
            "compatibility",
            "managed requirements conflict with the exact child profile",
        )


def _guard_tree(value: Any) -> None:
    nodes = 0
    active: set[int] = set()
    stack: list[tuple[Any, int, bool]] = [(value, 1, False)]
    try:
        while stack:
            current, depth, exiting = stack.pop()
            if exiting:
                active.remove(id(current))
                continue
            nodes += 1
            if nodes > MAX_TREE_NODES or depth > MAX_TREE_DEPTH:
                _fail(
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "limits",
                    "requirements exceed structural limits",
                )
            if current is None or type(current) in {bool, str}:
                if type(current) is str:
                    current.encode("utf-8")
                continue
            if type(current) is int:
                if not -MAX_SAFE_INTEGER <= current <= MAX_SAFE_INTEGER:
                    _fail(
                        "MANAGED_REQUIREMENT_MALFORMED",
                        "limits",
                        "integer is outside canonical-json-v1",
                    )
                continue
            if type(current) not in {dict, list}:
                _fail(
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "limits",
                    "requirements contain a non-JSON value",
                )
            marker = id(current)
            if marker in active:
                _fail(
                    "MANAGED_REQUIREMENT_MALFORMED",
                    "limits",
                    "requirements contain a cycle",
                )
            active.add(marker)
            stack.append((current, depth, True))
            if type(current) is dict:
                for key in current:
                    if type(key) is not str:
                        _fail(
                            "MANAGED_REQUIREMENT_MALFORMED",
                            "limits",
                            "object key is not a string",
                        )
                    key.encode("utf-8")
                stack.extend(
                    (item, depth + 1, False) for item in current.values()
                )
            else:
                stack.extend((item, depth + 1, False) for item in current)
        if len(canonical_json_bytes(value)) > MAX_DOCUMENT_BYTES:
            _fail(
                "MANAGED_REQUIREMENT_MALFORMED",
                "limits",
                "requirements exceed the byte limit",
            )
    except (CanonicalJsonError, UnicodeEncodeError, RecursionError) as exc:
        raise ManagedRequirementsError(
            "MANAGED_REQUIREMENT_MALFORMED",
            "limits",
            "requirements are outside canonical-json-v1",
        ) from exc


def _validate_source_structure(requirements: Any) -> None:
    if requirements is None:
        return
    if type(requirements) is not dict:
        _fail(
            "MANAGED_REQUIREMENT_MALFORMED",
            "structure",
            "requirements must be an object or null",
        )
    _reject_unknown_members(requirements, _CONFIG_FIELDS, "requirements")
    for field in _TOP_BOOLEAN_FIELDS:
        value = requirements.get(field)
        if value is not None and type(value) is not bool:
            _malformed(field)
    for field, allowed in _ENUM_FIELDS.items():
        value = requirements.get(field)
        if value is None:
            continue
        if type(value) is not list or any(
            type(item) is not str or item not in allowed for item in value
        ):
            _malformed(field)
    _validate_approval_policies(requirements.get("allowedApprovalPolicies"))
    for field in ("allowedPermissionProfiles", "featureRequirements"):
        value = requirements.get(field)
        if value is not None:
            _validate_named_boolean_map(value, field)
    computer_use = requirements.get("computerUse")
    if computer_use is not None:
        if type(computer_use) is not dict:
            _malformed("computerUse")
        _reject_unknown_members(computer_use, _COMPUTER_USE_FIELDS, "computerUse")
        locked = computer_use.get("allowLockedComputerUse")
        if locked is not None and type(locked) is not bool:
            _malformed("allowLockedComputerUse")
    default_permissions = requirements.get("defaultPermissions")
    if default_permissions is not None:
        if type(default_permissions) is not str:
            _malformed("defaultPermissions")
        _utf8_size(default_permissions, "defaultPermissions")
    residency = requirements.get("enforceResidency")
    if residency is not None and residency != "us":
        _malformed("enforceResidency")
    hooks = requirements.get("hooks")
    if hooks is not None:
        _validate_hooks(hooks)
    models = requirements.get("models")
    if models is not None:
        _validate_models(models)
    network = requirements.get("network")
    if network is not None:
        _validate_network(network)


def _validate_approval_policies(value: Any) -> None:
    if value is None:
        return
    if type(value) is not list:
        _malformed("allowedApprovalPolicies")
    for policy in value:
        if type(policy) is str:
            if policy not in {"untrusted", "on-request", "never"}:
                _malformed("allowedApprovalPolicies")
            continue
        if (
            type(policy) is not dict
            or set(policy) != {"granular"}
            or type(policy["granular"]) is not dict
        ):
            _malformed("allowedApprovalPolicies")
        granular = policy["granular"]
        _reject_unknown_members(granular, _GRANULAR_KEYS, "granular approval")
        if not _GRANULAR_REQUIRED_KEYS <= set(granular):
            _malformed("granular approval")
        if any(type(granular[key]) is not bool for key in _GRANULAR_REQUIRED_KEYS):
            _malformed("granular approval")
        if any(
            key in granular
            and granular[key] is not None
            and type(granular[key]) is not bool
            for key in _GRANULAR_DEFAULT_KEYS
        ):
            _malformed("granular approval")


def _validate_named_boolean_map(value: Any, field: str) -> None:
    if type(value) is not dict or len(value) > MAX_COLLECTION_ITEMS:
        _malformed(field)
    for key, item in value.items():
        if type(key) is not str or type(item) is not bool:
            _malformed(field)
        _utf8_size(key, f"{field} property name")


def _validate_hooks(value: Any) -> None:
    if type(value) is not dict:
        _malformed("hooks")
    _reject_unknown_members(value, _HOOK_FIELDS, "hooks")
    if not _HOOK_EVENTS <= set(value):
        _malformed("hooks")
    for field in ("managedDir", "windowsManagedDir"):
        if field in value and value[field] is not None:
            if type(value[field]) is not str:
                _malformed(field)
            _utf8_size(value[field], field)
    for event in _HOOK_EVENTS:
        groups = value[event]
        if type(groups) is not list or len(groups) > 256:
            _malformed(f"{event} groups")
        for group in groups:
            if type(group) is not dict:
                _malformed("hook group")
            _reject_unknown_members(group, _HOOK_GROUP_FIELDS, "hook group")
            if (
                "hooks" not in group
                or type(group["hooks"]) is not list
                or len(group["hooks"]) > 256
            ):
                _malformed("hook group")
            if "matcher" in group and group["matcher"] is not None:
                if type(group["matcher"]) is not str:
                    _malformed("hook matcher")
                _utf8_size(group["matcher"], "hook matcher")
            for handler in group["hooks"]:
                _validate_hook_handler(handler)


def _validate_hook_handler(value: Any) -> None:
    if type(value) is not dict or "type" not in value or type(value["type"]) is not str:
        _malformed("hook handler")
    handler_type = value["type"]
    if handler_type == "command":
        _reject_unknown_members(value, _COMMAND_HANDLER_FIELDS, "hook handler")
        if not {"type", "async", "command"} <= set(value):
            _malformed("command hook")
        if type(value["async"]) is not bool or type(value["command"]) is not str:
            _malformed("command hook")
        _utf8_size(value["command"], "hook command", 65_536)
        for field in ("commandWindows", "statusMessage"):
            if field in value and value[field] is not None:
                if type(value[field]) is not str:
                    _malformed(field)
                _utf8_size(value[field], field)
        timeout = value.get("timeoutSec")
        if timeout is not None and (
            type(timeout) is not int or not 0 <= timeout <= MAX_SAFE_INTEGER
        ):
            _malformed("timeoutSec")
        return
    if handler_type in {"prompt", "agent"}:
        _reject_unknown_members(value, {"type"}, "hook handler")
        return
    _malformed("hook handler type")


def _validate_models(value: Any) -> None:
    if type(value) is not dict:
        _malformed("models")
    _reject_unknown_members(value, _MODELS_FIELDS, "models")
    new_thread = value.get("newThread")
    if new_thread is None:
        return
    if type(new_thread) is not dict:
        _malformed("newThread")
    _reject_unknown_members(new_thread, _NEW_THREAD_FIELDS, "newThread")
    for field, item in new_thread.items():
        if item is not None:
            if type(item) is not str:
                _malformed(field)
            _utf8_size(item, field)


def _validate_network(value: Any) -> None:
    if type(value) is not dict:
        _malformed("network")
    _reject_unknown_members(value, _NETWORK_FIELDS, "network")
    for field in _NETWORK_BOOLEAN_FIELDS:
        if field in value and value[field] is not None and type(value[field]) is not bool:
            _malformed(field)
    for field in ("httpPort", "socksPort"):
        if field in value and value[field] is not None:
            port = value[field]
            if type(port) is not int or not 0 <= port <= 65_535:
                _malformed(field)
    for field in _NETWORK_SET_FIELDS:
        if field in value and value[field] is not None:
            _validate_string_set(value[field], field)
    for field in ("domains", "unixSockets"):
        if field in value and value[field] is not None:
            _validate_domain_map(value[field], field)


def _validate_string_set(value: Any, field: str) -> None:
    if type(value) is not list or len(value) > MAX_COLLECTION_ITEMS:
        _malformed(field)
    for item in value:
        if type(item) is not str:
            _malformed(field)
        _utf8_size(item, field)


def _validate_domain_map(value: Any, field: str) -> None:
    if type(value) is not dict or len(value) > MAX_COLLECTION_ITEMS:
        _malformed(field)
    for key, item in value.items():
        if type(key) is not str or item not in {"allow", "deny"}:
            _malformed(field)
        _utf8_size(key, field)


def _remove_optional_nulls(value: Any) -> Any:
    if type(value) is dict:
        return {
            key: _remove_optional_nulls(item)
            for key, item in value.items()
            if item is not None
        }
    if type(value) is list:
        return [_remove_optional_nulls(item) for item in value]
    return copy.deepcopy(value)


def _normalize_set(values: list[Any]) -> list[Any]:
    by_canonical = {canonical_json_bytes(value): value for value in values}
    return [copy.deepcopy(by_canonical[key]) for key in sorted(by_canonical)]


def _reject_unknown_members(value: dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = set(value) - allowed
    if unknown:
        _fail(
            "MANAGED_REQUIREMENT_UNSUPPORTED",
            "structure",
            f"unknown {field} fields: {sorted(unknown)}",
        )


def _utf8_size(value: str, field: str, maximum: int = 4_096) -> None:
    try:
        size = len(value.encode("utf-8"))
    except UnicodeEncodeError as exc:
        raise ManagedRequirementsError(
            "MANAGED_REQUIREMENT_MALFORMED",
            "structure",
            f"invalid {field}",
        ) from exc
    if not value or size > maximum:
        _malformed(field)


def _malformed(field: str) -> None:
    _fail(
        "MANAGED_REQUIREMENT_MALFORMED",
        "structure",
        f"invalid {field}",
    )


def _fail(code: str, phase: str, message: str) -> None:
    raise ManagedRequirementsError(code, phase, message)
