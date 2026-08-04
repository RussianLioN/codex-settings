"""Замкнутый загрузчик политики адаптивной маршрутизации версии 2.

Имена моделей и уровни рассуждения поступают только из проверяемых файлов
данных. Этот модуль связывает каталог оператора с отпечатанными договорами и
отклоняет любое расхождение до построения маршрутизатора.
"""

from __future__ import annotations

import copy
import hashlib
import json
import tomllib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Mapping

from .canonical_json import canonical_json_v1, domain_fingerprint
from .catalog import Catalog, CatalogError
from .semantic_routing_v2 import (
    ContractError,
    SEMANTIC_VERSION,
    SemanticRouterV2,
    verify_policy_snapshot,
)


class PolicyBundleError(ValueError):
    """Ошибка замыкания или согласования политики."""


def _fail(code: str, detail: str = "") -> None:
    suffix = f": {detail}" if detail else ""
    raise PolicyBundleError(code + suffix)


def _exact_keys(value: Any, expected: set[str], code: str) -> None:
    if type(value) is not dict or set(value) != expected:
        _fail(code)


def _read_json(path: Path, code: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(code, str(exc))
    if type(value) is not dict:
        _fail(code)
    return value


def _read_catalog(
    path: Path,
) -> tuple[dict[str, Any], dict[str, Any], Catalog]:
    try:
        catalog = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, tomllib.TOMLDecodeError) as exc:
        _fail("CATALOG_INVALID", str(exc))
    if type(catalog) is not dict:
        _fail("CATALOG_INVALID")
    if catalog.get("schema_version") not in {1, 2}:
        _fail("CATALOG_VERSION_UNSUPPORTED")

    models = catalog.get("models")
    if type(models) is not dict or not models:
        _fail("CATALOG_MODELS_INVALID")
    ranks: set[int] = set()
    normalized_models: dict[str, dict[str, Any]] = {}
    for name, raw in models.items():
        if type(name) is not str or not name:
            _fail("CATALOG_MODEL_NAME_INVALID")
        _exact_keys(raw, {"rank", "reasoning_efforts"}, "CATALOG_MODEL_INVALID")
        rank = raw["rank"]
        efforts = raw["reasoning_efforts"]
        if type(rank) is not int or rank < 0:
            _fail("CATALOG_MODEL_RANK_INVALID")
        if rank in ranks:
            _fail("CATALOG_MODEL_RANK_DUPLICATE")
        ranks.add(rank)
        if (
            type(efforts) is not list
            or not efforts
            or len(efforts) != len(set(efforts))
            or any(type(effort) is not str or not effort for effort in efforts)
        ):
            _fail("CATALOG_MODEL_EFFORTS_INVALID")
        normalized_models[name] = {
            "rank": rank,
            "reasoningEfforts": tuple(efforts),
        }
    if ranks != set(range(len(models))):
        _fail("CATALOG_MODEL_RANKS_NOT_CONTIGUOUS")

    try:
        verified_catalog = Catalog.load(path)
    except CatalogError as exc:
        _fail("CATALOG_INVALID", str(exc))
    coordinator_contract = {
        "selection": verified_catalog.coordinator_selection,
        "candidates": [
            {
                "model": candidate["model"],
                "reasoningEffort": candidate["reasoning_effort"],
            }
            for candidate in verified_catalog.coordinator_candidates
        ],
    }
    normalized = json.dumps(
        catalog,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if (
        hashlib.sha256(normalized.encode("utf-8")).hexdigest()
        != verified_catalog.canonical_sha256
    ):
        _fail("CATALOG_CHANGED_DURING_LOAD")
    return (
        catalog,
        coordinator_contract,
        verified_catalog,
    )


@dataclass(frozen=True)
class PolicyBundleV2:
    schema_version: int
    algorithm_version: str
    minimum_codex_version: str
    supported_platforms: tuple[str, ...]
    coordinator: Mapping[str, str]
    coordinator_selection: str
    coordinator_candidates: tuple[Mapping[str, str], ...]
    catalog_models: Mapping[str, Mapping[str, Any]]
    catalog_limits: Mapping[str, int]
    validation_commands: Mapping[str, tuple[tuple[str, ...], ...]]
    routing_policy_snapshot: Mapping[str, Any]
    delegation_policy: Mapping[str, Any]
    role_templates: tuple[Mapping[str, Any], ...]
    child_profiles: tuple[Mapping[str, Any], ...]
    child_profile_fingerprints: Mapping[str, str]
    child_profile_domain: str
    child_argv_domain: str
    child_environment_domain: str
    child_secret_domain: str
    result_schema_resolution: Mapping[str, str]
    known_child_features: frozenset[str]
    policy_pairs: tuple[Mapping[str, str], ...]
    bundle_fingerprint: str
    router: SemanticRouterV2


def load_policy_bundle_v2(
    *,
    catalog_path: Path,
    routing_vector_path: Path,
    delegation_vector_path: Path,
    role_vector_path: Path,
    child_profile_vector_path: Path,
) -> PolicyBundleV2:
    """Загружает, замыкает и отпечатывает все данные маршрутизации."""

    catalog, coordinator_contract, verified_catalog = _read_catalog(catalog_path)
    coordinator_candidates = tuple(
        copy.deepcopy(coordinator_contract["candidates"])
    )
    coordinator = copy.deepcopy(coordinator_candidates[0])
    normalized_models: dict[str, dict[str, Any]] = {
        name: {
            "rank": raw["rank"],
            "reasoningEfforts": tuple(raw["reasoning_efforts"]),
        }
        for name, raw in catalog["models"].items()
    }

    routing_vector = _read_json(
        routing_vector_path,
        "ROUTING_POLICY_VECTOR_INVALID",
    )
    required_routing_keys = {
        "schemaVersion",
        "domain",
        "policy",
        "canonicalUtf8",
        "fingerprint",
    }
    if not required_routing_keys.issubset(routing_vector):
        _fail("ROUTING_POLICY_VECTOR_INVALID")
    snapshot = {
        key: copy.deepcopy(routing_vector[key])
        for key in ("domain", "policy", "canonicalUtf8", "fingerprint")
    }
    try:
        policy = verify_policy_snapshot(snapshot)
    except ContractError as exc:
        _fail("ROUTING_POLICY_SNAPSHOT_INVALID", str(exc))

    expected_policy_coordinator = (
        coordinator
        if verified_catalog.schema_version == 1
        else coordinator_contract
    )
    if policy["coordinator"] != expected_policy_coordinator:
        _fail("COORDINATOR_POLICY_DRIFT")

    catalog_pairs = {
        (name, effort)
        for name, settings in normalized_models.items()
        for effort in settings["reasoningEfforts"]
    }
    policy_pairs = tuple(copy.deepcopy(policy["allowedPairs"]))
    for pair in policy_pairs:
        if (pair["model"], pair["reasoningEffort"]) not in catalog_pairs:
            _fail("POLICY_PAIR_NOT_IN_CATALOG")
    tier_ranks: list[int] = []
    for tier in policy["tiers"]:
        model = tier["model"]
        if model not in normalized_models:
            _fail("POLICY_TIER_MODEL_NOT_IN_CATALOG")
        tier_ranks.append(normalized_models[model]["rank"])
    if tier_ranks != sorted(tier_ranks) or len(tier_ranks) != len(set(tier_ranks)):
        _fail("POLICY_TIER_ORDER_DRIFT")

    delegation_vector = _read_json(
        delegation_vector_path,
        "DELEGATION_POLICY_VECTOR_INVALID",
    )
    _exact_keys(
        delegation_vector,
        {"schemaVersion", "contractVersion", "policy", "decisionCases", "mutations"},
        "DELEGATION_POLICY_VECTOR_INVALID",
    )
    if (
        delegation_vector["schemaVersion"] != 2
        or delegation_vector["contractVersion"] != "codex-delegation-policy-vector-v2"
        or type(delegation_vector["policy"]) is not dict
    ):
        _fail("DELEGATION_POLICY_VECTOR_INVALID")
    delegation_policy = copy.deepcopy(delegation_vector["policy"])

    role_vector = _read_json(role_vector_path, "ROLE_TEMPLATE_VECTOR_INVALID")
    _exact_keys(
        role_vector,
        {"schemaVersion", "contractVersion", "templates", "mutations"},
        "ROLE_TEMPLATE_VECTOR_INVALID",
    )
    if (
        role_vector["schemaVersion"] != 1
        or role_vector["contractVersion"] != "codex-role-template-vector-v1"
        or type(role_vector["templates"]) is not list
    ):
        _fail("ROLE_TEMPLATE_VECTOR_INVALID")
    role_templates = tuple(copy.deepcopy(role_vector["templates"]))

    child_vector = _read_json(
        child_profile_vector_path,
        "CHILD_PROFILE_VECTOR_INVALID",
    )
    _exact_keys(
        child_vector,
        {
            "schemaVersion",
            "profileDomain",
            "argvDomain",
            "environmentDomain",
            "secretDomain",
            "resultSchemaResolution",
            "syntheticSecretFixture",
            "cases",
            "concreteLaunch",
            "negativeCases",
            "environmentNegativeCases",
        },
        "CHILD_PROFILE_VECTOR_INVALID",
    )
    if (
        child_vector["schemaVersion"] != 1
        or type(child_vector["profileDomain"]) is not str
        or not child_vector["profileDomain"]
        or any(
            type(child_vector[name]) is not str or not child_vector[name]
            for name in ("argvDomain", "environmentDomain", "secretDomain")
        )
        or type(child_vector["cases"]) is not list
        or not child_vector["cases"]
    ):
        _fail("CHILD_PROFILE_VECTOR_INVALID")
    result_schema_resolution = child_vector["resultSchemaResolution"]
    _exact_keys(
        result_schema_resolution,
        {"virtualRoot", "repositoryRoot"},
        "RESULT_SCHEMA_RESOLUTION_INVALID",
    )
    if any(
        not isinstance(value, str) or not value or "\0" in value
        for value in result_schema_resolution.values()
    ):
        _fail("RESULT_SCHEMA_RESOLUTION_INVALID")
    virtual_root = PurePosixPath(result_schema_resolution["virtualRoot"])
    repository_root = PurePosixPath(result_schema_resolution["repositoryRoot"])
    if (
        not virtual_root.is_absolute()
        or ".." in virtual_root.parts
        or repository_root.is_absolute()
        or repository_root in {PurePosixPath("."), PurePosixPath("")}
        or ".." in repository_root.parts
        or str(virtual_root) != result_schema_resolution["virtualRoot"]
        or str(repository_root) != result_schema_resolution["repositoryRoot"]
    ):
        _fail("RESULT_SCHEMA_RESOLUTION_INVALID")
    child_profiles_list: list[dict[str, Any]] = []
    child_profile_fingerprints: dict[str, str] = {}
    permissions: set[str] = set()
    known_child_features: set[str] = set()
    for case in child_vector["cases"]:
        _exact_keys(
            case,
            {"name", "profile", "canonicalUtf8", "fingerprint"},
            "CHILD_PROFILE_VECTOR_INVALID",
        )
        profile = case["profile"]
        if (
            type(case["name"]) is not str
            or not case["name"]
            or type(profile) is not dict
            or profile.get("role") != case["name"]
            or type(profile.get("permissionProfileId")) is not str
            or not profile["permissionProfileId"]
            or type(profile.get("disabledFeatures")) is not list
            or any(
                type(feature) is not str or not feature
                for feature in profile["disabledFeatures"]
            )
            or len(profile["disabledFeatures"]) != len(set(profile["disabledFeatures"]))
            or case["name"] in child_profile_fingerprints
            or profile["permissionProfileId"] in permissions
        ):
            _fail("CHILD_PROFILE_VECTOR_INVALID")
        canonical = canonical_json_v1(profile)
        fingerprint = domain_fingerprint(child_vector["profileDomain"], profile)
        if case["canonicalUtf8"] != canonical or case["fingerprint"] != fingerprint:
            _fail("CHILD_PROFILE_FINGERPRINT_INVALID")
        child_profiles_list.append(copy.deepcopy(profile))
        child_profile_fingerprints[case["name"]] = fingerprint
        permissions.add(profile["permissionProfileId"])
        known_child_features.update(profile["disabledFeatures"])
    execution_profiles = {template["executionProfile"] for template in role_templates}
    if not execution_profiles.issubset(child_profile_fingerprints):
        _fail("ROLE_CHILD_PROFILE_MISMATCH")
    child_profiles = tuple(child_profiles_list)

    try:
        validation_commands = {
            "classifier-validation-v2": tuple(
                tuple(command)
                for command in verified_catalog.validation["none"]["commands"]
            ),
            "reader-validation-v2": tuple(
                tuple(command)
                for command in verified_catalog.validation["none"]["commands"]
            ),
            "writer-validation-v2": tuple(
                tuple(command)
                for command in verified_catalog.validation["python"]["commands"]
            ),
        }
    except (KeyError, TypeError) as exc:
        _fail("VALIDATION_PROFILE_BINDING_INVALID", str(exc))
    if not validation_commands["writer-validation-v2"]:
        _fail("VALIDATION_PROFILE_BINDING_INVALID")

    try:
        router = SemanticRouterV2(
            policy_snapshot=snapshot,
            delegation_policy=delegation_policy,
            role_templates=role_templates,
        )
    except ContractError as exc:
        _fail("POLICY_BUNDLE_INVALID", str(exc))

    bundle_projection = {
        "schemaVersion": 2,
        "algorithmVersion": SEMANTIC_VERSION,
        "catalog": catalog,
        "routingPolicyFingerprint": snapshot["fingerprint"],
        "delegationPolicyFingerprint": domain_fingerprint(
            "codex-smart/delegation-policy/v2",
            delegation_policy,
        ),
        "roleTemplateFingerprints": [
            domain_fingerprint("codex-smart/role-template/v1", template)
            for template in role_templates
        ],
        "childProfileFingerprints": child_profile_fingerprints,
        "resultSchemaResolution": result_schema_resolution,
    }
    return PolicyBundleV2(
        schema_version=2,
        algorithm_version=SEMANTIC_VERSION,
        minimum_codex_version=verified_catalog.minimum_codex_version,
        supported_platforms=verified_catalog.supported_platforms,
        coordinator=copy.deepcopy(coordinator),
        coordinator_selection=coordinator_contract["selection"],
        coordinator_candidates=coordinator_candidates,
        catalog_models=copy.deepcopy(normalized_models),
        catalog_limits=copy.deepcopy(verified_catalog.limits),
        validation_commands=copy.deepcopy(validation_commands),
        routing_policy_snapshot=snapshot,
        delegation_policy=delegation_policy,
        role_templates=role_templates,
        child_profiles=child_profiles,
        child_profile_fingerprints=copy.deepcopy(child_profile_fingerprints),
        child_profile_domain=child_vector["profileDomain"],
        child_argv_domain=child_vector["argvDomain"],
        child_environment_domain=child_vector["environmentDomain"],
        child_secret_domain=child_vector["secretDomain"],
        result_schema_resolution=copy.deepcopy(result_schema_resolution),
        known_child_features=frozenset(known_child_features),
        policy_pairs=policy_pairs,
        bundle_fingerprint=domain_fingerprint(
            "codex-smart/policy-bundle/v2",
            bundle_projection,
        ),
        router=router,
    )
