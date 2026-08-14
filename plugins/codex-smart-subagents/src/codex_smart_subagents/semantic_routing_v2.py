"""Производственная смысловая маршрутизация ``q+p+v+o-v2``.

Модуль не читает файлы проекта и не содержит имён моделей. Нормализованная
политика маршрутизации, политика делегирования и шаблоны ролей передаются
явно, поэтому один и тот же чистый алгоритм пригоден для рабочего процесса и
для проверки договорных векторов.
"""

from __future__ import annotations

import copy
import hashlib
from typing import Any, Iterable, Mapping, Sequence

from .canonical_json import canonical_json_v1, domain_fingerprint


SEMANTIC_VERSION = "q+p+v+o-v2"
TASK_FACTORS = ("q", "p", "v", "o")
LEGACY_FACTORS = (
    "ambiguity",
    "dependencyDepth",
    "breadth",
    "novelty",
    "harm",
    "crossDomain",
)


class ContractError(ValueError):
    """Нарушение смыслового договора с устойчивым кодом в сообщении."""


def _fail(code: str, detail: str = "") -> None:
    suffix = f": {detail}" if detail else ""
    raise ContractError(code + suffix)


def _exact_keys(value: Any, expected: Iterable[str], code: str) -> None:
    if type(value) is not dict or set(value) != set(expected):
        _fail(code)


def verify_policy_snapshot(snapshot: Mapping[str, Any]) -> dict[str, Any]:
    """Проверяет замкнутый отпечатанный снимок и возвращает копию политики."""

    _exact_keys(
        snapshot,
        {"domain", "policy", "canonicalUtf8", "fingerprint"},
        "ROUTING_POLICY_SNAPSHOT_MALFORMED",
    )
    policy = snapshot["policy"]
    if type(policy) is not dict:
        _fail("ROUTING_POLICY_MALFORMED")
    if policy.get("schemaVersion") != 2 or policy.get("contractVersion") != "codex-routing-policy-v2":
        _fail("ROUTING_POLICY_VERSION_MISMATCH")
    domain = snapshot["domain"]
    if type(domain) is not str or policy.get("fingerprintDomain") != domain:
        _fail("ROUTING_POLICY_DOMAIN_MISMATCH")
    canonical = canonical_json_v1(policy)
    if snapshot["canonicalUtf8"] != canonical:
        _fail("ROUTING_POLICY_CANONICAL_MISMATCH")
    if snapshot["fingerprint"] != domain_fingerprint(domain, policy):
        _fail("ROUTING_POLICY_FINGERPRINT_MISMATCH")
    _validate_policy_shape(policy)
    return copy.deepcopy(policy)


def _validate_policy_shape(policy: dict[str, Any]) -> None:
    if policy.get("factors") != list(TASK_FACTORS):
        _fail("ROUTING_POLICY_FACTORS_MISMATCH")
    if policy.get("factorRange") != {"min": 0, "max": 2}:
        _fail("ROUTING_POLICY_FACTOR_RANGE_MISMATCH")
    score_range = policy.get("scoreRange")
    if score_range != {"min": 0, "max": 8}:
        _fail("ROUTING_POLICY_SCORE_RANGE_MISMATCH")
    efforts = policy.get("effortOrder")
    if type(efforts) is not list or not efforts or len(efforts) != len(set(efforts)):
        _fail("ROUTING_POLICY_EFFORT_ORDER_MALFORMED")
    allowed_pairs = policy.get("allowedPairs")
    if type(allowed_pairs) is not list or not allowed_pairs:
        _fail("ROUTING_POLICY_ALLOWED_PAIRS_MALFORMED")
    pair_keys: list[tuple[str, str]] = []
    for pair in allowed_pairs:
        _exact_keys(pair, {"model", "reasoningEffort"}, "ROUTING_POLICY_PAIR_MALFORMED")
        key = (pair["model"], pair["reasoningEffort"])
        if not all(type(item) is str and item for item in key) or key[1] not in efforts:
            _fail("ROUTING_POLICY_PAIR_MALFORMED")
        pair_keys.append(key)
    if len(pair_keys) != len(set(pair_keys)):
        _fail("ROUTING_POLICY_PAIR_DUPLICATE")

    scores = range(score_range["min"], score_range["max"] + 1)
    tiers = policy.get("tiers")
    if type(tiers) is not list or not tiers:
        _fail("ROUTING_POLICY_TIERS_MALFORMED")
    tier_names: list[str] = []
    for tier in tiers:
        _exact_keys(
            tier,
            {"name", "scoreMin", "scoreMax", "model", "minimumEffort"},
            "ROUTING_POLICY_TIER_MALFORMED",
        )
        tier_names.append(tier["name"])
        if tier["minimumEffort"] not in efforts:
            _fail("ROUTING_POLICY_TIER_MALFORMED")
    if len(tier_names) != len(set(tier_names)):
        _fail("ROUTING_POLICY_TIER_DUPLICATE")
    for score in scores:
        matching = [tier for tier in tiers if tier["scoreMin"] <= score <= tier["scoreMax"]]
        if len(matching) != 1:
            _fail("ROUTING_POLICY_TIER_COVERAGE_INVALID")

    effort_by_score = policy.get("effortByScore")
    if type(effort_by_score) is not list:
        _fail("ROUTING_POLICY_SCORE_EFFORT_MALFORMED")
    effort_map = {item.get("score"): item.get("reasoningEffort") for item in effort_by_score if type(item) is dict}
    if set(effort_map) != set(scores) or any(effort not in efforts for effort in effort_map.values()):
        _fail("ROUTING_POLICY_SCORE_EFFORT_MALFORMED")

    factor_definitions = policy.get("factorDefinitions")
    if type(factor_definitions) is not dict or set(factor_definitions) != {"resolution", *TASK_FACTORS}:
        _fail("ROUTING_POLICY_FACTOR_DEFINITIONS_MALFORMED")
    for factor in TASK_FACTORS:
        criteria = factor_definitions[factor].get("criteria")
        if type(criteria) is not list:
            _fail("ROUTING_POLICY_CRITERIA_MALFORMED")
        ids = [criterion.get("id") for criterion in criteria if type(criterion) is dict]
        if len(ids) != len(criteria) or len(ids) != len(set(ids)):
            _fail("ROUTING_POLICY_CRITERIA_MALFORMED")
        if any(criterion.get("level") not in range(3) for criterion in criteria):
            _fail("ROUTING_POLICY_CRITERIA_MALFORMED")

    floors = policy.get("hardFloorDefinitions", {}).get("levels")
    if type(floors) is not list or not floors:
        _fail("ROUTING_POLICY_HARD_FLOORS_MALFORMED")
    reasons: list[str] = []
    for floor in floors:
        if floor.get("minimumTier") not in tier_names or type(floor.get("reasons")) is not list:
            _fail("ROUTING_POLICY_HARD_FLOORS_MALFORMED")
        reasons.extend(floor["reasons"])
    if len(reasons) != len(set(reasons)):
        _fail("ROUTING_POLICY_HARD_FLOOR_REASON_DUPLICATE")


def legacy_v1_score(factors: dict[str, Any]) -> int:
    """Старая шестимерная шкала остаётся отдельным явным интерфейсом."""

    if set(factors) != set(LEGACY_FACTORS):
        _fail("LEGACY_VERSION_MISMATCH")
    if any(type(value) is not int or value not in range(3) for value in factors.values()):
        _fail("LEGACY_FACTOR_RANGE")
    return sum(factors.values())


def semantic_v2_score(factors: dict[str, Any]) -> int:
    semantic_version = factors.get("semanticVersion", SEMANTIC_VERSION)
    if semantic_version != SEMANTIC_VERSION:
        _fail("SEMANTIC_VERSION_MISMATCH")
    values = {key: value for key, value in factors.items() if key != "semanticVersion"}
    if set(values) != set(TASK_FACTORS):
        _fail("SEMANTIC_VERSION_MISMATCH")
    if any(type(value) is not int or value not in range(3) for value in values.values()):
        _fail("SEMANTIC_FACTOR_RANGE")
    return sum(values.values())


def _evidence_map(value: Any) -> dict[str, dict[str, Any]]:
    if type(value) is dict:
        return value
    if type(value) is list:
        result: dict[str, dict[str, Any]] = {}
        for item in value:
            if type(item) is not dict or "evidenceRefId" not in item:
                _fail("EVIDENCE_RECORD_MALFORMED")
            ref_id = item["evidenceRefId"]
            if ref_id in result:
                _fail("DUPLICATE_EVIDENCE_REF_ID")
            result[ref_id] = item
        return result
    _fail("EVIDENCE_RECORD_MALFORMED")


def _require_resolved_refs(
    refs: Any,
    evidence: dict[str, dict[str, Any]],
    *,
    missing_code: str = "EVIDENCE_REFERENCE_UNRESOLVED",
) -> None:
    if type(refs) is not list or len(refs) != len(set(refs)):
        _fail("EVIDENCE_REFERENCE_SET_MALFORMED")
    if any(type(ref_id) is not str or ref_id not in evidence for ref_id in refs):
        _fail(missing_code)


def normalize_task_facts(
    value: dict[str, Any],
    *,
    routing_policy: Mapping[str, Any],
    delegation_policy: Mapping[str, Any],
) -> dict[str, Any]:
    expected_root = {
        "schemaVersion",
        "contractVersion",
        "taskText",
        "evidence",
        "workShape",
        "factorClaims",
        "delegation",
        "hardFloorReasons",
        "hardBanReasons",
    }
    if type(value) is not dict or set(value) != expected_root:
        _fail("TASK_FACTS_UNKNOWN_FIELD")
    if value.get("schemaVersion") != 1 or value.get("contractVersion") != "codex-task-facts-v1":
        _fail("TASK_FACTS_VERSION_MISMATCH")

    normalized = copy.deepcopy(value)
    evidence = _evidence_map(normalized["evidence"])
    _exact_keys(
        normalized["workShape"],
        {"scopeUnits", "workUnits", "boundaries", "workstreams"},
        "WORK_SHAPE_MALFORMED",
    )
    for fact in normalized["workShape"].values():
        _exact_keys(fact, {"value", "evidenceRefIds"}, "COUNT_FACT_MALFORMED")
        _require_resolved_refs(fact["evidenceRefIds"], evidence)
        if fact["value"] is not None and not fact["evidenceRefIds"]:
            _fail("COUNT_EVIDENCE_REQUIRED")

    criterion_ids = {
        factor: {
            criterion["id"]
            for criterion in routing_policy["factorDefinitions"][factor]["criteria"]
        }
        for factor in ("q", "v", "o")
    }
    _exact_keys(normalized["factorClaims"], criterion_ids, "FACTOR_CLAIMS_MALFORMED")
    for factor, allowed_ids in criterion_ids.items():
        claims = normalized["factorClaims"][factor]
        if type(claims) is not dict or set(claims) - allowed_ids:
            _fail("UNKNOWN_CRITERION_ID")
        for claim in claims.values():
            _exact_keys(claim, {"state", "evidenceRefIds"}, "FACTOR_CLAIM_MALFORMED")
            _require_resolved_refs(claim["evidenceRefIds"], evidence)
            state = claim["state"]
            if state == "true" and not claim["evidenceRefIds"]:
                _fail("UNPROVED_TRUE")
            if state == "conflict" and len(claim["evidenceRefIds"]) < 2:
                _fail("CONFLICT_EVIDENCE_INSUFFICIENT")
            if state == "false" and not claim["evidenceRefIds"]:
                claim["state"] = "unknown"

    delegation = normalized["delegation"]
    _exact_keys(
        delegation,
        {"permission", "objectivelyVerifiable", "independentWorkUnits"},
        "DELEGATION_FACTS_MALFORMED",
    )
    for name, fact in delegation.items():
        _exact_keys(fact, {"value", "evidenceRefIds"}, "DELEGATION_FACT_MALFORMED")
        _require_resolved_refs(fact["evidenceRefIds"], evidence)
        if fact["value"] is not None and name != "permission" and not fact["evidenceRefIds"]:
            _fail("DELEGATION_FACT_EVIDENCE_REQUIRED")
    permission = delegation["permission"]
    if permission["value"] in {"allow", "forbid"}:
        if not permission["evidenceRefIds"]:
            _fail("DELEGATION_PERMISSION_EVIDENCE_REQUIRED")
        kinds = {evidence[ref_id]["kind"] for ref_id in permission["evidenceRefIds"]}
        if not kinds & {"explicit-policy", "user-request"}:
            _fail("DELEGATION_ALLOW_NOT_EXPLICIT")

    ban_decisions = {
        item["reason"]: item["decision"]
        for item in delegation_policy["hardBanReasons"]
    }
    seen_bans: set[str] = set()
    for item in normalized["hardBanReasons"]:
        _exact_keys(item, {"reason", "decision", "evidenceRefIds"}, "HARD_BAN_MALFORMED")
        _require_resolved_refs(item["evidenceRefIds"], evidence)
        if not item["evidenceRefIds"]:
            _fail("HARD_BAN_EVIDENCE_REQUIRED")
        if ban_decisions.get(item["reason"]) != item["decision"]:
            _fail("HARD_BAN_DECISION_MISMATCH")
        if item["reason"] in seen_bans:
            _fail("DUPLICATE_HARD_BAN_REASON")
        seen_bans.add(item["reason"])

    floor_reasons = {
        reason
        for level in routing_policy["hardFloorDefinitions"]["levels"]
        for reason in level["reasons"]
    }
    seen_floors: set[str] = set()
    for item in normalized["hardFloorReasons"]:
        _exact_keys(item, {"reason", "evidenceRefIds"}, "HARD_FLOOR_MALFORMED")
        _require_resolved_refs(item["evidenceRefIds"], evidence)
        if not item["evidenceRefIds"]:
            _fail("HARD_FLOOR_EVIDENCE_REQUIRED")
        if item["reason"] not in floor_reasons:
            _fail("HARD_FLOOR_REASON_UNKNOWN")
        if item["reason"] in seen_floors:
            _fail("DUPLICATE_HARD_FLOOR_REASON")
        seen_floors.add(item["reason"])
    return normalized


def derive_p_criterion_states(work_shape: dict[str, Any]) -> dict[str, str]:
    values = {name: fact["value"] for name, fact in work_shape.items()}
    scope = values["scopeUnits"]
    work = values["workUnits"]
    boundaries = values["boundaries"]
    streams = values["workstreams"]

    if scope is not None and work is not None and boundaries is not None and streams is not None:
        p1 = "true" if 2 <= max(scope, work) <= 5 and boundaries <= 1 and streams <= 1 else "false"
    elif (
        (scope is not None and scope >= 6)
        or (work is not None and work >= 6)
        or (boundaries is not None and boundaries >= 2)
        or (streams is not None and streams >= 2)
    ):
        p1 = "false"
    else:
        p1 = "unknown"

    def threshold_state(left: int | None, right: int | None) -> str:
        candidates = [candidate for candidate in (left, right) if candidate is not None]
        if any(candidate >= 6 for candidate in candidates):
            return "true"
        if left is not None and right is not None:
            return "false"
        return "unknown"

    def two_plus(candidate: int | None) -> str:
        if candidate is None:
            return "unknown"
        return "true" if candidate >= 2 else "false"

    return {
        "p1-scope-2-to-5": p1,
        "p2-scope-6-plus": threshold_state(scope, work),
        "p2-boundaries-2-plus": two_plus(boundaries),
        "p2-workstreams-2-plus": two_plus(streams),
    }


def validate_context_bundle(value: dict[str, Any], evidence_by_id: Any | None = None) -> None:
    _exact_keys(
        value,
        {"schemaVersion", "contractVersion", "bundleId", "maxBytes", "totalBytes", "entries"},
        "CONTEXT_BUNDLE_MALFORMED",
    )
    if value["schemaVersion"] != 1 or value["contractVersion"] != "codex-context-bundle-v1":
        _fail("CONTEXT_BUNDLE_VERSION_MISMATCH")
    evidence = _evidence_map(evidence_by_id) if evidence_by_id is not None else None
    seen: set[str] = set()
    total = 0
    for entry in value["entries"]:
        _exact_keys(
            entry,
            {"contextRefId", "kind", "required", "sourceEvidenceRefs", "sha256", "byteLength", "content"},
            "CONTEXT_ENTRY_MALFORMED",
        )
        if entry["contextRefId"] in seen:
            _fail("DUPLICATE_CONTEXT_REF_ID")
        seen.add(entry["contextRefId"])
        encoded = entry["content"].encode("utf-8")
        if len(encoded) != entry["byteLength"]:
            _fail("CONTEXT_ENTRY_BYTE_LENGTH_MISMATCH")
        if hashlib.sha256(encoded).hexdigest() != entry["sha256"]:
            _fail("CONTEXT_DIGEST_MISMATCH")
        total += len(encoded)
        source_ids: set[str] = set()
        for source in entry["sourceEvidenceRefs"]:
            _exact_keys(source, {"evidenceRefId", "evidenceSha256"}, "CONTEXT_SOURCE_MALFORMED")
            ref_id = source["evidenceRefId"]
            if ref_id in source_ids:
                _fail("DUPLICATE_CONTEXT_SOURCE_REF")
            source_ids.add(ref_id)
            if evidence is not None:
                if ref_id not in evidence:
                    _fail("CONTEXT_SOURCE_UNRESOLVED")
                if evidence[ref_id]["sha256"] != source["evidenceSha256"]:
                    _fail("CONTEXT_SOURCE_STALE")
    if total != value["totalBytes"]:
        _fail("CONTEXT_TOTAL_BYTES_MISMATCH")
    if total > value["maxBytes"]:
        _fail("CONTEXT_BUDGET_EXCEEDED")


def validate_role_template(value: dict[str, Any]) -> None:
    _exact_keys(
        value,
        {
            "schemaVersion",
            "contractVersion",
            "templateId",
            "semanticRole",
            "executionProfile",
            "objective",
            "requiredContextKinds",
            "requiredEvidenceKinds",
            "requiredOutputFields",
            "completionConditions",
        },
        "ROLE_TEMPLATE_MALFORMED",
    )
    if value["schemaVersion"] != 1 or value["contractVersion"] != "codex-role-template-v1":
        _fail("ROLE_TEMPLATE_VERSION_MISMATCH")
    profile_by_role = {
        "researcher": "reader",
        "diagnostician": "reader",
        "validator": "reader",
        "risk_auditor": "reader",
        "implementer": "writer",
    }
    role = value["semanticRole"]
    if value["templateId"] != f"{role}-v1":
        _fail("ROLE_TEMPLATE_ID_MISMATCH")
    if profile_by_role.get(role) != value["executionProfile"]:
        _fail("ROLE_PROFILE_MISMATCH")
    for field in (
        "requiredContextKinds",
        "requiredEvidenceKinds",
        "requiredOutputFields",
        "completionConditions",
    ):
        items = value[field]
        if type(items) is not list or not items or len(items) != len(set(items)):
            code = "ROLE_TEMPLATE_EMPTY_COMPLETION" if field == "completionConditions" else "ROLE_TEMPLATE_SET_MALFORMED"
            _fail(code)


def decide_delegation(
    normalized: dict[str, Any], delegation_policy: Mapping[str, Any]
) -> dict[str, Any]:
    decision_order = delegation_policy["decisionOrder"]
    bans_by_decision = {
        decision: [
            item["reason"]
            for item in normalized["hardBanReasons"]
            if item["decision"] == decision
        ]
        for decision in ("clarify", "direct")
    }
    for decision in decision_order:
        if decision in bans_by_decision and bans_by_decision[decision]:
            return {"decision": decision, "reasons": bans_by_decision[decision]}

    facts = normalized["delegation"]
    requirements = delegation_policy["delegateRequirements"]
    if facts["permission"]["value"] == "forbid":
        return {"decision": "direct", "reasons": ["delegation-explicitly-forbidden"]}
    if facts["permission"]["value"] != requirements["permission"]:
        return {"decision": "direct", "reasons": ["delegation-not-explicitly-allowed"]}
    if facts["objectivelyVerifiable"]["value"] is not requirements["objectivelyVerifiable"]:
        return {"decision": "direct", "reasons": ["no-objectively-verifiable-unit"]}
    independent = facts["independentWorkUnits"]["value"]
    if type(independent) is not int or independent < requirements["minimumIndependentWorkUnits"]:
        return {"decision": "direct", "reasons": ["no-independent-work-unit"]}
    return {"decision": "delegate", "reasons": ["delegation-requirements-satisfied"]}


class SemanticRouterV2:
    """Чистый исполнитель решения, оценки и выбора точной атомарной пары."""

    def __init__(
        self,
        *,
        policy_snapshot: Mapping[str, Any],
        delegation_policy: Mapping[str, Any],
        role_templates: Sequence[Mapping[str, Any]],
    ) -> None:
        self.policy = verify_policy_snapshot(policy_snapshot)
        self.policy_fingerprint = policy_snapshot["fingerprint"]
        self.delegation_policy = copy.deepcopy(dict(delegation_policy))
        if self.delegation_policy.get("schemaVersion") != 2 or self.delegation_policy.get("contractVersion") != "codex-delegation-policy-v2":
            _fail("DELEGATION_POLICY_VERSION_MISMATCH")
        templates: dict[str, dict[str, Any]] = {}
        for original in role_templates:
            template = copy.deepcopy(dict(original))
            validate_role_template(template)
            template_id = template["templateId"]
            if template_id in templates:
                _fail("ROLE_TEMPLATE_DUPLICATE")
            templates[template_id] = template
        self.role_templates = templates

    def normalize_task_facts(self, value: dict[str, Any]) -> dict[str, Any]:
        return normalize_task_facts(
            value,
            routing_policy=self.policy,
            delegation_policy=self.delegation_policy,
        )

    def select_pair(
        self,
        factors: dict[str, Any],
        *,
        hard_floor_reasons: Sequence[str] = (),
    ) -> dict[str, str]:
        """Выбирает точную пару только из переданной отпечатанной политики."""

        score = semantic_v2_score(factors)
        return self._pair_for_score(
            score,
            [{"reason": reason} for reason in hard_floor_reasons],
        )

    def evaluate(self, value: dict[str, Any]) -> dict[str, Any]:
        expected_root = {
            "schemaVersion",
            "contractVersion",
            "semanticVersion",
            "phase",
            "taskFacts",
            "delegationPolicyRef",
            "contextBundle",
            "roleTemplateId",
            "catalogs",
            "accountEvidenceJobs",
            "reassessment",
        }
        if type(value) is not dict or set(value) != expected_root:
            _fail("ROUTING_INPUT_UNKNOWN_FIELD")
        if value["semanticVersion"] != SEMANTIC_VERSION:
            _fail("SEMANTIC_VERSION_MISMATCH")
        if value["schemaVersion"] != 2 or value["contractVersion"] != "codex-routing-input-v2":
            _fail("ROUTING_INPUT_VERSION_MISMATCH")
        if value["delegationPolicyRef"] != self.delegation_policy["policyId"]:
            _fail("DELEGATION_POLICY_MISMATCH")
        self._validate_catalogs(value["catalogs"])

        normalized = self.normalize_task_facts(value["taskFacts"])
        evidence = _evidence_map(normalized["evidence"])
        validate_context_bundle(value["contextBundle"], evidence)
        role = self.role_templates.get(value["roleTemplateId"])
        if role is None:
            _fail("ROLE_TEMPLATE_UNKNOWN")
        context_kinds = {entry["kind"] for entry in value["contextBundle"]["entries"]}
        if not set(role["requiredContextKinds"]).issubset(context_kinds):
            _fail("ROLE_CONTEXT_KIND_MISSING")

        decision = decide_delegation(normalized, self.delegation_policy)
        if decision["decision"] != "delegate":
            if (
                value["accountEvidenceJobs"]
                or value["catalogs"]["accountPairs"] is not None
            ):
                return self._result(
                    decision,
                    pair=None,
                    score=None,
                    factors=None,
                    jobs=0,
                    error="ACCOUNT_EVIDENCE_FORBIDDEN_FOR_NON_DELEGATE",
                )
            return self._result(
                decision, pair=None, score=None, factors=None, jobs=0
            )

        jobs_consumed, phase_error = self._validate_account_evidence_phase(value)
        if phase_error is not None:
            factors = self._selected_factors(normalized)
            score = semantic_v2_score(factors)
            return self._result(
                decision,
                pair=None,
                score=score,
                factors=factors,
                jobs=jobs_consumed,
                error=phase_error,
            )

        factors = self._selected_factors(normalized)
        score = semantic_v2_score(factors)
        candidate = self.select_pair(
            factors,
            hard_floor_reasons=tuple(
                item["reason"] for item in normalized["hardFloorReasons"]
            ),
        )
        reassessment = value["reassessment"]
        expected_mode = self.delegation_policy["reassessment"]["mode"]
        if reassessment["mode"] == expected_mode:
            if (
                reassessment["currentPair"] is None
                or not reassessment["explicitPolicyAllowed"]
            ):
                return self._result(
                    decision,
                    pair=None,
                    score=score,
                    factors=factors,
                    jobs=jobs_consumed,
                    error=self.delegation_policy["reassessment"]["missingPolicyError"],
                )
            rank = {
                (pair["model"], pair["reasoningEffort"]): index
                for index, pair in enumerate(self.policy["allowedPairs"])
            }
            current = reassessment["currentPair"]
            current_key = (current["model"], current["reasoningEffort"])
            candidate_key = (candidate["model"], candidate["reasoningEffort"])
            if current_key not in rank or candidate_key not in rank:
                _fail("REASSESSMENT_PAIR_UNKNOWN")
            if rank[current_key] > rank[candidate_key]:
                candidate = current
        elif reassessment["mode"] != "initial":
            _fail("REASSESSMENT_MODE_UNKNOWN")

        phase_sources = (
            self.delegation_policy["pairAvailability"]["smartPlanSources"]
            if value["phase"] == "smart-plan"
            else self.delegation_policy["pairAvailability"]["nodeAttemptSources"]
        )
        catalogs = [value["catalogs"][source] for source in phase_sources]
        if not self._pair_available(candidate, catalogs):
            return self._result(
                decision,
                pair=None,
                score=score,
                factors=factors,
                jobs=jobs_consumed,
                error=self.delegation_policy["pairAvailability"]["errorCode"],
            )
        return self._result(
            decision,
            pair=candidate,
            score=score,
            factors=factors,
            jobs=jobs_consumed,
        )

    def _criterion_states(self, normalized: dict[str, Any]) -> dict[str, dict[str, str]]:
        result: dict[str, dict[str, str]] = {}
        for factor in ("q", "v", "o"):
            result[factor] = {
                criterion["id"]: normalized["factorClaims"][factor]
                .get(criterion["id"], {"state": "unknown"})["state"]
                for criterion in self.policy["factorDefinitions"][factor]["criteria"]
            }
        result["p"] = derive_p_criterion_states(normalized["workShape"])
        return result

    def _selected_factors(self, normalized: dict[str, Any]) -> dict[str, int]:
        states = self._criterion_states(normalized)
        resolution = self.policy["factorDefinitions"]["resolution"]
        selected: dict[str, int] = {}
        for factor in TASK_FACTORS:
            criteria = self.policy["factorDefinitions"][factor]["criteria"]
            lower = max(
                [resolution["identityValue"]]
                + [
                    criterion["level"]
                    for criterion in criteria
                    if states[factor][criterion["id"]] in resolution["lowerStates"]
                ]
            )
            selected[factor] = max(
                [lower]
                + [
                    criterion["level"]
                    for criterion in criteria
                    if states[factor][criterion["id"]] in resolution["upperStates"]
                ]
            )
        return selected

    def _pair_for_score(
        self, score: int, hard_floor_reasons: list[dict[str, Any]]
    ) -> dict[str, str]:
        tiers = self.policy["tiers"]
        tier_rank = {tier["name"]: index for index, tier in enumerate(tiers)}
        effort_rank = {
            effort: index for index, effort in enumerate(self.policy["effortOrder"])
        }
        score_tier = next(
            tier for tier in tiers if tier["scoreMin"] <= score <= tier["scoreMax"]
        )
        floor_by_reason: dict[str, str] = {}
        default_floor = self.policy["defaults"]["hardFloor"]
        floor_tier = None
        for level in self.policy["hardFloorDefinitions"]["levels"]:
            if level["name"] == default_floor:
                floor_tier = level["minimumTier"]
            for reason in level["reasons"]:
                floor_by_reason[reason] = level["minimumTier"]
        if floor_tier is None:
            _fail("ROUTING_POLICY_DEFAULT_FLOOR_UNKNOWN")
        triggered = [floor_tier]
        for item in hard_floor_reasons:
            if item["reason"] not in floor_by_reason:
                _fail("HARD_FLOOR_REASON_UNKNOWN")
            triggered.append(floor_by_reason[item["reason"]])
        selected_floor = max(triggered, key=tier_rank.__getitem__)
        selected_tier = max(
            (score_tier, next(tier for tier in tiers if tier["name"] == selected_floor)),
            key=lambda tier: tier_rank[tier["name"]],
        )
        effort = next(
            item["reasoningEffort"]
            for item in self.policy["effortByScore"]
            if item["score"] == score
        )
        effort = max(
            (effort, selected_tier["minimumEffort"]), key=effort_rank.__getitem__
        )
        pair = {"model": selected_tier["model"], "reasoningEffort": effort}
        if pair not in self.policy["allowedPairs"]:
            _fail("ROUTING_POLICY_SELECTED_PAIR_NOT_ALLOWED")
        return pair

    @staticmethod
    def _pair_available(
        pair: dict[str, str], catalogs: list[list[dict[str, str]]]
    ) -> bool:
        key = (pair["model"], pair["reasoningEffort"])
        return all(
            key
            in {(item["model"], item["reasoningEffort"]) for item in catalog}
            for catalog in catalogs
        )

    @staticmethod
    def _validate_catalogs(value: Any) -> None:
        _exact_keys(
            value,
            {"policyPairs", "bundledSnapshotPairs", "accountPairs"},
            "ROUTING_CATALOGS_MALFORMED",
        )
        for source in ("policyPairs", "bundledSnapshotPairs", "accountPairs"):
            catalog = value[source]
            if source == "accountPairs" and catalog is None:
                continue
            if type(catalog) is not list:
                _fail("ROUTING_CATALOGS_MALFORMED")
            seen: set[tuple[str, str]] = set()
            for pair in catalog:
                _exact_keys(
                    pair,
                    {"model", "reasoningEffort"},
                    "ROUTING_CATALOGS_MALFORMED",
                )
                key = (pair["model"], pair["reasoningEffort"])
                if not all(type(item) is str and item for item in key) or key in seen:
                    _fail("ROUTING_CATALOGS_MALFORMED")
                seen.add(key)

    def _validate_account_evidence_phase(
        self, value: dict[str, Any]
    ) -> tuple[int, str | None]:
        phase = value.get("phase")
        jobs = value.get("accountEvidenceJobs")
        account_pairs = value.get("catalogs", {}).get("accountPairs")
        account_policy = self.delegation_policy["accountEvidence"]
        if phase == "smart-plan":
            if jobs or account_pairs is not None:
                return 0, "ACCOUNT_EVIDENCE_FORBIDDEN_DURING_SMART_PLAN"
            return 0, None
        if phase != "node-attempt":
            return 0, "ROUTING_PHASE_UNKNOWN"
        if account_pairs is None or type(jobs) is not list or not jobs:
            return 0, account_policy["missingAttemptEvidenceError"]
        if len(jobs) != account_policy["fullCollectionJobsPerAttempt"]:
            return 0, "ACCOUNT_EVIDENCE_JOB_COUNT_INVALID"
        job = jobs[0]
        if job.get("cacheHit") is not account_policy["cacheAcrossAttempts"]:
            return 0, "ACCOUNT_EVIDENCE_REUSE_FORBIDDEN"
        if job.get("hiddenRetry") is not account_policy["hiddenRetry"]:
            return 0, "ACCOUNT_EVIDENCE_HIDDEN_RETRY_FORBIDDEN"
        if (
            job.get("fullCollection") is not True
            or job.get("processCount") != account_policy["processesPerFullCollection"]
        ):
            return 0, "ACCOUNT_EVIDENCE_INCOMPLETE"
        return 1, None

    @staticmethod
    def _result(
        decision: dict[str, Any],
        *,
        pair: dict[str, str] | None,
        score: int | None,
        factors: dict[str, int] | None,
        jobs: int,
        error: str | None = None,
    ) -> dict[str, Any]:
        result: dict[str, Any] = {
            "decision": decision["decision"],
            "reasons": decision["reasons"],
            "pair": pair,
            "score": score,
            "factors": factors,
            "accountEvidenceJobsConsumed": jobs,
        }
        if error is not None:
            result["errorCode"] = error
        return result
