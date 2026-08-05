"""Детерминированная подготовка публичного ``planInput`` версии 2."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping

from .public_routing_input_v2 import validate_public_routing_input_v2


_PACKAGE = Path(__file__).resolve().parent
_CLIENT_NODE = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,63}$")
_WORK_SHAPE_FIELDS = ("scopeUnits", "workUnits", "boundaries", "workstreams")


class PlanInputBuilderV2Error(ValueError):
    """Смысловое описание нельзя преобразовать без догадок."""


def build_plan_input_v2(specification: Any) -> dict[str, Any]:
    """Строит полный план и вычисляет все поля целостности текста."""

    if type(specification) is not dict or set(specification) != {"nodes"}:
        _fail("корень должен содержать только nodes")
    nodes = specification["nodes"]
    if type(nodes) is not list or not 1 <= len(nodes) <= 20:
        _fail("nodes должен содержать от 1 до 20 узлов")
    base = _base_input()
    result: list[dict[str, Any]] = []
    known: set[str] = set()
    for index, node in enumerate(nodes):
        result.append(_build_node(node, index=index, base=base, known=known))
    all_ids = {item["clientNodeId"] for item in result}
    for item in result:
        missing = sorted(set(item["dependencyIds"]) - all_ids)
        if missing:
            _fail(
                f"узел {item['clientNodeId']} ссылается на неизвестные зависимости: "
                + ", ".join(missing)
            )
    _validate_dependency_graph(result)
    return {"nodes": result}


def _validate_dependency_graph(nodes: list[dict[str, Any]]) -> None:
    remaining = {
        item["clientNodeId"]: set(item["dependencyIds"]) for item in nodes
    }
    resolved: set[str] = set()
    while remaining:
        ready = sorted(
            node_id
            for node_id, dependencies in remaining.items()
            if dependencies <= resolved
        )
        if not ready:
            _fail(
                "граф зависимостей содержит цикл: "
                + ", ".join(sorted(remaining))
            )
        resolved.update(ready)
        for node_id in ready:
            del remaining[node_id]


def _build_node(
    node: Any,
    *,
    index: int,
    base: Mapping[str, Any],
    known: set[str],
) -> dict[str, Any]:
    required = {
        "clientNodeId",
        "dependencyIds",
        "taskText",
        "roleTemplateId",
        "evidence",
        "workShape",
        "delegation",
        "contextEntries",
    }
    optional = {"factorClaims", "hardFloorReasons", "hardBanReasons", "maxBytes"}
    if type(node) is not dict:
        _fail(f"узел {index} должен быть объектом")
    missing = sorted(required - set(node))
    extra = sorted(set(node) - required - optional)
    if missing or extra:
        _fail(
            f"узел {index}: отсутствуют {missing or '[]'}, лишние {extra or '[]'}"
        )
    client_node_id = node["clientNodeId"]
    if (
        type(client_node_id) is not str
        or _CLIENT_NODE.fullmatch(client_node_id) is None
        or client_node_id in known
    ):
        _fail(f"узел {index} имеет неверный или повторный clientNodeId")
    known.add(client_node_id)
    dependencies = node["dependencyIds"]
    if (
        type(dependencies) is not list
        or len(dependencies) > 20
        or len(set(dependencies)) != len(dependencies)
        or any(type(value) is not str for value in dependencies)
    ):
        _fail(f"узел {index} имеет неверные dependencyIds")

    task_facts = copy.deepcopy(base["taskFacts"])
    task_facts.pop("schemaVersion", None)
    task_facts.pop("contractVersion", None)
    task_facts["taskText"] = _text(node["taskText"], f"узел {index}.taskText")
    task_facts["evidence"] = _evidence(node["evidence"], index=index)
    evidence_ids = {item["evidenceRefId"] for item in task_facts["evidence"]}
    default_evidence = "scope" if "scope" in evidence_ids else next(iter(evidence_ids))
    task_facts["workShape"] = _work_shape(
        node["workShape"], evidence_ids=evidence_ids, default_evidence=default_evidence
    )
    delegation = node["delegation"]
    if type(delegation) is not dict or set(delegation) != {
        "objectivelyVerifiable",
        "independentWorkUnits",
    }:
        _fail(f"узел {index}.delegation имеет неверные поля")
    task_facts["delegation"] = {
        "objectivelyVerifiable": _claim_value(
            delegation["objectivelyVerifiable"],
            evidence_ids=evidence_ids,
            default_evidence=default_evidence,
            expected=bool,
            label=f"узел {index}.delegation.objectivelyVerifiable",
        ),
        "independentWorkUnits": _claim_value(
            delegation["independentWorkUnits"],
            evidence_ids=evidence_ids,
            default_evidence=default_evidence,
            expected=int,
            label=f"узел {index}.delegation.independentWorkUnits",
        ),
    }
    task_facts["factorClaims"] = _factor_claims(
        task_facts["factorClaims"],
        node.get("factorClaims"),
        evidence_ids=evidence_ids,
        default_evidence=default_evidence,
    )
    task_facts["hardFloorReasons"] = copy.deepcopy(node.get("hardFloorReasons", []))
    task_facts["hardBanReasons"] = copy.deepcopy(node.get("hardBanReasons", []))

    context_bundle = _context_bundle(
        node["contextEntries"],
        evidence=task_facts["evidence"],
        bundle_id=client_node_id,
        requested_max=node.get("maxBytes"),
    )
    routing_input = {
        "taskFacts": task_facts,
        "contextBundle": context_bundle,
        "roleTemplateId": _text(
            node["roleTemplateId"], f"узел {index}.roleTemplateId"
        ),
    }
    validate_public_routing_input_v2(routing_input)
    return {
        "clientNodeId": client_node_id,
        "dependencyIds": copy.deepcopy(dependencies),
        "routingInput": routing_input,
    }


def _base_input() -> dict[str, Any]:
    candidates = (
        _PACKAGE.parents[1] / "config" / "contracts" / "routing-input-v2.json",
        _PACKAGE.parents[3]
        / "docs"
        / "contracts"
        / "vectors"
        / "routing-input-v2.json",
    )
    for path in candidates:
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        base = document.get("baseInput") if type(document) is dict else None
        if type(base) is dict:
            return copy.deepcopy(base)
    _fail("не найден нормативный routing-input-v2.json")


def _evidence(value: Any, *, index: int) -> list[dict[str, Any]]:
    if type(value) is not list or not 1 <= len(value) <= 63:
        _fail(f"узел {index}.evidence должен содержать от 1 до 63 записей")
    result: list[dict[str, Any]] = []
    known: set[str] = set()
    for position, item in enumerate(value):
        if type(item) is not dict or set(item) != {
            "evidenceRefId",
            "kind",
            "statement",
        }:
            _fail(f"узел {index}.evidence[{position}] имеет неверные поля")
        evidence_id = _text(item["evidenceRefId"], "evidenceRefId")
        if evidence_id in known or evidence_id.startswith("server."):
            _fail(f"повторный или служебный evidenceRefId: {evidence_id}")
        known.add(evidence_id)
        statement = _text(item["statement"], "statement")
        result.append(
            {
                "evidenceRefId": evidence_id,
                "kind": _text(item["kind"], "kind"),
                "statement": statement,
                "sha256": _sha256(statement),
            }
        )
    return result


def _work_shape(
    value: Any, *, evidence_ids: set[str], default_evidence: str
) -> dict[str, Any]:
    if type(value) is not dict or set(value) != set(_WORK_SHAPE_FIELDS):
        _fail("workShape имеет неверные поля")
    return {
        name: _claim_value(
            value[name],
            evidence_ids=evidence_ids,
            default_evidence=default_evidence,
            expected=int,
            label=f"workShape.{name}",
        )
        for name in _WORK_SHAPE_FIELDS
    }


def _claim_value(
    value: Any,
    *,
    evidence_ids: set[str],
    default_evidence: str,
    expected: type,
    label: str,
) -> dict[str, Any]:
    if type(value) is expected:
        raw_value = value
        refs = [default_evidence]
    elif type(value) is dict and set(value) == {"value", "evidenceRefIds"}:
        raw_value = value["value"]
        refs = value["evidenceRefIds"]
    else:
        _fail(f"{label} имеет неверный вид")
    if type(raw_value) is not expected or (expected is int and raw_value < 0):
        _fail(f"{label}.value имеет неверный тип или диапазон")
    _evidence_refs(refs, evidence_ids=evidence_ids, label=label)
    return {"value": raw_value, "evidenceRefIds": copy.deepcopy(refs)}


def _factor_claims(
    base: Mapping[str, Any],
    overrides: Any,
    *,
    evidence_ids: set[str],
    default_evidence: str,
) -> dict[str, Any]:
    result = copy.deepcopy(dict(base))
    for group in result.values():
        for claim in group.values():
            claim["state"] = "unknown"
            claim["evidenceRefIds"] = [default_evidence]
    if overrides is None:
        return result
    if type(overrides) is not dict:
        _fail("factorClaims должен быть объектом")
    for group_name, claims in overrides.items():
        if group_name not in result or type(claims) is not dict:
            _fail(f"неизвестная группа factorClaims: {group_name}")
        for claim_name, value in claims.items():
            if claim_name not in result[group_name]:
                _fail(f"неизвестный factorClaim: {claim_name}")
            if type(value) is str:
                state, refs = value, [default_evidence]
            elif type(value) is dict and set(value) == {"state", "evidenceRefIds"}:
                state, refs = value["state"], value["evidenceRefIds"]
            else:
                _fail(f"factorClaim {claim_name} имеет неверный вид")
            if state not in {"true", "false", "unknown"}:
                _fail(f"factorClaim {claim_name} имеет неверное состояние")
            _evidence_refs(refs, evidence_ids=evidence_ids, label=claim_name)
            result[group_name][claim_name] = {
                "state": state,
                "evidenceRefIds": copy.deepcopy(refs),
            }
    return result


def _context_bundle(
    value: Any,
    *,
    evidence: list[dict[str, Any]],
    bundle_id: str,
    requested_max: Any,
) -> dict[str, Any]:
    if type(value) is not list or not value:
        _fail("contextEntries должен быть непустым массивом")
    by_id = {item["evidenceRefId"]: item for item in evidence}
    entries: list[dict[str, Any]] = []
    known: set[str] = set()
    for index, item in enumerate(value):
        if type(item) is not dict or set(item) != {
            "contextRefId",
            "kind",
            "evidenceRefIds",
            "content",
        }:
            _fail(f"contextEntries[{index}] имеет неверные поля")
        context_id = _text(item["contextRefId"], "contextRefId")
        if context_id in known:
            _fail(f"повторный contextRefId: {context_id}")
        known.add(context_id)
        refs = item["evidenceRefIds"]
        _evidence_refs(refs, evidence_ids=set(by_id), label=context_id)
        content = _text(item["content"], "content")
        encoded = content.encode("utf-8")
        entries.append(
            {
                "contextRefId": context_id,
                "kind": _text(item["kind"], "kind"),
                "required": True,
                "sourceEvidenceRefs": [
                    {
                        "evidenceRefId": ref,
                        "evidenceSha256": by_id[ref]["sha256"],
                    }
                    for ref in refs
                ],
                "sha256": hashlib.sha256(encoded).hexdigest(),
                "byteLength": len(encoded),
                "content": content,
            }
        )
    total = sum(item["byteLength"] for item in entries)
    if requested_max is None:
        maximum = total
    elif type(requested_max) is int and requested_max >= total:
        maximum = requested_max
    else:
        _fail("maxBytes должен быть целым числом не меньше totalBytes")
    return {
        "schemaVersion": 1,
        "contractVersion": "codex-context-bundle-v1",
        "bundleId": bundle_id,
        "maxBytes": maximum,
        "totalBytes": total,
        "entries": entries,
    }


def _evidence_refs(value: Any, *, evidence_ids: set[str], label: str) -> None:
    if (
        type(value) is not list
        or not value
        or len(set(value)) != len(value)
        or any(type(item) is not str or item not in evidence_ids for item in value)
    ):
        _fail(f"{label}.evidenceRefIds содержит неверные ссылки")


def _text(value: Any, label: str) -> str:
    if type(value) is not str or not value:
        _fail(f"{label} должен быть непустой строкой")
    return value


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _fail(message: str) -> None:
    raise PlanInputBuilderV2Error(message)
