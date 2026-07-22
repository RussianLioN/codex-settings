"""Чтение узловых данных из сохранённого многоузлового плана версии 2."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any, Mapping


@dataclass
class PlanProjectionV2Error(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


def node_routing_input_v2(
    plan_output: Mapping[str, Any],
    node_id: str,
) -> dict[str, Any]:
    """Возвращает ровно тот routingInput, который принадлежит указанному узлу."""

    if type(plan_output) is not dict or type(plan_output.get("nodes")) is not list:
        raise PlanProjectionV2Error(
            "ROUTE_PLAN_NODE_INPUT_MISSING",
            "сохранённый план не содержит узловых входов маршрутизации",
        )
    matches = [
        item
        for item in plan_output["nodes"]
        if type(item) is dict and item.get("nodeId") == node_id
    ]
    if len(matches) != 1 or type(matches[0].get("routingInput")) is not dict:
        raise PlanProjectionV2Error(
            "ROUTE_PLAN_NODE_INPUT_MISSING",
            "для узла не найден ровно один routingInput",
        )
    return copy.deepcopy(matches[0]["routingInput"])


__all__ = ["PlanProjectionV2Error", "node_routing_input_v2"]
