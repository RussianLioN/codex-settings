from __future__ import annotations

from typing import Any


def valid_plan(catalog: Any | None = None) -> dict[str, object]:
    plan: dict[str, object] = {
        "schemaVersion": "1",
        "turnBinding": "tb1_" + "A" * 43,
        "requestKey": "request-0001",
        "catalogGeneration": "cg1_" + "a" * 16,
        "nodes": [
            {
                "clientNodeId": "node-1",
                "mission": "Проверить структуру репозитория.",
                "role": "researcher",
                "dependencyIds": [],
                "contextRefs": [],
                "scopeId": "scope_default",
                "artifactProfileId": "artifact_report",
                "validationProfileId": "validation_none",
                "assessment": {
                    "delegation": {
                        "q": {"min": 1, "max": 2},
                        "p": {"min": 0, "max": 1},
                        "v": {"min": 2, "max": 2},
                        "o": {"min": 0, "max": 1},
                    },
                    "complexity": {
                        "ambiguity": 0,
                        "dependencyDepth": 0,
                        "breadth": 1,
                        "novelty": 0,
                        "harm": 0,
                        "crossDomain": 0,
                    },
                    "reasoning": {
                        "evidence": 1,
                        "verification": 1,
                        "harm": 0,
                    },
                },
                "riskFlags": [],
            }
        ],
    }
    if catalog is not None:
        node = plan["nodes"][0]  # type: ignore[index]
        node["scopeId"] = catalog.opaque_id("scope", "default")
        node["artifactProfileId"] = catalog.opaque_id(
            "artifact",
            "report",
        )
        node["validationProfileId"] = catalog.opaque_id(
            "validation",
            "none",
        )
    return plan
