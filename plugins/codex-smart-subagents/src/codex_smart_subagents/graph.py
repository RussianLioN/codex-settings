"""Validation for bounded adaptive-subagent task graphs."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass


ALLOWED_ROLES = frozenset(
    {
        "researcher",
        "diagnostician",
        "implementer",
        "validator",
        "risk_auditor",
    }
)


@dataclass(frozen=True)
class GraphError(ValueError):
    code: str
    message: str

    def __str__(self) -> str:
        return f"{self.code}: {self.message}"


@dataclass(frozen=True)
class TaskNode:
    node_id: str
    role: str
    dependencies: tuple[str, ...] = ()


@dataclass(frozen=True)
class ValidatedGraph:
    order: tuple[str, ...]
    depth: int
    edge_count: int
    writer_id: str | None


def validate_graph(
    nodes: list[TaskNode],
    *,
    split_generation: int = 0,
    max_nodes: int = 20,
    max_edges: int = 60,
    max_depth: int = 4,
) -> ValidatedGraph:
    """Validate graph shape, acyclicity, depth, and the single-writer contract."""

    if split_generation not in range(3):
        raise GraphError(
            "SPLIT_GENERATION_EXCEEDED",
            "split generation must be in 0..2",
        )
    if not nodes:
        raise GraphError("EMPTY_GRAPH", "at least one node is required")
    if len(nodes) > max_nodes:
        raise GraphError(
            "TOO_MANY_NODES",
            f"graph has {len(nodes)} nodes; maximum is {max_nodes}",
        )

    by_id: dict[str, TaskNode] = {}
    for node in nodes:
        if node.node_id in by_id:
            raise GraphError("DUPLICATE_NODE", f"duplicate node: {node.node_id}")
        if node.role not in ALLOWED_ROLES:
            raise GraphError("UNKNOWN_ROLE", f"unsupported role: {node.role}")
        if len(node.dependencies) != len(set(node.dependencies)):
            raise GraphError(
                "DUPLICATE_DEPENDENCY",
                f"node {node.node_id} repeats a dependency",
            )
        by_id[node.node_id] = node

    edge_count = sum(len(node.dependencies) for node in nodes)
    if edge_count > max_edges:
        raise GraphError(
            "TOO_MANY_EDGES",
            f"graph has {edge_count} edges; maximum is {max_edges}",
        )

    outgoing: dict[str, list[str]] = defaultdict(list)
    indegree = {node.node_id: len(node.dependencies) for node in nodes}
    for node in nodes:
        for dependency in node.dependencies:
            if dependency == node.node_id:
                raise GraphError(
                    "SELF_DEPENDENCY",
                    f"node {node.node_id} depends on itself",
                )
            if dependency not in by_id:
                raise GraphError(
                    "UNKNOWN_DEPENDENCY",
                    f"node {node.node_id} depends on unknown node {dependency}",
                )
            outgoing[dependency].append(node.node_id)

    ready = deque(
        node.node_id for node in nodes if indegree[node.node_id] == 0
    )
    order: list[str] = []
    depth_by_id: dict[str, int] = {}
    while ready:
        node_id = ready.popleft()
        node = by_id[node_id]
        depth_by_id[node_id] = (
            0
            if not node.dependencies
            else 1 + max(depth_by_id[dependency] for dependency in node.dependencies)
        )
        order.append(node_id)
        for child in outgoing[node_id]:
            indegree[child] -= 1
            if indegree[child] == 0:
                ready.append(child)

    if len(order) != len(nodes):
        raise GraphError("GRAPH_CYCLE", "graph contains a dependency cycle")

    graph_depth = max(depth_by_id.values(), default=0)
    if graph_depth > max_depth:
        raise GraphError(
            "GRAPH_TOO_DEEP",
            f"graph depth is {graph_depth}; maximum is {max_depth}",
        )

    writers = [node for node in nodes if node.role == "implementer"]
    if len(writers) > 1:
        raise GraphError("MULTIPLE_WRITERS", "only one writer is allowed")

    writer_id: str | None = None
    if writers:
        writer = writers[0]
        writer_id = writer.node_id
        if outgoing[writer.node_id]:
            raise GraphError(
                "WRITER_NOT_SINK",
                "the writer must be a final sink",
            )
        ancestors = _ancestors(writer.node_id, by_id)
        readers = set(by_id) - {writer.node_id}
        missing = readers - ancestors
        if missing:
            raise GraphError(
                "WRITER_MISSING_READER_DEPENDENCY",
                "writer does not depend on all readers: "
                + ", ".join(sorted(missing)),
            )

    return ValidatedGraph(
        order=tuple(order),
        depth=graph_depth,
        edge_count=edge_count,
        writer_id=writer_id,
    )


def _ancestors(node_id: str, by_id: dict[str, TaskNode]) -> set[str]:
    result: set[str] = set()
    pending = list(by_id[node_id].dependencies)
    while pending:
        dependency = pending.pop()
        if dependency in result:
            continue
        result.add(dependency)
        pending.extend(by_id[dependency].dependencies)
    return result

