from __future__ import annotations

import hashlib

from faultloom_protocol import ActionIntent, MissingLink, SCHEMA_VERSION

from .contracts import GraphComponent
from .search_core import reachable_capability_ids
from .search_state import ChainRuntime, SearchEnvironment


def graph_components(runtime: ChainRuntime) -> tuple[GraphComponent, ...]:
    """Return deterministic SCCs without recursion or a depth ceiling."""

    nodes = tuple(sorted(runtime.index.capabilities))
    adjacency = {node: [] for node in nodes}
    reverse = {node: [] for node in nodes}
    for edge in sorted(runtime.index.edges.values(), key=lambda item: item.edge_id):
        adjacency[edge.source_capability_id].append(edge.target_capability_id)
        reverse[edge.target_capability_id].append(edge.source_capability_id)
    order: list[str] = []
    seen: set[str] = set()
    for root in nodes:
        if root in seen:
            continue
        stack = [(root, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                order.append(node)
                continue
            if node in seen:
                continue
            seen.add(node)
            stack.append((node, True))
            stack.extend(
                (child, False)
                for child in reversed(sorted(adjacency[node]))
                if child not in seen
            )
    components: list[GraphComponent] = []
    assigned: set[str] = set()
    for root in reversed(order):
        if root in assigned:
            continue
        members: list[str] = []
        stack = [root]
        assigned.add(root)
        while stack:
            node = stack.pop()
            members.append(node)
            for parent in reversed(sorted(reverse[node])):
                if parent not in assigned:
                    assigned.add(parent)
                    stack.append(parent)
        member_ids = tuple(sorted(members))
        cyclic = len(member_ids) > 1 or any(
            edge.source_capability_id == edge.target_capability_id == member_ids[0]
            for edge in runtime.index.edges.values()
        )
        components.append(
            GraphComponent(capability_ids=member_ids, cyclic=cyclic)
        )
    return tuple(sorted(components, key=lambda item: item.capability_ids))


def missing_links(environment: SearchEnvironment) -> tuple[MissingLink, ...]:
    """Plan one fresh, minimum experiment for each first missing prerequisite."""

    reached = reachable_capability_ids(environment)
    available = set(environment.settings.available_precondition_ids)
    for capability_id in reached:
        available.update(
            environment.runtime.index.capabilities[capability_id].effect_ids
        )
    links: list[MissingLink] = []
    for edge in sorted(
        environment.runtime.index.edges.values(), key=lambda item: item.edge_id
    ):
        if (
            edge.source_capability_id not in reached
            or edge.target_capability_id in reached
        ):
            continue
        target = environment.runtime.index.capabilities[edge.target_capability_id]
        missing = sorted(set(target.precondition_ids).difference(available))
        if not missing:
            continue
        experiment_id = _stable_id("experiment", edge.edge_id, missing[0])
        document = edge.action_intent.model_dump(mode="python")
        document.update(
            action_id=experiment_id,
            parent_action_ids=tuple(
                sorted((*edge.action_intent.parent_action_ids, edge.action_intent.action_id))
            ),
        )
        intent = ActionIntent.model_validate(document)
        links.append(
            MissingLink(
                schema_version=SCHEMA_VERSION,
                missing_link_id=_stable_id("missing-link", edge.edge_id, missing[0]),
                chain_graph_id=environment.runtime.graph.graph_id,
                source_capability_id=edge.source_capability_id,
                target_capability_id=edge.target_capability_id,
                missing_precondition=missing[0],
                minimum_experiment_intent=intent,
                expected_information_gain_bps=edge.confidence_bps,
            )
        )
    return tuple(links)


def _stable_id(prefix: str, edge_id: str, prerequisite_id: str) -> str:
    material = f"{edge_id}\0{prerequisite_id}".encode()
    return f"{prefix}.{hashlib.sha256(material).hexdigest()[:16]}"
