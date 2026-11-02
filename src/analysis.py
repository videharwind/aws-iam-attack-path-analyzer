from attack_path import attack_view, find_reachable
from assume_role import find_can_assume
from graph import build_graph


def build_attack_graph(inventory, permission_map):
    """Builds the full graph, computes can-assume edges, adds them, and returns the full MultiDiGraph."""
    graph = build_graph(inventory)
    edges = find_can_assume(inventory, permission_map)
    # add_can_assume_edges directly in graph
    for edge in edges:
        if edge.source not in graph or edge.target not in graph:
            raise ValueError(
                f"can-assume edge reference unknown identity: {edge.source} -> {edge.target}"
            )
    for edge in edges:
        graph.add_edge(
            edge.source,
            edge.target,
            key="can-assume",
            type="can-assume",
            reason=edge.reason,
            evidence=edge.evidence,
        )
    return graph


def describe_path(graph, path):
    """Returns a list of {'from', 'to', 'reason'} dicts for consecutive nodes in path.
    Raises ValueError if any consecutive pair is not an attack-view edge."""
    view = attack_view(graph)
    descriptions = []
    for u, v in zip(path[:-1], path[1:]):
        if not view.has_edge(u, v, key="can-assume"):
            raise ValueError(f"Path step {u} -> {v} is not a valid can-assume attack edge")
        edge_data = view.edges[u, v, "can-assume"]
        descriptions.append({
            "from": u,
            "to": v,
            "reason": edge_data.get("reason", ""),
        })
    return descriptions


def reachable_report(graph, source_arn, max_hops=None):
    """Finds reachable roles/users from source_arn, returning list of path report dicts sorted by (hops, name)."""
    reachable_paths = find_reachable(graph, source_arn, max_hops=max_hops)
    report = []
    for target_arn, path in reachable_paths.items():
        node_data = graph.nodes.get(target_arn, {})
        target_name = node_data.get("name", target_arn.split("/")[-1])
        target_type = node_data.get("type", "Role")
        hops = len(path) - 1

        path_names = [graph.nodes.get(n, {}).get("name", n.split("/")[-1]) for n in path]
        hop_reasons = [step["reason"] for step in describe_path(graph, path)]

        report.append({
            "target": target_arn,
            "name": target_name,
            "type": target_type,
            "hops": hops,
            "path": path,
            "path_names": path_names,
            "hop_reasons": hop_reasons,
        })

    report.sort(key=lambda r: (r["hops"], r["name"]))
    return report


def list_identities(graph):
    """Returns list of {'arn', 'name', 'type'} for User and Role nodes sorted by (type, name)."""
    identities = []
    for node_id, data in graph.nodes(data=True):
        node_type = data.get("type")
        if node_type in ("User", "Role"):
            identities.append({
                "arn": node_id,
                "name": data.get("name", node_id.split("/")[-1]),
                "type": node_type,
            })
    identities.sort(key=lambda item: (item["type"], item["name"]))
    return identities


def summarize(inventory, graph):
    """Returns summary counts: users, groups, roles, policies, can_assume_edges."""
    can_assume_count = sum(1 for _, _, k in graph.edges(keys=True) if k == "can-assume")
    return {
        "users": len(inventory.users),
        "groups": len(inventory.groups),
        "roles": len(inventory.roles),
        "policies": len(inventory.policies),
        "can_assume_edges": can_assume_count,
    }


