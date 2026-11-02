from attack_path import attack_view


def graph_to_json(graph, mode: str) -> dict:
    """Converts a graph to a JSON-serializable dictionary with 'nodes' and 'edges'.
    Mode must be 'full' or 'attack'. Never copies 'evidence' attributes."""
    if mode == "full":
        source_graph = graph
    elif mode == "attack":
        source_graph = attack_view(graph)
    else:
        raise ValueError(f"Unknown mode '{mode}', expected 'full' or 'attack'")

    nodes = []
    for node_id, data in source_graph.nodes(data=True):
        label = data.get("name") or str(node_id).split("/")[-1]
        node_type = data.get("type", "External")
        nodes.append({
            "id": node_id,
            "label": label,
            "type": node_type,
        })

    edges = []
    for u, v, key, data in source_graph.edges(keys=True, data=True):
        edge_type = data.get("type", key)
        reason = data.get("reason", "") if key == "can-assume" else ""
        edges.append({
            "from": u,
            "to": v,
            "type": edge_type,
            "reason": reason,
        })

    return {"nodes": nodes, "edges": edges}

