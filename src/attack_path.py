import networkx as nx

TRAVERSABLE_EDGE_TYPES = frozenset({"can-assume"})


def add_can_assume_edges(graph, can_assume_edges):
    """Validates all edges first, then adds them; modifies the graph in place and returns it; raises ValueError and adds nothing if any endpoint is unknown."""
    for edge in can_assume_edges:
        if edge.source not in graph or edge.target not in graph:
            raise ValueError(
                f"can-assume edge reference unknown identity: "
                f"{edge.source} -> {edge.target}"
            )
    for edge in can_assume_edges:
        graph.add_edge(
            edge.source,
            edge.target,
            key="can-assume",
            type="can-assume",
            reason=edge.reason,
            evidence=edge.evidence,
        )
    return graph


def attack_view(graph):
    """Returns a read-only subgraph view containing only User and Role nodes and traversable attack edges."""
    def filter_node(n):
        return graph.nodes[n].get("type") in ("User", "Role")

    def filter_edge(source, target, key):
        return key in TRAVERSABLE_EDGE_TYPES

    view = nx.subgraph_view(
        graph,
        filter_node=filter_node,
        filter_edge=filter_edge,
    )
    return view


def find_reachable(graph, source_arn, max_hops=None):
    """Finds shortest path per target; which of two equal-length paths is returned is not guaranteed; only the attack view is searched; cycles are safe; returns {target_arn: [source, ..., target]}, source excluded, {} when nothing reachable."""
    if max_hops is not None and max_hops < 0:
        raise ValueError(f"max_hops cannot be negative: {max_hops}")
    view = attack_view(graph)
    if source_arn not in view:
        raise ValueError(f"{source_arn} is not a user or role in the graph")
    reachables = nx.single_source_shortest_path(view, source_arn, cutoff=max_hops)
    reachables.pop(source_arn)
    return reachables
