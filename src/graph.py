import networkx as nx


def classify_node_type(identifier):
    """Classifies an identifier into 'Service', 'Policy', 'Wildcard', or 'External'. Never raises."""
    if not isinstance(identifier, str):
        return "External"
    if identifier == "*":
        return "Wildcard"
    if not identifier.startswith("arn:") and (
        identifier.endswith(".amazonaws.com") or identifier.endswith(".amazonaws.com.cn")
    ):
        return "Service"
    if identifier.startswith("arn:"):
        parts = identifier.split(":")
        if len(parts) >= 6 and parts[2] == "iam" and parts[5].startswith("policy/"):
            return "Policy"
    return "External"


def build_graph(inventory):
    graph = nx.MultiDiGraph()

    for user in inventory.users:
        graph.add_node(user.arn, type="User", name=user.name)
    for group in inventory.groups:
        graph.add_node(group.arn, type="Group", name=group.name)
    for role in inventory.roles:
        graph.add_node(role.arn, type="Role", name=role.name)
    for policy in inventory.policies:
        graph.add_node(policy.arn, type="Policy", name=policy.name)

    for relationship in inventory.relationships:
        if relationship.source not in graph.nodes():
            graph.add_node(
                relationship.source,
                type=classify_node_type(relationship.source),
                name=relationship.source,
            )
        if relationship.target not in graph.nodes():
            graph.add_node(
                relationship.target,
                type=classify_node_type(relationship.target),
                name=relationship.target,
            )
        graph.add_edge(
            relationship.source,
            relationship.target,
            key=relationship.relationship,
            type=relationship.relationship,
        )

    return graph
