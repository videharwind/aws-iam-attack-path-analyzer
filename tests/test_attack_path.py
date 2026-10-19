import networkx as nx
import pytest

from iam_models import (
    IAMUser,
    IAMGroup,
    IAMRole,
    IAMPolicy,
    IAMInventory,
    IAMRelationship,
    CanAssumeEdge,
    EffectivePermission,
)
from graph import build_graph
from attack_path import (
    TRAVERSABLE_EDGE_TYPES,
    add_can_assume_edges,
    attack_view,
)


BASE = "arn:aws:iam::123456789012:"


def U(name):
    return f"{BASE}user/{name}"


def R(name):
    return f"{BASE}role/{name}"


GROUP = f"{BASE}group/testgroup"
POLICY = f"{BASE}policy/testpolicy"
SERVICE = "ec2.amazonaws.com"

LAB_USERS = ["testuser", "testuser2"]
LAB_ROLES = ["testrole", "testrole2", "testrole3", "testrole4", "testrole5"]

# The five edges the live lab should produce.
LAB_PAIRS = [
    (U("testuser"), R("testrole")),
    (U("testuser2"), R("testrole3")),
    (U("testuser2"), R("testrole4")),
    (R("testrole3"), R("testrole5")),
    (R("testrole4"), R("testrole5")),
]


# ---------- helpers ----------

def trust(source, target):
    return IAMRelationship(
        source=source, relationship="trusted-to-assume", target=target
    )


def can_assume(source, target, reason="direct-trust", evidence=None):
    return CanAssumeEdge(
        source=source,
        target=target,
        reason=reason,
        evidence=evidence if evidence is not None else [],
    )


def make_inventory(users=(), roles=(), groups=(), policies=(), relationships=()):
    return IAMInventory(
        users=[IAMUser(name=n, id=f"{n}-id", arn=U(n)) for n in users],
        groups=[IAMGroup(name=n, id=f"{n}-id", arn=f"{BASE}group/{n}") for n in groups],
        roles=[IAMRole(name=n, id=f"{n}-id", arn=R(n), trust_policy={}) for n in roles],
        policies=[IAMPolicy(name=n, arn=f"{BASE}policy/{n}", id=f"{n}-id") for n in policies],
        relationships=list(relationships),
    )


def make_graph(users=(), roles=(), pairs=(), **kwargs):
    """Build the Session 7 graph, then add can-assume edges for the given pairs."""
    graph = build_graph(make_inventory(users, roles, **kwargs))
    add_can_assume_edges(graph, [can_assume(s, t) for s, t in pairs])
    return graph


def lab_inventory():
    """Lab-shaped inventory: trust edges, a service trust, a group and a policy."""
    relationships = [
        trust(U("testuser"), R("testrole")),
        trust(U("testuser2"), R("testrole3")),
        trust(U("testuser2"), R("testrole4")),
        trust(R("testrole3"), R("testrole5")),
        trust(R("testrole4"), R("testrole5")),
        trust(SERVICE, R("testrole2")),
        IAMRelationship(
            source=U("testuser"), relationship="member-of", target=GROUP
        ),
        IAMRelationship(
            source=GROUP, relationship="attached-policy", target=POLICY
        ),
    ]
    return make_inventory(
        users=LAB_USERS,
        roles=LAB_ROLES,
        groups=["testgroup"],
        policies=["testpolicy"],
        relationships=relationships,
    )


def lab_graph():
    graph = build_graph(lab_inventory())
    add_can_assume_edges(graph, [can_assume(s, t) for s, t in LAB_PAIRS])
    return graph


def keyed_edge_count(graph, key):
    return sum(1 for _, _, k in graph.edges(keys=True) if k == key)


# ---------- constant ----------

def test_allowlist_contains_can_assume():
    assert "can-assume" in TRAVERSABLE_EDGE_TYPES


# ---------- adding edges ----------

# 1
def test_single_edge_has_key_and_attributes():
    permission = EffectivePermission(
        identity_arn=U("u"),
        action="sts:AssumeRole",
        resource=R("r"),
        via=[],
    )
    graph = make_graph(["u"], ["r"])
    add_can_assume_edges(
        graph,
        [can_assume(U("u"), R("r"), "trust-and-permission", [permission])],
    )

    data = graph.edges[U("u"), R("r"), "can-assume"]
    assert data["type"] == "can-assume"
    assert data["reason"] == "trust-and-permission"
    assert data["evidence"] == [permission]


# 2
def test_lab_shape_adds_exactly_five_edges_and_keeps_originals():
    graph = build_graph(lab_inventory())
    before_total = graph.number_of_edges()
    before_trust = keyed_edge_count(graph, "trusted-to-assume")

    add_can_assume_edges(graph, [can_assume(s, t) for s, t in LAB_PAIRS])

    assert keyed_edge_count(graph, "can-assume") == 5
    assert graph.number_of_edges() == before_total + 5
    assert keyed_edge_count(graph, "trusted-to-assume") == before_trust


# 3
def test_trust_and_can_assume_coexist_on_same_pair():
    graph = build_graph(
        make_inventory(["u"], ["r"], relationships=[trust(U("u"), R("r"))])
    )
    add_can_assume_edges(graph, [can_assume(U("u"), R("r"))])

    assert graph.number_of_edges(U("u"), R("r")) == 2
    assert graph.has_edge(U("u"), R("r"), key="trusted-to-assume")
    assert graph.has_edge(U("u"), R("r"), key="can-assume")


# 4
def test_adding_same_edge_twice_does_not_duplicate():
    graph = make_graph(["u"], ["r"])
    edge = can_assume(U("u"), R("r"))

    add_can_assume_edges(graph, [edge])
    add_can_assume_edges(graph, [edge])

    assert keyed_edge_count(graph, "can-assume") == 1
    assert graph.number_of_edges(U("u"), R("r")) == 1


# 5a
def test_unknown_source_raises():
    graph = make_graph(["u"], ["r"])
    with pytest.raises(ValueError):
        add_can_assume_edges(graph, [can_assume(U("ghost"), R("r"))])


# 5b
def test_unknown_target_raises():
    graph = make_graph(["u"], ["r"])
    with pytest.raises(ValueError):
        add_can_assume_edges(graph, [can_assume(U("u"), R("ghost"))])


# 5c: a bad edge must not create a bare node
def test_unknown_endpoint_does_not_create_node():
    graph = make_graph(["u"], ["r"])
    nodes_before = set(graph.nodes)

    with pytest.raises(ValueError):
        add_can_assume_edges(graph, [can_assume(U("u"), R("ghost"))])

    assert set(graph.nodes) == nodes_before


# 6
def test_bad_edge_after_good_edge_adds_nothing():
    graph = make_graph(["u"], ["r"])
    edges_before = graph.number_of_edges()

    with pytest.raises(ValueError):
        add_can_assume_edges(
            graph,
            [can_assume(U("u"), R("r")), can_assume(U("u"), R("ghost"))],
        )

    assert not graph.has_edge(U("u"), R("r"), key="can-assume")
    assert graph.number_of_edges() == edges_before


# 7
def test_empty_list_leaves_graph_unchanged():
    graph = build_graph(lab_inventory())
    nodes_before = set(graph.nodes)
    edges_before = set(graph.edges(keys=True))

    add_can_assume_edges(graph, [])

    assert set(graph.nodes) == nodes_before
    assert set(graph.edges(keys=True)) == edges_before


# ---------- the attack view ----------

# 8
def test_view_contains_only_users_and_roles():
    graph = lab_graph()

    # make sure the full graph really does contain the other kinds
    full_types = {graph.nodes[n]["type"] for n in graph}
    assert {"Group", "Policy", "Service"} <= full_types

    view = attack_view(graph)
    view_types = {view.nodes[n]["type"] for n in view}
    assert view_types == {"User", "Role"}
    assert GROUP not in view
    assert POLICY not in view
    assert SERVICE not in view


# 9: the key design test
def test_trust_only_pair_is_invisible_in_view():
    graph = build_graph(
        make_inventory(["u"], ["r"], relationships=[trust(U("u"), R("r"))])
    )

    assert graph.has_edge(U("u"), R("r"), key="trusted-to-assume")

    view = attack_view(graph)
    assert not view.has_edge(U("u"), R("r"))
    assert view.number_of_edges() == 0
    assert not nx.has_path(view, U("u"), R("r"))


# 9b: and once can-assume is added, the pair becomes visible
def test_pair_becomes_visible_once_can_assume_is_added():
    graph = build_graph(
        make_inventory(["u"], ["r"], relationships=[trust(U("u"), R("r"))])
    )
    add_can_assume_edges(graph, [can_assume(U("u"), R("r"))])

    view = attack_view(graph)
    assert view.has_edge(U("u"), R("r"), key="can-assume")
    assert not view.has_edge(U("u"), R("r"), key="trusted-to-assume")
    assert nx.has_path(view, U("u"), R("r"))


# 10
def test_direction_and_diamond_paths_survive_in_view():
    view = attack_view(lab_graph())

    assert nx.has_path(view, U("testuser2"), R("testrole5"))      # diamond
    assert not nx.has_path(view, R("testrole5"), U("testuser2"))  # reverse
    assert not nx.has_path(view, U("testuser"), R("testrole5"))   # wrong start


# 10b: the lab view holds exactly the five expected edges
def test_lab_view_has_exactly_the_five_edges():
    view = attack_view(lab_graph())

    assert {(s, t) for s, t, _ in view.edges(keys=True)} == set(LAB_PAIRS)
    assert view.number_of_edges() == 5


# 11
def test_edge_key_outside_allowlist_is_not_in_view():
    graph = make_graph(["u"], ["r"])
    graph.add_edge(U("u"), R("r"), key="made-up-edge", type="made-up-edge")

    view = attack_view(graph)

    assert graph.has_edge(U("u"), R("r"), key="made-up-edge")
    assert not view.has_edge(U("u"), R("r"))
    assert view.number_of_edges() == 0


# 12a
def test_view_counts_match_the_filtered_full_graph():
    graph = lab_graph()
    view = attack_view(graph)

    expected_nodes = {
        n for n in graph if graph.nodes[n]["type"] in ("User", "Role")
    }
    expected_edges = {
        (s, t, k)
        for s, t, k in graph.edges(keys=True)
        if k in TRAVERSABLE_EDGE_TYPES
        and s in expected_nodes
        and t in expected_nodes
    }

    assert set(view.nodes) == expected_nodes
    assert set(view.edges(keys=True)) == expected_edges


# 12b: a view is a window onto the graph, not a copy
def test_view_reflects_edges_added_after_it_was_created():
    graph = make_graph(["u"], ["r"])
    view = attack_view(graph)
    assert view.number_of_edges() == 0

    add_can_assume_edges(graph, [can_assume(U("u"), R("r"))])

    assert view.number_of_edges() == 1
    assert view.has_edge(U("u"), R("r"), key="can-assume")


# 12c: the view is read-only
def test_view_is_read_only():
    view = attack_view(lab_graph())
    with pytest.raises(nx.NetworkXError):
        view.add_edge(U("testuser"), R("testrole5"), key="can-assume")