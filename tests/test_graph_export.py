import json
from pathlib import Path
import pytest
from snapshot import load_snapshot
from analysis import build_attack_graph
from graph_export import graph_to_json
from iam_models import EffectivePermission


@pytest.fixture
def sample_graph():
    path = Path("snapshots/sample_lab.json")
    inv, pm, _ = load_snapshot(path)
    return build_attack_graph(inv, pm)


def test_graph_export_modes(sample_graph):
    full_data = graph_to_json(sample_graph, mode="full")
    attack_data = graph_to_json(sample_graph, mode="attack")

    # Both must dump cleanly to JSON
    json_full = json.dumps(full_data)
    json_attack = json.dumps(attack_data)
    assert len(json_full) > 0
    assert len(json_attack) > 0

    # Full graph node types: User, Group, Role, Policy, Service
    full_types = {n["type"] for n in full_data["nodes"]}
    assert {"User", "Group", "Role", "Policy", "Service"} <= full_types

    # Full graph edge types: member-of, attached-policy, trusted-to-assume, can-assume
    full_edge_types = {e["type"] for e in full_data["edges"]}
    assert {"member-of", "attached-policy", "trusted-to-assume", "can-assume"} <= full_edge_types

    # Attack graph has only User and Role nodes
    attack_types = {n["type"] for n in attack_data["nodes"]}
    assert attack_types <= {"User", "Role"}
    assert len(attack_data["edges"]) == 5
    assert all(e["type"] == "can-assume" for e in attack_data["edges"])

    # Every edge endpoint exists in nodes
    full_node_ids = {n["id"] for n in full_data["nodes"]}
    for e in full_data["edges"]:
        assert e["from"] in full_node_ids
        assert e["to"] in full_node_ids

    attack_node_ids = {n["id"] for n in attack_data["nodes"]}
    for e in attack_data["edges"]:
        assert e["from"] in attack_node_ids
        assert e["to"] in attack_node_ids


def test_graph_export_unknown_mode_raises(sample_graph):
    with pytest.raises(ValueError, match="Unknown mode"):
        graph_to_json(sample_graph, mode="invalid_mode")


def test_graph_export_never_mutates_input_graph(sample_graph):
    nodes_before = list(sample_graph.nodes(data=True))
    edges_before = list(sample_graph.edges(keys=True, data=True))

    graph_to_json(sample_graph, mode="full")
    graph_to_json(sample_graph, mode="attack")

    assert list(sample_graph.nodes(data=True)) == nodes_before
    assert list(sample_graph.edges(keys=True, data=True)) == edges_before


def test_graph_export_serializes_with_complex_evidence(sample_graph):
    # Add an edge with non-serializable dataclass in evidence
    perm = EffectivePermission(
        identity_arn="arn:aws:iam::123456789012:user/testuser",
        action="sts:AssumeRole",
        resource="*",
        via=["p1"],
    )
    sample_graph.add_edge(
        "arn:aws:iam::123456789012:user/testuser",
        "arn:aws:iam::123456789012:role/testrole",
        key="test-evidence",
        type="test-evidence",
        evidence=[perm],
    )
    # Evidence must never be copied, json.dumps must succeed
    data = graph_to_json(sample_graph, mode="full")
    dumped = json.dumps(data)
    assert "test-evidence" in dumped

