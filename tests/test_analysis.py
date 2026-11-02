import pytest
from pathlib import Path
from snapshot import load_snapshot
from analysis import (
    build_attack_graph,
    describe_path,
    reachable_report,
    list_identities,
    summarize,
)
from attack_path import attack_view


@pytest.fixture
def sample_data():
    path = Path("snapshots/sample_lab.json")
    inv, pm, _ = load_snapshot(path)
    graph = build_attack_graph(inv, pm)
    return inv, pm, graph


def test_summarize_sample(sample_data):
    inv, pm, graph = sample_data
    summary = summarize(inv, graph)
    assert summary == {
        "users": 2,
        "groups": 1,
        "roles": 5,
        "policies": 3,
        "can_assume_edges": 5,
    }


def test_list_identities_sample(sample_data):
    _, _, graph = sample_data
    identities = list_identities(graph)
    assert len(identities) == 7
    # sorted by (type, name) -> Role then User
    roles = [i for i in identities if i["type"] == "Role"]
    users = [i for i in identities if i["type"] == "User"]
    assert len(roles) == 5
    assert len(users) == 2
    assert [r["name"] for r in roles] == ["testrole", "testrole2", "testrole3", "testrole4", "testrole5"]
    assert [u["name"] for u in users] == ["testuser", "testuser2"]


def test_reachable_report_diamond(sample_data):
    _, _, graph = sample_data
    u2 = "arn:aws:iam::123456789012:user/testuser2"
    r3 = "arn:aws:iam::123456789012:role/testrole3"
    r4 = "arn:aws:iam::123456789012:role/testrole4"
    r5 = "arn:aws:iam::123456789012:role/testrole5"

    report = reachable_report(graph, u2)
    assert len(report) == 3

    # Sorted by (hops, name): hops 1 (testrole3, testrole4), hops 2 (testrole5)
    assert report[0]["target"] == r3
    assert report[0]["hops"] == 1
    assert report[0]["path"] == [u2, r3]
    assert report[0]["path_names"] == ["testuser2", "testrole3"]
    assert report[0]["hop_reasons"] == ["direct-trust"]

    assert report[1]["target"] == r4
    assert report[1]["hops"] == 1
    assert report[1]["path"] == [u2, r4]

    assert report[2]["target"] == r5
    assert report[2]["hops"] == 2
    assert report[2]["path"][0] == u2
    assert report[2]["path"][-1] == r5
    assert report[2]["hop_reasons"] == ["direct-trust", "direct-trust"]


def test_reachable_report_max_hops(sample_data):
    _, _, graph = sample_data
    u2 = "arn:aws:iam::123456789012:user/testuser2"
    report_1 = reachable_report(graph, u2, max_hops=1)
    assert len(report_1) == 2
    assert {r["name"] for r in report_1} == {"testrole3", "testrole4"}


def test_reachable_report_unknown_source_raises(sample_data):
    _, _, graph = sample_data
    with pytest.raises(ValueError):
        reachable_report(graph, "arn:aws:iam::123456789012:user/ghost")


def test_describe_path_success_and_invalid(sample_data):
    _, _, graph = sample_data
    u2 = "arn:aws:iam::123456789012:user/testuser2"
    r3 = "arn:aws:iam::123456789012:role/testrole3"
    r5 = "arn:aws:iam::123456789012:role/testrole5"

    steps = describe_path(graph, [u2, r3, r5])
    assert len(steps) == 2
    assert steps[0] == {"from": u2, "to": r3, "reason": "direct-trust"}
    assert steps[1] == {"from": r3, "to": r5, "reason": "direct-trust"}

    # Invalid consecutive step (no can-assume edge u2 -> r5 directly)
    with pytest.raises(ValueError, match="is not a valid can-assume attack edge"):
        describe_path(graph, [u2, r5])


def test_analysis_functions_do_not_mutate_graph(sample_data):
    _, _, graph = sample_data
    nodes_before = list(graph.nodes(data=True))
    edges_before = list(graph.edges(keys=True, data=True))

    u2 = "arn:aws:iam::123456789012:user/testuser2"
    list_identities(graph)
    reachable_report(graph, u2)
    describe_path(graph, [u2, "arn:aws:iam::123456789012:role/testrole3"])

    assert list(graph.nodes(data=True)) == nodes_before
    assert list(graph.edges(keys=True, data=True)) == edges_before



