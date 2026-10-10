# tests/test_detect_direct_assumerole.py
import networkx as nx
import pytest
from attack_detection import detect_direct_assumerole   # use your module name

def make_graph():
    g = nx.DiGraph()
    g.add_edge("u1", "r1", type="trusted-to-assume")
    g.add_edge("r1", "r2", type="trusted-to-assume")
    g.add_edge("u1", "p1", type="attached-policy")
    g.add_edge("u2", "r1", type="trusted-to-assume")
    g.add_node("lonely")
    return g

def test_positive():
    f = detect_direct_assumerole("u1", {"r1"}, make_graph())
    assert len(f) == 1
    assert f[0] == {"source": "u1", "target": "r1",
                    "via": ["u1", "r1"], "technique": "AssumeRole"}

def test_negative_no_edge():
    assert detect_direct_assumerole("u1", {"r9"}, make_graph()) == []

def test_one_hop_only():
    g = make_graph()
    assert detect_direct_assumerole("u1", {"r2"}, g) == []          # r2 is two hops away
    assert len(detect_direct_assumerole("r1", {"r2"}, g)) == 1      # but one hop from r1

def test_non_trust_edge_ignored():
    # p1 is a successor of u1 via attached-policy, so it must not count
    assert detect_direct_assumerole("u1", {"p1"}, make_graph()) == []

def test_multiple_matches():
    g = make_graph()
    g.add_edge("u1", "r3", type="trusted-to-assume")
    targets = {f["target"] for f in detect_direct_assumerole("u1", {"r1", "r3"}, g)}
    assert targets == {"r1", "r3"}

def test_accepts_list_and_empty_set():
    g = make_graph()
    assert len(detect_direct_assumerole("u1", ["r1"], g)) == 1
    assert detect_direct_assumerole("u1", set(), g) == []

def test_source_without_edges():
    assert detect_direct_assumerole("lonely", {"r1"}, make_graph()) == []

def test_unknown_source_raises():
    with pytest.raises(nx.NetworkXError):
        detect_direct_assumerole("nope", {"r1"}, make_graph())