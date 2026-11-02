from pathlib import Path
import pytest
from fastapi.testclient import TestClient

import api
from snapshot import load_snapshot, save_snapshot
from iam_models import IAMInventory, IAMUser


@pytest.fixture(autouse=True)
def reset_api_state():
    api.reset_state()
    yield
    api.reset_state()


@pytest.fixture
def client():
    return TestClient(api.app)


def test_health(client):
    r = client.get("/api/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_snapshots_list_contains_sample(client):
    r = client.get("/api/snapshots")
    assert r.status_code == 200
    names = [s["name"] for s in r.json()["snapshots"]]
    assert "sample_lab.json" in names


def test_data_endpoints_return_409_before_load(client):
    endpoints = [
        "/api/summary",
        "/api/identities",
        "/api/reachable?source=arn:aws:iam::123456789012:user/testuser",
        "/api/graph/full",
        "/api/graph/attack",
    ]
    for ep in endpoints:
        r = client.get(ep)
        assert r.status_code == 409, f"Expected 409 for {ep}, got {r.status_code}"
        assert r.json()["detail"] == "No snapshot loaded"


def test_load_sample_and_endpoints(client):
    # 1. Load sample
    r = client.post("/api/snapshots/load", json={"name": "sample_lab.json"})
    assert r.status_code == 200
    assert r.json()["loaded"] == "sample_lab.json"

    # 2. Summary
    r_sum = client.get("/api/summary")
    assert r_sum.status_code == 200
    sum_data = r_sum.json()
    assert sum_data["users"] == 2
    assert sum_data["groups"] == 1
    assert sum_data["roles"] == 5
    assert sum_data["policies"] == 3
    assert sum_data["can_assume_edges"] == 5
    assert sum_data["snapshot_name"] == "sample_lab.json"

    # 3. Identities
    r_ident = client.get("/api/identities")
    assert r_ident.status_code == 200
    assert len(r_ident.json()["identities"]) == 7

    # 4. Reachable for testuser2
    u2 = "arn:aws:iam::123456789012:user/testuser2"
    r_reach = client.get(f"/api/reachable?source={u2}")
    assert r_reach.status_code == 200
    results = r_reach.json()["results"]
    assert len(results) == 3
    assert results[0]["name"] == "testrole3"
    assert results[0]["hops"] == 1
    assert results[1]["name"] == "testrole4"
    assert results[1]["hops"] == 1
    assert results[2]["name"] == "testrole5"
    assert results[2]["hops"] == 2

    # 5. max_hops=1 excludes testrole5
    r_reach_1 = client.get(f"/api/reachable?source={u2}&max_hops=1")
    assert r_reach_1.status_code == 200
    assert len(r_reach_1.json()["results"]) == 2
    assert "testrole5" not in [x["name"] for x in r_reach_1.json()["results"]]

    # 6. Unknown source -> 404
    r_unknown = client.get("/api/reachable?source=arn:aws:iam::123456789012:user/ghost")
    assert r_unknown.status_code == 404

    # 7. Negative max_hops -> 422
    r_neg = client.get(f"/api/reachable?source={u2}&max_hops=-1")
    assert r_neg.status_code == 422

    # 8. Graph attack mode
    r_att = client.get("/api/graph/attack")
    assert r_att.status_code == 200
    att_json = r_att.json()
    assert len(att_json["edges"]) == 5
    assert all(e["type"] == "can-assume" for e in att_json["edges"])
    assert all(n["type"] in ("User", "Role") for n in att_json["nodes"])

    # 9. Graph full mode
    r_full = client.get("/api/graph/full")
    assert r_full.status_code == 200
    full_json = r_full.json()
    full_types = {n["type"] for n in full_json["nodes"]}
    assert "Group" in full_types and "Policy" in full_types


def test_load_validation(client):
    # Invalid names
    for bad_name in ["../x.json", "a/b.json", "x.txt", "", "bad..name.json"]:
        r = client.post("/api/snapshots/load", json={"name": bad_name})
        assert r.status_code == 400

    # Missing file
    r_miss = client.post("/api/snapshots/load", json={"name": "non_existent.json"})
    assert r_miss.status_code == 404


def test_upload_snapshot_valid_corrupt_and_size_limit(client):
    # 1. Valid upload
    sample_path = Path("snapshots/sample_lab.json")
    import json
    with open(sample_path, "r", encoding="utf-8") as f:
        valid_dict = json.load(f)

    r_up = client.post("/api/snapshots/upload", json=valid_dict)
    assert r_up.status_code == 200
    assert r_up.json()["loaded"] == "(uploaded)"

    # Check state was populated
    r_sum = client.get("/api/summary")
    assert r_sum.status_code == 200
    assert r_sum.json()["snapshot_name"] == "(uploaded)"

    # 2. Corrupt upload
    corrupt_dict = {"invalid": "data"}
    r_bad = client.post("/api/snapshots/upload", json=corrupt_dict)
    assert r_bad.status_code == 400

    # 3. Payload > 10MB rejected with 413
    big_header = {"Content-Length": str(11 * 1024 * 1024)}
    r_big = client.post("/api/snapshots/upload", json=valid_dict, headers=big_header)
    assert r_big.status_code == 413


def test_serve_index_html(client):
    r = client.get("/")
    assert r.status_code == 200
    assert "text/html" in r.headers["content-type"]


def test_replace_loaded_snapshot(tmp_path, client, monkeypatch):
    # Create two snapshots in tmp_path
    snap1 = tmp_path / "snap1.json"
    snap2 = tmp_path / "snap2.json"

    u1 = IAMUser(name="user1", id="u1", arn="arn:aws:iam::123456789012:user/user1")
    u2 = IAMUser(name="user2", id="u2", arn="arn:aws:iam::123456789012:user/user2")

    save_snapshot(
        IAMInventory(users=[u1], groups=[], roles=[], policies=[], relationships=[]),
        {u1.arn: []},
        snap1,
        meta={"name": "snap1"},
    )
    save_snapshot(
        IAMInventory(users=[u1, u2], groups=[], roles=[], policies=[], relationships=[]),
        {u1.arn: [], u2.arn: []},
        snap2,
        meta={"name": "snap2"},
    )

    monkeypatch.setattr(api, "SNAP_DIR", tmp_path)

    # Load snap1
    client.post("/api/snapshots/load", json={"name": "snap1.json"})
    assert client.get("/api/summary").json()["users"] == 1

    # Replace with snap2
    client.post("/api/snapshots/load", json={"name": "snap2.json"})
    assert client.get("/api/summary").json()["users"] == 2


def test_permissions_endpoint_does_not_exist(client):
    client.post("/api/snapshots/load", json={"name": "sample_lab.json"})
    r = client.get("/api/permissions?arn=arn:aws:iam::123456789012:user/testuser")
    assert r.status_code == 404


