from pathlib import Path
from snapshot import load_snapshot
from assume_role import find_can_assume


def test_sample_snapshot_contents_and_edges():
    path = Path("snapshots/sample_lab.json")
    assert path.is_file(), "sample_lab.json must exist"

    raw_text = path.read_text(encoding="utf-8")
    forbidden_id = "944146" + "429179"
    assert forbidden_id not in raw_text, "Real AWS account ID must not be present in sample snapshot"

    inventory, permission_map, meta = load_snapshot(path)

    assert meta.get("account_id") == "123456789012"
    assert len(inventory.users) == 2
    assert len(inventory.groups) == 1
    assert len(inventory.roles) == 5
    assert len(inventory.policies) == 3

    edges = find_can_assume(inventory, permission_map)
    assert len(edges) == 5

    base = "arn:aws:iam::123456789012:"
    expected_pairs = {
        (f"{base}user/testuser", f"{base}role/testrole"),
        (f"{base}user/testuser2", f"{base}role/testrole3"),
        (f"{base}user/testuser2", f"{base}role/testrole4"),
        (f"{base}role/testrole3", f"{base}role/testrole5"),
        (f"{base}role/testrole4", f"{base}role/testrole5"),
    }
    actual_pairs = {(e.source, e.target) for e in edges}
    assert actual_pairs == expected_pairs

    # All reasons direct-trust
    for e in edges:
        assert e.reason == "direct-trust"

    # testrole2 (ec2 service trust) has none
    role2_arn = f"{base}role/testrole2"
    assert not any(e.target == role2_arn or e.source == role2_arn for e in edges)

