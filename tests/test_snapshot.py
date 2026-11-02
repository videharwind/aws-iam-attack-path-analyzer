import json
from pathlib import Path
import pytest
from iam_models import (
    IAMUser,
    IAMGroup,
    IAMRole,
    IAMPolicy,
    IAMRelationship,
    IAMInventory,
    EffectivePermission,
)
from snapshot import (
    inventory_to_dict,
    inventory_from_dict,
    permission_map_to_dict,
    permission_map_from_dict,
    snapshot_to_dict,
    snapshot_from_dict,
    save_snapshot,
    load_snapshot,
)
from assume_role import find_can_assume


def test_no_boto3_in_snapshot_module():
    import sys
    import snapshot
    # Confirm snapshot module does not import boto3
    assert "boto3" not in sys.modules or "boto3" not in dir(snapshot)
    with open("src/snapshot.py", "r", encoding="utf-8") as f:
        assert "boto3" not in f.read()


def test_roundtrip_empty_inventory():
    inv = IAMInventory(users=[], groups=[], roles=[], policies=[], relationships=[])
    pm = {}
    snap = snapshot_to_dict(inv, pm, meta={"test": "empty"})
    loaded_inv, loaded_pm, meta = snapshot_from_dict(snap)
    assert loaded_inv == inv
    assert loaded_pm == pm
    assert meta == {"test": "empty"}


def test_roundtrip_lab_shaped_inventory(tmp_path):
    user = IAMUser(name="testuser", id="u-1", arn="arn:aws:iam::123456789012:user/testuser")
    group = IAMGroup(name="testgroup", id="g-1", arn="arn:aws:iam::123456789012:group/testgroup")
    role = IAMRole(
        name="testrole",
        id="r-1",
        arn="arn:aws:iam::123456789012:role/testrole",
        trust_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": user.arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    )
    policy = IAMPolicy(name="testpolicy", arn="arn:aws:iam::123456789012:policy/testpolicy", id=None)
    rel1 = IAMRelationship(source=user.arn, relationship="member-of", target=group.arn)
    rel2 = IAMRelationship(source=user.arn, relationship="trusted-to-assume", target=role.arn)

    inv = IAMInventory(
        users=[user],
        groups=[group],
        roles=[role],
        policies=[policy],
        relationships=[rel1, rel2],
    )

    perm1 = EffectivePermission(
        identity_arn=user.arn,
        action="sts:AssumeRole",
        resource=role.arn,
        via=["arn:aws:iam::123456789012:policy/p1", "arn:aws:iam::123456789012:policy/p2"],
    )
    pm = {
        user.arn: [perm1],
        role.arn: [],
    }

    meta = {"account_id": "123456789012", "created_at": "2026-11-01T12:00:00Z"}
    snap_path = tmp_path / "deep" / "nested" / "snap.json"

    # Test save creates parent directories and writes valid UTF-8 JSON
    save_snapshot(inv, pm, snap_path, meta=meta)
    assert snap_path.is_file()

    with open(snap_path, "rb") as f:
        raw_bytes = f.read()
        raw_text = raw_bytes.decode("utf-8")
        parsed = json.loads(raw_text)
        assert parsed["schema_version"] == 1

    loaded_inv, loaded_pm, loaded_meta = load_snapshot(snap_path)
    assert loaded_inv == inv
    assert loaded_pm == pm
    assert loaded_meta == meta

    # Verify dataclass types
    assert isinstance(loaded_inv.users[0], IAMUser)
    assert isinstance(loaded_inv.groups[0], IAMGroup)
    assert isinstance(loaded_inv.roles[0], IAMRole)
    assert isinstance(loaded_inv.policies[0], IAMPolicy)
    assert isinstance(loaded_inv.relationships[0], IAMRelationship)
    assert isinstance(loaded_pm[user.arn][0], EffectivePermission)
    assert loaded_inv.policies[0].id is None
    assert isinstance(loaded_pm[user.arn][0].via, list)


def test_roundtrip_find_can_assume_matches_before_and_after(tmp_path):
    user = IAMUser(name="testuser", id="u-1", arn="arn:aws:iam::123456789012:user/testuser")
    role = IAMRole(
        name="testrole",
        id="r-1",
        arn="arn:aws:iam::123456789012:role/testrole",
        trust_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": user.arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    )
    inv = IAMInventory(users=[user], groups=[], roles=[role], policies=[], relationships=[])
    pm = {user.arn: [], role.arn: []}

    edges_before = find_can_assume(inv, pm)
    snap_path = tmp_path / "test_edges.json"
    save_snapshot(inv, pm, snap_path)

    loaded_inv, loaded_pm, _ = load_snapshot(snap_path)
    edges_after = find_can_assume(loaded_inv, loaded_pm)

    assert len(edges_before) == 1
    assert edges_before == edges_after


def test_wrong_schema_version_raises():
    data = {
        "schema_version": 2,
        "inventory": {"users": [], "groups": [], "roles": [], "policies": [], "relationships": []},
        "permission_map": {},
    }
    with pytest.raises(ValueError, match="Unsupported schema_version"):
        snapshot_from_dict(data)


def test_missing_schema_version_raises():
    data = {
        "inventory": {"users": [], "groups": [], "roles": [], "policies": [], "relationships": []},
        "permission_map": {},
    }
    with pytest.raises(ValueError, match="Missing 'schema_version'"):
        snapshot_from_dict(data)


def test_missing_top_level_key_raises():
    data = {
        "schema_version": 1,
        "inventory": {"users": [], "groups": [], "roles": [], "policies": [], "relationships": []},
    }
    with pytest.raises(ValueError, match="Missing required top-level key"):
        snapshot_from_dict(data)


def test_missing_inventory_key_raises():
    data = {
        "schema_version": 1,
        "inventory": {"users": [], "groups": [], "roles": [], "policies": []},
        "permission_map": {},
    }
    with pytest.raises(ValueError, match="Missing required inventory key"):
        snapshot_from_dict(data)


def test_missing_file_raises(tmp_path):
    missing_path = tmp_path / "ghost.json"
    with pytest.raises(FileNotFoundError):
        load_snapshot(missing_path)


def test_invalid_json_raises(tmp_path):
    corrupt_path = tmp_path / "corrupt.json"
    corrupt_path.write_text("{ broken json", encoding="utf-8")
    with pytest.raises(ValueError, match="Invalid JSON in snapshot"):
        load_snapshot(corrupt_path)


def test_non_dict_json_raises(tmp_path):
    array_path = tmp_path / "array.json"
    array_path.write_text("[1, 2, 3]", encoding="utf-8")
    with pytest.raises(ValueError, match="Snapshot data must be a dictionary"):
        load_snapshot(array_path)

