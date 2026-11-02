import dataclasses
import json
from pathlib import Path
from iam_models import (
    IAMUser,
    IAMGroup,
    IAMRole,
    IAMPolicy,
    IAMRelationship,
    IAMInventory,
    EffectivePermission,
)


def inventory_to_dict(inventory: IAMInventory) -> dict:
    """Converts an IAMInventory dataclass into a JSON-serializable dictionary."""
    return dataclasses.asdict(inventory)


def inventory_from_dict(data: dict) -> IAMInventory:
    """Rebuilds an IAMInventory dataclass from a dictionary. Raises ValueError on missing keys."""
    if not isinstance(data, dict):
        raise ValueError("Inventory data must be a dictionary")

    required_keys = ("users", "groups", "roles", "policies", "relationships")
    for key in required_keys:
        if key not in data:
            raise ValueError(f"Missing required inventory key: '{key}'")

    users = []
    for u in data["users"]:
        for k in ("name", "id", "arn"):
            if k not in u:
                raise ValueError(f"Missing required user key: '{k}'")
        users.append(IAMUser(name=u["name"], id=u["id"], arn=u["arn"]))

    groups = []
    for g in data["groups"]:
        for k in ("name", "id", "arn"):
            if k not in g:
                raise ValueError(f"Missing required group key: '{k}'")
        groups.append(IAMGroup(name=g["name"], id=g["id"], arn=g["arn"]))

    roles = []
    for r in data["roles"]:
        for k in ("name", "id", "arn"):
            if k not in r:
                raise ValueError(f"Missing required role key: '{k}'")
        roles.append(
            IAMRole(
                name=r["name"],
                id=r["id"],
                arn=r["arn"],
                trust_policy=r.get("trust_policy", None),
            )
        )

    policies = []
    for p in data["policies"]:
        for k in ("name", "arn"):
            if k not in p:
                raise ValueError(f"Missing required policy key: '{k}'")
        policies.append(IAMPolicy(name=p["name"], arn=p["arn"], id=p.get("id", None)))

    relationships = []
    for rel in data["relationships"]:
        for k in ("source", "relationship", "target"):
            if k not in rel:
                raise ValueError(f"Missing required relationship key: '{k}'")
        relationships.append(
            IAMRelationship(
                source=rel["source"],
                relationship=rel["relationship"],
                target=rel["target"],
            )
        )

    return IAMInventory(
        users=users,
        groups=groups,
        roles=roles,
        policies=policies,
        relationships=relationships,
    )


def permission_map_to_dict(pm: dict) -> dict:
    """Converts a permission map into a JSON-serializable dictionary."""
    return {
        arn: [dataclasses.asdict(perm) for perm in perms]
        for arn, perms in pm.items()
    }


def permission_map_from_dict(data: dict) -> dict:
    """Rebuilds a permission map from a dictionary. Keeps empty lists and preserves via list[str]."""
    if not isinstance(data, dict):
        raise ValueError("permission_map must be a dictionary")
    pm = {}
    for arn, perms in data.items():
        if not isinstance(perms, list):
            raise ValueError(f"Permissions for {arn} must be a list")
        perm_list = []
        for p in perms:
            for req in ("identity_arn", "action", "resource", "via"):
                if req not in p:
                    raise ValueError(f"Missing required EffectivePermission key: '{req}'")
            perm_list.append(
                EffectivePermission(
                    identity_arn=p["identity_arn"],
                    action=p["action"],
                    resource=p["resource"],
                    via=list(p["via"]),
                )
            )
        pm[arn] = perm_list
    return pm


def snapshot_to_dict(inventory, permission_map, meta=None) -> dict:
    """Creates a schema v1 snapshot dictionary."""
    return {
        "schema_version": 1,
        "meta": meta if meta is not None else {},
        "inventory": inventory_to_dict(inventory),
        "permission_map": permission_map_to_dict(permission_map),
    }


def snapshot_from_dict(data: dict):
    """Validates schema v1 dictionary and unpacks (inventory, permission_map, meta)."""
    if not isinstance(data, dict):
        raise ValueError("Snapshot data must be a dictionary")
    if "schema_version" not in data:
        raise ValueError("Missing 'schema_version' in snapshot")
    if data["schema_version"] != 1:
        raise ValueError(f"Unsupported schema_version: {data['schema_version']}, expected 1")
    for req in ("inventory", "permission_map"):
        if req not in data:
            raise ValueError(f"Missing required top-level key: '{req}'")

    meta = data.get("meta", {})
    inventory = inventory_from_dict(data["inventory"])
    permission_map = permission_map_from_dict(data["permission_map"])
    return inventory, permission_map, meta


def save_snapshot(inventory, permission_map, path, meta=None):
    """Saves inventory and permission map as indented UTF-8 JSON, creating parent folders."""
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    snap = snapshot_to_dict(inventory, permission_map, meta=meta)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(snap, f, indent=2)


def load_snapshot(path):
    """Loads a snapshot from file. Raises FileNotFoundError or ValueError on invalid content."""
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Snapshot file not found: {path}")
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in snapshot at {path}: {e}") from e
    return snapshot_from_dict(data)

