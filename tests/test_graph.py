import pytest
from graph import classify_node_type, build_graph
from iam_models import IAMUser, IAMRole, IAMRelationship, IAMInventory
from attack_path import attack_view


@pytest.mark.parametrize(
    "identifier,expected",
    [
        ("ec2.amazonaws.com", "Service"),
        ("lambda.amazonaws.com", "Service"),
        ("arn:aws:iam::aws:policy/AdministratorAccess", "Policy"),
        ("arn:aws:iam::aws:policy/job-function/AmazonODBAutonomousDatabaseAdmin", "Policy"),
        ("arn:aws:iam::123456789012:policy/other", "Policy"),
        ("*", "Wildcard"),
        ("arn:aws:iam::123456789012:root", "External"),
        ("arn:aws:iam::999999999999:user/bob", "External"),
        ("arn:aws:iam::123456789012:role/ghost", "External"),
        ("arn:aws:iam", "External"),
        ("", "External"),
        (None, "External"),
        (12345, "External"),
    ],
)
def test_classify_node_type(identifier, expected):
    assert classify_node_type(identifier) == expected


def test_aws_managed_policy_attached_to_role_becomes_policy_node():
    role_arn = "arn:aws:iam::123456789012:role/testrole"
    policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
    inventory = IAMInventory(
        users=[],
        groups=[],
        roles=[IAMRole(name="testrole", id="role-id", arn=role_arn, trust_policy={})],
        policies=[],
        relationships=[
            IAMRelationship(source=role_arn, relationship="attached-policy", target=policy_arn)
        ],
    )
    g = build_graph(inventory)
    assert g.has_node(policy_arn)
    assert g.nodes[policy_arn]["type"] == "Policy"


def test_wildcard_trust_becomes_wildcard_node():
    role_arn = "arn:aws:iam::123456789012:role/testrole"
    inventory = IAMInventory(
        users=[],
        groups=[],
        roles=[IAMRole(name="testrole", id="role-id", arn=role_arn, trust_policy={})],
        policies=[],
        relationships=[
            IAMRelationship(source="*", relationship="trusted-to-assume", target=role_arn)
        ],
    )
    g = build_graph(inventory)
    assert g.has_node("*")
    assert g.nodes["*"]["type"] == "Wildcard"


def test_unknown_role_arn_becomes_external():
    role_arn = "arn:aws:iam::123456789012:role/testrole"
    ghost_arn = "arn:aws:iam::123456789012:role/ghost"
    inventory = IAMInventory(
        users=[],
        groups=[],
        roles=[IAMRole(name="testrole", id="role-id", arn=role_arn, trust_policy={})],
        policies=[],
        relationships=[
            IAMRelationship(source=ghost_arn, relationship="trusted-to-assume", target=role_arn)
        ],
    )
    g = build_graph(inventory)
    assert g.has_node(ghost_arn)
    assert g.nodes[ghost_arn]["type"] == "External"


def test_inventory_user_as_trust_principal_stays_user():
    user_arn = "arn:aws:iam::123456789012:user/testuser"
    role_arn = "arn:aws:iam::123456789012:role/testrole"
    inventory = IAMInventory(
        users=[IAMUser(name="testuser", id="u-id", arn=user_arn)],
        groups=[],
        roles=[IAMRole(name="testrole", id="role-id", arn=role_arn, trust_policy={})],
        policies=[],
        relationships=[
            IAMRelationship(source=user_arn, relationship="trusted-to-assume", target=role_arn)
        ],
    )
    g = build_graph(inventory)
    assert g.nodes[user_arn]["type"] == "User"


def test_attack_view_contains_only_users_and_roles_with_all_node_types():
    user_arn = "arn:aws:iam::123456789012:user/testuser"
    role_arn = "arn:aws:iam::123456789012:role/testrole"
    inventory = IAMInventory(
        users=[IAMUser(name="testuser", id="u-id", arn=user_arn)],
        groups=[],
        roles=[IAMRole(name="testrole", id="role-id", arn=role_arn, trust_policy={})],
        policies=[],
        relationships=[
            IAMRelationship(source="*", relationship="trusted-to-assume", target=role_arn),
            IAMRelationship(source="arn:aws:iam::123456789012:root", relationship="trusted-to-assume", target=role_arn),
            IAMRelationship(source="ec2.amazonaws.com", relationship="trusted-to-assume", target=role_arn),
            IAMRelationship(source=role_arn, relationship="attached-policy", target="arn:aws:iam::aws:policy/AdministratorAccess"),
        ],
    )
    g = build_graph(inventory)
    view = attack_view(g)
    assert set(view.nodes) == {user_arn, role_arn}
    types = {view.nodes[n]["type"] for n in view}
    assert types <= {"User", "Role"}

