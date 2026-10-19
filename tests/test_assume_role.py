import pytest

from iam_models import (
    TrustPrincipal,
    IAMUser,
    IAMRole,
    IAMInventory,
    EffectivePermission,
)
from assume_role import (
    account_id_from,
    classify_trust,
    find_can_assume,
)


ROLE = "arn:aws:iam::123456789012:role/testrole"
USER = "arn:aws:iam::123456789012:user/testuser"
OTHER_ROLE = "arn:aws:iam::123456789012:role/other"
OTHER_USER_SAME_ACCOUNT = "arn:aws:iam::123456789012:user/someone-else"
ROOT = "arn:aws:iam::123456789012:root"
BOB_OTHER_ACCOUNT = "arn:aws:iam::999999999999:user/bob"
OTHER_ROOT = "arn:aws:iam::999999999999:root"

ROLE_A = "arn:aws:iam::123456789012:role/roleA"
ROLE_B = "arn:aws:iam::123456789012:role/roleB"


# ---------- helpers ----------

def aws(identifier):
    return TrustPrincipal(
        principal_type="AWS",
        identifier=identifier,
    )


def make_user(name, arn):
    return IAMUser(
        name=name,
        id=f"{name}-id",
        arn=arn,
    )


def make_role(name, arn, trust_policy):
    return IAMRole(
        name=name,
        id=f"{name}-id",
        arn=arn,
        trust_policy=trust_policy,
    )


def make_permission(action, resource, identity_arn):
    return EffectivePermission(
        identity_arn=identity_arn,
        action=action,
        resource=resource,
        via=[],
    )


def make_inventory(users=None, roles=None):
    return IAMInventory(
        users=users or [],
        groups=[],
        roles=roles or [],
        policies=[],
        relationships=[],
    )


def root_trust():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": ROOT},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def trust_for(*arns):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": list(arns)},
                "Action": "sts:AssumeRole",
            }
        ],
    }


def service_trust():
    return {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }


# ---------- classify_trust ----------

# 1
def test_exact_user_same_account_is_direct():
    assert classify_trust([aws(USER)], ROLE, USER) == "direct"


# 2
def test_exact_role_same_account_is_direct():
    assert classify_trust([aws(OTHER_ROLE)], ROLE, OTHER_ROLE) == "direct"


# 3
def test_same_account_root_needs_permission():
    assert classify_trust([aws(ROOT)], ROLE, USER) == "needs-permission"


# 4
def test_bare_account_number_needs_permission():
    assert classify_trust([aws("123456789012")], ROLE, USER) == "needs-permission"


# 5
def test_other_account_root_does_not_cover_caller():
    assert classify_trust([aws(OTHER_ROOT)], ROLE, USER) == "none"


# 6
def test_wildcard_needs_permission():
    assert classify_trust([aws("*")], ROLE, USER) == "needs-permission"


# 7
def test_different_user_same_account_is_none():
    assert classify_trust([aws(OTHER_USER_SAME_ACCOUNT)], ROLE, USER) == "none"


# 8
def test_cross_account_exact_match_needs_permission():
    assert (
        classify_trust([aws(BOB_OTHER_ACCOUNT)], ROLE, BOB_OTHER_ACCOUNT)
        == "needs-permission"
    )


# 9
def test_service_principal_only_is_none():
    service = TrustPrincipal(
        principal_type="Service",
        identifier="ec2.amazonaws.com",
    )
    assert classify_trust([service], ROLE, USER) == "none"


# 10
def test_direct_beats_root():
    assert classify_trust([aws(ROOT), aws(USER)], ROLE, USER) == "direct"
    assert classify_trust([aws(USER), aws(ROOT)], ROLE, USER) == "direct"


# 11
def test_empty_trust_list_is_none():
    assert classify_trust([], ROLE, USER) == "none"


# ---------- account_id_from ----------

def test_account_from_user_arn():
    assert account_id_from(USER) == "123456789012"


def test_account_from_role_arn():
    assert account_id_from(ROLE) == "123456789012"


def test_account_from_bare_number():
    assert account_id_from("123456789012") == "123456789012"


def test_account_from_wildcard_is_none():
    assert account_id_from("*") is None


def test_account_from_service_name_is_none():
    assert account_id_from("ec2.amazonaws.com") is None


def test_account_from_aws_managed_policy_arn_is_none():
    assert account_id_from("arn:aws:iam::aws:policy/AdministratorAccess") is None


# NEW: malformed identifiers must not crash or be misread as account IDs
def test_malformed_identifiers_do_not_crash():
    assert account_id_from("ec2.amazon.c") is None   # 12 chars, not digits
    assert account_id_from("arn:aws:iam") is None    # too few parts
    assert account_id_from("") is None


# ---------- find_can_assume ----------

# 12. Direct trust creates an edge without an identity permission.
def test_direct_trust_creates_edge_without_permission():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, trust_for(USER))
    inventory = make_inventory(users=[user], roles=[role])

    edges = find_can_assume(inventory, {USER: []})

    assert len(edges) == 1
    assert edges[0].source == USER
    assert edges[0].target == ROLE
    assert edges[0].reason == "direct-trust"
    assert edges[0].evidence == []


# 13. Account-root trust and a matching permission create an edge.
def test_root_trust_with_matching_permission_creates_edge():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, root_trust())
    permission = make_permission("sts:AssumeRole", ROLE, USER)
    inventory = make_inventory(users=[user], roles=[role])

    edges = find_can_assume(inventory, {USER: [permission]})

    assert len(edges) == 1
    assert edges[0].source == USER
    assert edges[0].target == ROLE
    assert edges[0].reason == "trust-and-permission"
    assert edges[0].evidence == [permission]


# 14. Root trust without a matching permission creates no edge.
def test_root_trust_without_permission_creates_no_edge():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, root_trust())
    inventory = make_inventory(users=[user], roles=[role])

    assert find_can_assume(inventory, {USER: []}) == []


# 15. Permission targeting another role creates no edge.
def test_permission_for_different_role_creates_no_edge():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, root_trust())
    permission = make_permission("sts:AssumeRole", OTHER_ROLE, USER)
    inventory = make_inventory(users=[user], roles=[role])

    assert find_can_assume(inventory, {USER: [permission]}) == []


# 16. Permission alone is insufficient if the role does not trust the caller.
def test_permission_without_matching_trust_creates_no_edge():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, trust_for(OTHER_USER_SAME_ACCOUNT))
    permission = make_permission("sts:AssumeRole", ROLE, USER)
    inventory = make_inventory(users=[user], roles=[role])

    assert find_can_assume(inventory, {USER: [permission]}) == []


# 17. One role can assume another with matching trust and permission.
#     Exact assertion: roleA -> roleB is the ONLY edge.
def test_role_to_role_assumption():
    role_a = make_role("roleA", ROLE_A, root_trust())
    role_b = make_role("roleB", ROLE_B, root_trust())
    permission = make_permission("sts:AssumeRole", ROLE_B, ROLE_A)
    inventory = make_inventory(roles=[role_a, role_b])

    edges = find_can_assume(inventory, {ROLE_A: [permission], ROLE_B: []})

    assert len(edges) == 1
    assert edges[0].source == ROLE_A
    assert edges[0].target == ROLE_B
    assert edges[0].reason == "trust-and-permission"
    assert edges[0].evidence == [permission]


# 18. A missing permission-map entry must not cause an exception.
def test_missing_permission_map_entry_creates_no_edge():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, root_trust())
    inventory = make_inventory(users=[user], roles=[role])

    assert find_can_assume(inventory, {}) == []


# 19. Edge evidence should contain only matching AssumeRole permissions.
def test_edge_evidence_contains_only_matching_permission():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, root_trust())
    matching = make_permission("sts:AssumeRole", ROLE, USER)
    unrelated = make_permission("s3:GetObject", "*", USER)
    inventory = make_inventory(users=[user], roles=[role])

    edges = find_can_assume(inventory, {USER: [matching, unrelated]})

    assert len(edges) == 1
    assert edges[0].evidence == [matching]


# 20. Service trust does not create an IAM user/role caller edge.
def test_service_only_trust_creates_no_edges():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, service_trust())
    inventory = make_inventory(users=[user], roles=[role])

    assert find_can_assume(inventory, {USER: []}) == []


# 21. A user's permissions must not be borrowed from another role.
def test_user_does_not_inherit_role_permissions():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, root_trust())
    role_permission = make_permission("sts:AssumeRole", ROLE, ROLE)
    inventory = make_inventory(users=[user], roles=[role])

    edges = find_can_assume(inventory, {USER: [], ROLE: [role_permission]})

    assert not any(e.source == USER and e.target == ROLE for e in edges)


# 22. An unrelated permission must not authorize assumption.
def test_unrelated_permission_creates_no_edge():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, root_trust())
    unrelated = make_permission("s3:GetObject", "*", USER)
    inventory = make_inventory(users=[user], roles=[role])

    assert find_can_assume(inventory, {USER: [unrelated]}) == []


# ---------- NEW: wildcard permissions go through policy_matcher ----------

@pytest.mark.parametrize(
    "action,resource",
    [
        ("sts:*", "*"),
        ("*", "*"),
        ("sts:Assume*", "arn:aws:iam::123456789012:role/*"),
        ("STS:ASSUMEROLE", ROLE),  # IAM action names are case-insensitive
    ],
)
def test_wildcard_permissions_grant_edge(action, resource):
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, root_trust())
    perm = make_permission(action, resource, USER)

    edges = find_can_assume(make_inventory([user], [role]), {USER: [perm]})

    assert len(edges) == 1
    assert edges[0].reason == "trust-and-permission"


def test_resource_pattern_for_other_role_does_not_match():
    user = make_user("testuser", USER)
    role = make_role("testrole", ROLE, root_trust())
    perm = make_permission(
        "sts:AssumeRole", "arn:aws:iam::123456789012:role/app-*", USER
    )

    assert find_can_assume(make_inventory([user], [role]), {USER: [perm]}) == []


# ---------- NEW: self-edge decision ----------
# Requires this line at the top of the inner loop in find_can_assume:
#     if caller.arn == role.arn:
#         continue
def test_role_trusting_itself_creates_no_self_edge():
    role = make_role("testrole", ROLE, trust_for(ROLE))

    assert find_can_assume(make_inventory(roles=[role]), {}) == []


# ---------- NEW: the real lab shape (hand-built, no AWS) ----------

def test_lab_shape_produces_exactly_five_edges():
    base = "arn:aws:iam::123456789012:"
    u1, u2 = base + "user/testuser", base + "user/testuser2"
    r = {
        n: base + f"role/{n}"
        for n in ["testrole", "testrole2", "testrole3", "testrole4", "testrole5"]
    }

    roles = [
        make_role("testrole", r["testrole"], trust_for(u1)),
        make_role("testrole2", r["testrole2"], service_trust()),
        make_role("testrole3", r["testrole3"], trust_for(u2)),
        make_role("testrole4", r["testrole4"], trust_for(u2)),
        make_role(
            "testrole5", r["testrole5"], trust_for(r["testrole3"], r["testrole4"])
        ),
    ]
    users = [make_user("testuser", u1), make_user("testuser2", u2)]

    edges = find_can_assume(make_inventory(users, roles), {})

    assert {(e.source, e.target) for e in edges} == {
        (u1, r["testrole"]),
        (u2, r["testrole3"]),
        (u2, r["testrole4"]),
        (r["testrole3"], r["testrole5"]),
        (r["testrole4"], r["testrole5"]),
    }
    assert len(edges) == 5  # no duplicates


# ---------- NEW: live check against the real lab (needs AWS credentials) ----------

@pytest.mark.aws
def test_live_lab_produces_expected_five_edges():
    from IAM_Inventory import filter_inventory
    from effective_permission import build_permission_map

    inventory = filter_inventory()
    edges = find_can_assume(inventory, build_permission_map(inventory))

    pairs = {
        (e.source.split("/")[-1], e.target.split("/")[-1]) for e in edges
    }
    assert pairs == {
        ("testuser", "testrole"),
        ("testuser2", "testrole3"),
        ("testuser2", "testrole4"),
        ("testrole3", "testrole5"),
        ("testrole4", "testrole5"),
    }