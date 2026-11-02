import os
from pathlib import Path
import sys

# Ensure src/ is importable
SRC_DIR = Path(__file__).resolve().parent.parent / "src"
sys.path.insert(0, str(SRC_DIR))

from iam_models import (
    IAMUser,
    IAMGroup,
    IAMRole,
    IAMPolicy,
    IAMRelationship,
    IAMInventory,
    EffectivePermission,
    user_group_relationship,
    user_policy_relationship,
    group_policy_relationship,
    role_policy_relationship,
    role_principal_relationship,
)
from trust_policy_parser import parse_trust_policy
from snapshot import save_snapshot


def build_sample_lab():
    base = "arn:aws:iam::123456789012:"

    u_testuser = IAMUser(name="testuser", id="AIDA1111111111111", arn=f"{base}user/testuser")
    u_testuser2 = IAMUser(name="testuser2", id="AIDA2222222222222", arn=f"{base}user/testuser2")
    users = [u_testuser, u_testuser2]

    g_testgroup = IAMGroup(name="testgroup", id="AGPA1111111111111", arn=f"{base}group/testgroup")
    groups = [g_testgroup]

    r_testrole = IAMRole(
        name="testrole",
        id="AROA1111111111111",
        arn=f"{base}role/testrole",
        trust_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": u_testuser.arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    )
    r_testrole2 = IAMRole(
        name="testrole2",
        id="AROA2222222222222",
        arn=f"{base}role/testrole2",
        trust_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ec2.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    )
    r_testrole3 = IAMRole(
        name="testrole3",
        id="AROA3333333333333",
        arn=f"{base}role/testrole3",
        trust_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": u_testuser2.arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    )
    r_testrole4 = IAMRole(
        name="testrole4",
        id="AROA4444444444444",
        arn=f"{base}role/testrole4",
        trust_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": u_testuser2.arn},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    )
    r_testrole5 = IAMRole(
        name="testrole5",
        id="AROA5555555555555",
        arn=f"{base}role/testrole5",
        trust_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": [r_testrole3.arn, r_testrole4.arn]},
                    "Action": "sts:AssumeRole",
                }
            ],
        },
    )
    roles = [r_testrole, r_testrole2, r_testrole3, r_testrole4, r_testrole5]

    p_testpolicy = IAMPolicy(name="testpolicy", arn=f"{base}policy/testpolicy", id="ANPA1111111111111")
    p_testpolicy2 = IAMPolicy(name="testpolicy2", arn=f"{base}policy/testpolicy2", id="ANPA2222222222222")
    p_standalone = IAMPolicy(name="test-standalone-assume-policy", arn=f"{base}policy/test-standalone-assume-policy", id="ANPA3333333333333")
    policies = [p_testpolicy, p_testpolicy2, p_standalone]

    relationships = [
        # user to group
        user_group_relationship(u_testuser, g_testgroup),
        # attached policies
        group_policy_relationship(g_testgroup, p_testpolicy2),
        role_policy_relationship(r_testrole2, p_testpolicy),
        role_policy_relationship(r_testrole, p_testpolicy),
        role_policy_relationship(r_testrole5, p_testpolicy2),
        user_policy_relationship(u_testuser, p_standalone),
    ]

    # Deriving trusted-to-assume relationships consistently using trust_policy_parser
    for role in roles:
        principals = parse_trust_policy(role.trust_policy)
        for princ in principals:
            relationships.append(role_principal_relationship(role, princ))

    inventory = IAMInventory(
        users=users,
        groups=groups,
        roles=roles,
        policies=policies,
        relationships=relationships,
    )

    permission_map = {
        u_testuser.arn: [
            EffectivePermission(
                identity_arn=u_testuser.arn,
                action="sts:AssumeRole",
                resource=r_testrole.arn,
                via=[p_standalone.arn],
            ),
            EffectivePermission(
                identity_arn=u_testuser.arn,
                action="s3:GetObject",
                resource="*",
                via=[g_testgroup.arn, p_testpolicy2.arn],
            ),
        ],
        u_testuser2.arn: [],
        r_testrole.arn: [],
        r_testrole2.arn: [],
        r_testrole3.arn: [],
        r_testrole4.arn: [],
        r_testrole5.arn: [],
    }

    meta = {
        "account_id": "123456789012",
        "prefix": "test",
        "created_at": "2026-11-01T00:00:00Z",
        "tool_version": "0.1",
    }

    out_path = Path(__file__).resolve().parent.parent / "snapshots" / "sample_lab.json"
    save_snapshot(inventory, permission_map, out_path, meta=meta)
    print(f"Sample snapshot written to {out_path}")


if __name__ == "__main__":
    build_sample_lab()

