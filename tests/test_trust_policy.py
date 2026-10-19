from iam_models import TrustPrincipal
from trust_policy_parser import parse_trust_policy

USER_ARN = "arn:aws:iam::123456789012:user/testuser"
USER2_ARN = "arn:aws:iam::123456789012:user/testuser2"
ROOT_ARN = "arn:aws:iam::123456789012:root"


def allow(principal):
    """Build one Allow trust statement with the given Principal value."""
    return {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": principal}


def policy(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


# 1
def test_single_aws_principal():
    result = parse_trust_policy(policy(allow({"AWS": USER_ARN})))
    assert result == [TrustPrincipal(principal_type="AWS", identifier=USER_ARN)]


# 2
def test_aws_list_gives_one_record_each():
    result = parse_trust_policy(policy(allow({"AWS": [USER_ARN, USER2_ARN]})))
    assert result == [
        TrustPrincipal(principal_type="AWS", identifier=USER_ARN),
        TrustPrincipal(principal_type="AWS", identifier=USER2_ARN),
    ]


# 3
def test_bare_account_number():
    result = parse_trust_policy(policy(allow({"AWS": "123456789012"})))
    assert result == [TrustPrincipal(principal_type="AWS", identifier="123456789012")]


# 4
def test_account_root_arn():
    result = parse_trust_policy(policy(allow({"AWS": ROOT_ARN})))
    assert result == [TrustPrincipal(principal_type="AWS", identifier=ROOT_ARN)]


# 5
def test_wildcard_inside_aws_dict():
    result = parse_trust_policy(policy(allow({"AWS": "*"})))
    assert result == [TrustPrincipal(principal_type="AWS", identifier="*")]


# 6
def test_wildcard_as_plain_string_principal():
    result = parse_trust_policy(policy(allow("*")))
    assert result == [TrustPrincipal(principal_type="AWS", identifier="*")]


# 7
def test_deny_statement_is_skipped():
    deny = {"Effect": "Deny", "Action": "sts:AssumeRole", "Principal": {"AWS": USER_ARN}}
    assert parse_trust_policy(policy(deny)) == []


# 8
def test_service_and_aws_in_one_statement():
    result = parse_trust_policy(
        policy(allow({"Service": "ec2.amazonaws.com", "AWS": USER_ARN}))
    )
    assert result == [
        TrustPrincipal(principal_type="Service", identifier="ec2.amazonaws.com"),
        TrustPrincipal(principal_type="AWS", identifier=USER_ARN),
    ]


# 9
def test_statement_without_principal_is_skipped():
    no_principal = {"Effect": "Allow", "Action": "sts:AssumeRole"}
    assert parse_trust_policy(policy(no_principal)) == []


# 10
def test_single_statement_dict_instead_of_list():
    doc = {"Version": "2012-10-17", "Statement": allow({"AWS": USER_ARN})}
    result = parse_trust_policy(doc)
    assert result == [TrustPrincipal(principal_type="AWS", identifier=USER_ARN)]