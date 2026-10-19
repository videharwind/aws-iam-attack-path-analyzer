import pytest
from policy_matcher import matches_pattern, action_matches, resource_matches

ROLE = "arn:aws:iam::123456789012:role/testrole"


# ---------- matches_pattern: wildcard behaviour ----------

@pytest.mark.parametrize("value, pattern, expected", [
    ("sts:AssumeRole", "sts:AssumeRole", True),    # exact match
    ("sts:AssumeRole", "*", True),                 # star alone matches everything
    ("sts:AssumeRole", "sts:*", True),             # service wildcard
    ("sts:AssumeRole", "sts:Assume*", True),       # partial wildcard
    ("s3:GetObject", "sts:*", False),              # wrong service
    ("sts:Assume", "sts:AssumeRole", False),       # value shorter than pattern
    ("sts:AssumeRole", "sts:Assume", False),       # fullmatch, not prefix match
    ("ec2:DescribeVpc", "ec2:DescribeVp?", True),  # ? = exactly one character
    ("ec2:DescribeVpcs", "ec2:DescribeVp?", False),# two characters left, ? allows one
    ("ec2:DescribeVp", "ec2:DescribeVp?", False),  # zero characters left, ? needs one
])
def test_wildcards(value, pattern, expected):
    assert matches_pattern(value, pattern) is expected


# ---------- matches_pattern: special characters are literal ----------

def test_square_brackets_are_literal():
    pattern = "arn:aws:s3:::my[1]bucket"
    assert matches_pattern("arn:aws:s3:::my[1]bucket", pattern) is True
    assert matches_pattern("arn:aws:s3:::my1bucket", pattern) is False


def test_dot_is_literal():
    assert matches_pattern("a.b", "a.b") is True
    assert matches_pattern("axb", "a.b") is False


# ---------- case rules ----------

def test_case_sensitive_by_default():
    assert matches_pattern("sts:assumerole", "sts:AssumeRole") is False


def test_case_insensitive_when_requested():
    assert matches_pattern("sts:assumerole", "sts:AssumeRole", case_sensitive=False) is True


# ---------- action_matches ----------

def test_action_matches_ignores_case():
    assert action_matches("sts:AssumeRole", "STS:assumerole") is True


def test_action_matches_wildcard():
    assert action_matches("sts:AssumeRole", "sts:*") is True


def test_action_matches_wrong_service():
    assert action_matches("s3:GetObject", "sts:*") is False


# ---------- resource_matches ----------

def test_resource_exact_match():
    assert resource_matches(ROLE, ROLE) is True


def test_resource_wildcard():
    assert resource_matches("arn:aws:iam::123456789012:role/App-Web",
                            "arn:aws:iam::123456789012:role/App-*") is True


def test_resource_wrong_role_does_not_match():
    assert resource_matches("arn:aws:iam::123456789012:role/testrole2", ROLE) is False


def test_resource_is_case_sensitive():
    assert resource_matches("arn:aws:iam::123456789012:role/TestRole", ROLE) is False


def test_resource_star_matches_any_role():
    assert resource_matches(ROLE, "*") is True