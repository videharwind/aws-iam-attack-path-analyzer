def test_statement_parser():
    from policy_parser import parse_statement

    statement = {"Effect" : "Deny","Action": "s3:DeleteObject", "Resource" : "*"}
    result = parse_statement(statement)

    assert result.effect == "Deny"
    assert result.action == ["s3:DeleteObject"]
    assert result.resource == ["*"]

def test_parse_policy_testpolicy():
    from policy_parser import parse_policy

    document = {
        'Statement': [
            {'Action': ['ec2:Describe*'], 'Effect': 'Allow', 'Resource': '*'}
        ],
        'Version': '2012-10-17'
    }
    result = parse_policy(document)
    assert result[0].action == ['ec2:Describe*']
    assert result[0].effect == 'Allow'
    assert result[0].resource == ["*"]

def test_trust_policy_statement():
    from trust_policy_parser import parse_trust_statement
    statement = {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "arn:aws:iam::123456789012:user/testuser"}}
    result = parse_trust_statement(statement)
    assert result.principal_type == "AWS"
    assert result.identifier == "arn:aws:iam::123456789012:user/testuser"

def test_trust_policy_parser():
    from trust_policy_parser import parse_trust_policy
    trust_policy={'Version': '2012-10-17', 'Statement': [{'Sid': '', 'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]}
    result = parse_trust_policy(trust_policy)
    assert result[0].principal_type == "Service"
    assert result[0].identifier == 'ec2.amazonaws.com'