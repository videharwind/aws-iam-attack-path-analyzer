from iam_models import TrustPrincipal
def parse_trust_statement(statement_data):
    Principal_dict = statement_data["Principal"]
    principal_type = next(iter(Principal_dict))
    
    identifier = Principal_dict[principal_type]

    if isinstance(identifier,list):
        identifiers = identifier
    else:
        identifiers = [identifier]

    result = []
    for single_identifier in identifiers:
        result.append(TrustPrincipal(principal_type=principal_type,identifier=single_identifier)) 
    return result


def parse_trust_policy(policy_document):
    trustprincipals = []
    document_statement = policy_document['Statement']
    for statement in document_statement:
        trustprincipals.extend(parse_trust_statement(statement))

    return trustprincipals
'''
aws_principal_stmt = {
        "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "arn:aws:iam::123456789012:user/testuser"}
    }    
print(parse_trust_statement(aws_principal_stmt))

trust_policy={
    'Version': '2012-10-17', 'Statement': [{'Sid': '', 'Effect': 'Allow', 'Principal': {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]
    }
print(parse_trust_policy(trust_policy))
'''    