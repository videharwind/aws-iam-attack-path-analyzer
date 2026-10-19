from iam_models import TrustPrincipal
def parse_trust_statement(statement_data):
    principal = statement_data.get("Principal")
    if principal is None:
        return []  # no Principal (for example a NotPrincipal statement)

    # "Principal": "*" written as a plain string means "anyone"
    if isinstance(principal, str):
        return [TrustPrincipal(principal_type="AWS", identifier=principal)]

    result = []
    for principal_type, identifier in principal.items():
        identifiers = identifier if isinstance(identifier, list) else [identifier]
        for single_identifier in identifiers:
            result.append(
                TrustPrincipal(principal_type=principal_type, identifier=single_identifier)
            )
    return result



def parse_trust_policy(policy_document):
    trustprincipals = []
    document_statement = policy_document.get('Statement',[])
    if isinstance(document_statement,dict):
        document_statement = [document_statement]
    for statement in document_statement:
        if statement.get('Effect') != "Allow":
            continue
        trustprincipals.extend(parse_trust_statement(statement))

    return trustprincipals

'''
aws_principal_stmt = {
        "Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS":"arn:aws:iam::123456789012:user/testuser"}
    }    
print(parse_trust_statement(aws_principal_stmt))

trust_policy={
    'Version': '2012-10-17', 'Statement': [{'Sid': '', 'Effect': 'Deny', 'Principal': {'Service': 'ec2.amazonaws.com'}, 'Action': 'sts:AssumeRole'}]
    }
print(parse_trust_policy(trust_policy))
'''
