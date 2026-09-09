from iam_models import TrustPrincipal
def parse_trust_statement(statement_data):
    Principal_dict = statement_data["Principal"]
    principal_type = next(iter(Principal_dict))
    
    identifier = Principal_dict[principal_type]
    return TrustPrincipal(
        principal_type= principal_type,
        identifier= identifier
    )

def parse_trust_policy(policy_document):
    trustprincipals = []
    document_statement = policy_document['Statement']
    for statement in document_statement:
        trustprincipals.append(parse_trust_statement(statement))

    return trustprincipals

#aws_principal_stmt = {"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": {"AWS": "arn:aws:iam::123456789012:user/testuser"}}    
#print(parse_trust_statement(aws_principal_stmt))