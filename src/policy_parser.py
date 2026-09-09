from IAM_Enumerator import enumerate_policy_document
from iam_models import IAMStatement
def parse_statement(statement_data):
    effect = statement_data['Effect']
    action = []
    resource = []
    if isinstance(statement_data['Action'],str):
        action.append(statement_data['Action'])
    else:
        action.extend(statement_data['Action'])

    if isinstance(statement_data['Resource'],str):
        resource.append(statement_data['Resource'])
    else:
        resource.extend(statement_data['Resource'])

    return IAMStatement(
        effect = effect,
        action = action,
        resource= resource
    )

def parse_policy(policy_document):
    statements = []
    document_statement = policy_document['Statement']
    for statement in document_statement:
        statements.append(parse_statement(statement))
    return statements

