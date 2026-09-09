from iam_models import *
from IAM_Enumerator import *
from trust_policy_parser import parse_trust_policy
def build_inventory():
    users = []
    groups = []
    roles = []
    relationships = []
    policies = []

    userdata = enumerate_users()
    for user in userdata:
        users.append(user_from_aws(user))

    groupdata = enumerate_groups()
    for group in groupdata:
        groups.append(group_from_aws(group))
    
    roledata = enumerate_roles()
    for role in roledata:
        roles.append(role_from_aws(role))
    
    policydata = enumerate_policies()
    for policy in policydata:
        policies.append(policy_from_list_policy_aws(policy))

    for user in users:
        usergroups = enumerate_group_from_user(user.name)
        for groupdata in usergroups:
            group = next(
                group for group in groups
                if group.arn == groupdata['Arn']
            )
            relationships.append(user_group_relationship(user,group))

    for user in users:
        userpolicy = enumerate_attached_user_policies(user.name)
        for policydata in userpolicy:
            policy = next(
                policy for policy in policies
                if policy.arn == policydata['PolicyArn']
            )
            relationships.append(user_policy_relationship(user,policy))

    for group in groups:
        grouppolicy = enumerate_attached_group_policies(group.name)
        for policydata in grouppolicy:
            policy = next(
                policy for policy in policies
                if policy.arn == policydata['PolicyArn']
            )
            relationships.append(group_policy_relationship(group,policy))

    for role in roles:
        rolepolicy = enumerate_attached_role_policies(role.name)
        for policydata in rolepolicy:
            policy = next(
                policy for policy in policies
                if policy.arn == policydata['PolicyArn']
            )
            relationships.append(role_policy_relationship(role,policy))

    for role in roles:
        trust_principal = parse_trust_policy(role.trust_policy)
        for principal in trust_principal:
            relationships.append(role_principal_relationship(role,principal))

    return IAMInventory(
        users = users,
        groups = groups,
        roles = roles,
        policies = policies,
        relationships = relationships
    )

iaminventory = build_inventory()
print(iaminventory.relationships)