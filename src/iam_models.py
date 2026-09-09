from dataclasses import dataclass
from typing import Optional
from IAM_Enumerator import *
@dataclass
class IAMUser:
    name: str
    id : str
    arn : str

@dataclass
class IAMGroup:
    name :str
    id : str
    arn : str

@dataclass 
class IAMRole:
    name : str
    id :str
    arn: str
    trust_policy : dict = None

@dataclass
class IAMPolicy:
    name :str
    arn : str
    id : Optional[str] = None

@dataclass
class IAMRelationship:
    source: str
    relationship :str
    target:str

@dataclass
class IAMInventory:
    users: list
    groups : list
    roles : list
    policies : list
    relationships : list

@dataclass
class IAMStatement:
    effect : str
    action : list
    resource : list

@dataclass
class TrustPrincipal:
    principal_type: str
    identifier : str

def user_from_aws(user_data):
    return IAMUser(
        name = user_data['UserName'],
        id = user_data['UserId'],
        arn= user_data['Arn']
    )

def group_from_aws(group_data):
    return IAMGroup(
        name= group_data['GroupName'],
        id= group_data['GroupId'],
        arn = group_data['Arn']
    )

def role_from_aws(role_data):
    return IAMRole(
        name= role_data['RoleName'],
        id = role_data['RoleId'],
        arn = role_data['Arn'],
        trust_policy = role_data['AssumeRolePolicyDocument']
    )

def policy_from_list_policy_aws(policy_data):
    return IAMPolicy(
        name= policy_data['PolicyName'],
        id= policy_data['PolicyId'],
        arn = policy_data['Arn']
    )
def policy_from_attached_policy_aws(policy_data):
    return IAMPolicy(
        name = policy_data['PolicyName'],
        arn = policy_data['PolicyArn']
    )

def user_group_relationship(user,group):
    return IAMRelationship(
        source=user.arn,
        relationship = 'member-of',
        target=group.arn
    )

def user_policy_relationship(user,policy):
    return IAMRelationship(
        source= user.arn,
        relationship= 'attached-policy',
        target= policy.arn
    )


def group_policy_relationship(group,policy):
    return IAMRelationship(
        source= group.arn,
        relationship= 'attached-policy',
        target= policy.arn
    )


def role_policy_relationship(role,policy):
    return IAMRelationship(
        source= role.arn,
        relationship= 'attached-policy',
        target= policy.arn
    )

def role_principal_relationship(role,principal):
    return IAMRelationship(
        source = principal.identifier,
        relationship = "trusted-to-assume",
        target= role.arn
    )
'''
aws_users = enumerate_users()
users = []
for user in aws_users:
    users.append(user_from_aws(user))


aws_groups = enumerate_groups()
groups = []
for group in aws_groups:
    groups.append(group_from_aws(group))


print(user_group_relationship(users[1],groups[1]))
print(user_group_relationship(users[1],groups[0]))

aws_roles = enumerate_roles()
roles = []
for role in aws_roles:
    roles.append(role_from_aws(role))

aws_policies = enumerate_policies()
policies = []
for policy in aws_policies:
    policies.append(policy_from_list_policy_aws(policy))

print(users)
print(groups)
print(roles)

'''

