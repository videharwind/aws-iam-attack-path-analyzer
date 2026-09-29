from main import client

def enumerate_users():
    paginator = client.get_paginator('list_users')

    users = []

    page_iterator = paginator.paginate()
    for page in page_iterator:
        users.extend(page['Users'])
    return users

def enumerate_groups():
    paginator = client.get_paginator('list_groups')

    groups = []

    page_iterator = paginator.paginate()
    for page in page_iterator:
        groups.extend(page['Groups'])
    return groups

def enumerate_roles():
    paginator = client.get_paginator('list_roles')

    roles = []

    page_iterator = paginator.paginate()
    for page in page_iterator:
        roles.extend(page['Roles'])
    return roles

def enumerate_policies():
    paginator = client.get_paginator('list_policies')

    policies = []

    page_iterator = paginator.paginate(Scope='Local')
    for page in page_iterator:
        policies.extend(page['Policies'])
    return policies
    

def enumerate_inline_user_policies(user):
    paginator = client.get_paginator('list_user_policies')
    inline_user_policies = []
    page_iterator = paginator.paginate(UserName = user)
    for page in page_iterator:
        inline_user_policies.extend(page['PolicyNames'])
    return inline_user_policies

def enumerate_inline_group_policies(group):
    paginator = client.get_paginator('list_group_policies')
    inline_group_policies = []
    page_iterator = paginator.paginate(GroupName = group)
    for page in page_iterator:
        inline_group_policies.extend(page['PolicyNames'])
    return inline_group_policies

def enumerate_inline_role_policies(role):
    paginator = client.get_paginator('list_role_policies')
    inline_role_policies = []
    page_iterator = paginator.paginate(RoleName = role)
    for page in page_iterator:
        inline_role_policies.extend(page['PolicyNames'])
    return inline_role_policies

def enumerate_instance_profile():
    paginator = client.get_paginator('list_instance_profiles')

    instance_profile = []

    page_iterator = paginator.paginate()
    for page in page_iterator:
        instance_profile.extend(page['InstanceProfiles'])
    return instance_profile
    

def enumerate_attached_user_policies(user):
    paginator = client.get_paginator('list_attached_user_policies')
    attached_policies = []
    page_iterator = paginator.paginate(UserName = user)
    for page in page_iterator:
        attached_policies.extend(page['AttachedPolicies'])
    return attached_policies

def enumerate_attached_group_policies(group):

    paginator = client.get_paginator('list_attached_group_policies')
    attached_policies = []
    page_iterator = paginator.paginate(GroupName = group)
    for page in page_iterator:
        attached_policies.extend(page['AttachedPolicies'])
    return attached_policies

def enumerate_attached_role_policies(role):
    paginator = client.get_paginator('list_attached_role_policies')
    attached_policies = []
    page_iterator = paginator.paginate(RoleName = role)
    for page in page_iterator:
        attached_policies.extend(page['AttachedPolicies'])
    return attached_policies

def enumerate_group_from_user(user):
    paginator = client.get_paginator('list_groups_for_user')
    groups = []
    for page in paginator.paginate(UserName = user):
        groups.extend(page['Groups'])
    return groups

def enumerate_policy_metadata(policy_arn):
    response = client.get_policy(
        PolicyArn = policy_arn
    )
    return response

def enumerate_policy_document(policy_arn):
    policy_metadata = enumerate_policy_metadata(policy_arn)
    version_id = policy_metadata['Policy']['DefaultVersionId']
    response = client.get_policy_version(
        PolicyArn = policy_arn,
        VersionId = version_id
    )
    return response['PolicyVersion']['Document']


#print(enumerate_policy_document('arn:aws:iam::944146429179:policy/testpolicy'))
#print(enumerate_policy_document('arn:aws:iam::aws:policy/job-function/AmazonODBAutonomousDatabaseAdmin'))
#print('_______________________')
'''
print(enumerate_groups())
print('_______________________')

print(enumerate_roles())
print('_______________________')

print(enumerate_policies())
print('_______________________')

print(enumerate_instance_profile())
print('_______________________')
'''
'''
print(enumerate_inline_user_policies("testuser"))
print(enumerate_inline_group_policies("testgroup"))
print(enumerate_inline_role_policies("testrole"))

print(enumerate_attached_user_policies("testuser"))
print(enumerate_attached_group_policies("testgroup"))

print(enumerate_attached_role_policies("testrole2"))
'''