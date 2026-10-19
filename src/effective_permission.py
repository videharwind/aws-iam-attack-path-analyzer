from iam_models import EffectivePermission
from IAM_Inventory import filter_inventory
from IAM_Enumerator import enumerate_policy_document
from policy_parser import parse_policy
def resolve_user_permissions(user,inventory):
    effective_permissions = []
    policy_path_tuple_list = find_policy_path(user,inventory)
    for policy_path_pair in policy_path_tuple_list:
        temp_effective_permissions = permission_from_policy(policy_arn=policy_path_pair[0],via_path=policy_path_pair[1],identity_arn=user.arn)
        effective_permissions.extend(temp_effective_permissions)
    return effective_permissions

def resolve_role_permission(role,inventory):
    effective_permissions = []
    policy_path_role_tuple_list = find_attached_policy_to_role(role.arn,inventory)
    for policy_path_pair in policy_path_role_tuple_list:
        temp_effective_permissions = permission_from_policy(policy_arn=policy_path_pair[0],via_path=policy_path_pair[1],identity_arn=role.arn)
        effective_permissions.extend(temp_effective_permissions)

    return(effective_permissions)


    

def find_assumable_roles(user_arn,inventory):
    assumable_roles = []
    roles = get_targets(inventory=inventory,source_arn=user_arn,relationship_type='trusted-to-assume')
    assumable_roles.extend(roles)
    return assumable_roles

def find_attached_policy_to_role(identity_arn,inventory):
    policy_path_tuple_list = []
    attached_policies = get_targets(inventory=inventory,source_arn=identity_arn,relationship_type='attached-policy')
    for policy in attached_policies:
        via_path = [identity_arn,policy]
        policy_path_tuple_list.append((policy,via_path))

    return policy_path_tuple_list

        
def find_policy_path_role(identity_arn,inventory):
    policy_path_tuple_list = []
    #finding attached policies to roles
    initial_roles = find_assumable_roles(identity_arn,inventory)

    queue = []
    visited = set()
    for role in initial_roles:
        queue.append((role,[identity_arn,role]))
        visited.add((role))
    
    while queue:
        current_role, current_path = queue.pop(0)

        attached_policies = get_targets(inventory=inventory,source_arn=current_role,relationship_type='attached-policy')
        for policy in attached_policies:
            via_path = current_path + [policy]
            policy_path_tuple_list.append((policy,via_path))

        further_roles = find_assumable_roles(current_role,inventory=inventory)
        for further_role in further_roles:
            if further_role not in visited:
                visited.add(further_role)
                queue.append((further_role,current_path + [further_role]))
    
    return policy_path_tuple_list


def permission_from_policy(policy_arn,via_path,identity_arn):
    policy_document = enumerate_policy_document(policy_arn= policy_arn)
    effectivepermissions = []
    statements = parse_policy(policy_document)
    for statement in statements: 
        if statement.effect != "Allow":
            continue
        for a in statement.action:
            for r in statement.resource:
                effectivepermissions.append(EffectivePermission(
                    identity_arn= identity_arn,
                    action= a,
                    resource= r,
                    via = list(via_path)
                ))
    return effectivepermissions

def get_targets(inventory,source_arn,relationship_type):
    target_arns = []
    for relationship in inventory.relationships:
        if relationship.source == source_arn and relationship.relationship == relationship_type:
            target_arns.append(relationship.target)

    return target_arns

def find_policy_path(user,inventory):
    policy_path_tuple_list = []
    source_arn = user.arn
    #finding attached policies
    direct_attached_policies = get_targets(inventory,source_arn=source_arn,relationship_type='attached-policy')
    for policy in direct_attached_policies:
        via_path = [source_arn,policy]    
        policy_path_tuple_list.append((policy,via_path))

    #finding attached groups
    attached_groups = get_targets(inventory,source_arn=source_arn,relationship_type='member-of')
    for group in attached_groups:
        group_attached_policies = get_targets(inventory,source_arn=group,relationship_type='attached-policy')
        for policy in group_attached_policies:
            via_path = [source_arn,group,policy]
            policy_path_tuple_list.append((policy,via_path))
    return policy_path_tuple_list

def build_permission_map(inventory):
    permission_map = dict() 
    for user in inventory.users:
        temp_permissions = resolve_user_permissions(user,inventory=inventory)
        permission_map[user.arn] = temp_permissions 
    for role in inventory.roles:
        temp_permissions = resolve_role_permission(role,inventory=inventory)
        permission_map[role.arn] = temp_permissions

    return permission_map

#filterinventory = filter_inventory()
#print(build_permission_map(filterinventory))
'''
from iam_models import IAMInventory, IAMRelationship

fake_relationships = [
    IAMRelationship(source="userX", target="roleA", relationship="trusted-to-assume"),
    IAMRelationship(source="roleA", target="roleB", relationship="trusted-to-assume"),
    IAMRelationship(source="roleB", target="roleA", relationship="trusted-to-assume"),  # the cycle
]
fake_inventory = IAMInventory(users=[], groups=[], roles=[], policies=[], relationships=fake_relationships)

result = find_policy_path_role("userX", fake_inventory)
print(result)  # should return (empty, since no policies attached) without hanging
'''
'''
testuser = next(user for user in filterinventory.users if user.name == "testuser")
print(resolve_user_permissions(testuser,filterinventory))
testrole3 = next(role for role in filterinventory.roles if role.name == "testrole3")
print(resolve_role_permission(testrole3,filterinventory))
testrole5 = next(role for role in filterinventory.roles if role.name == "testrole5")
print(resolve_role_permission(testrole5,filterinventory))
'''
'''
print(filterinventory.users)
print(filterinventory.relationships)
targets = get_targets(filterinventory,'arn:aws:iam::944146429179:user/testuser','attached-policy')
print(targets)
'''
'''
print(filterinventory.relationships)
testuser = next(user for user in filterinventory.users if user.name == 'testuser')
print(resolve_role_permissions(testuser,filterinventory))
'''
'''
via_path = ["arn:aws:iam::944146429179:group/testgroup", "arn:aws:iam::944146429179:policy/testpolicy2"]
identity_arn = "arn:aws:iam::944146429179:user/testuser"
policy = IAMPolicy(
    name="testpolicy2",
    arn="arn:aws:iam::944146429179:policy/testpolicy2",
    id="ANPA5XU4DGT5TM5LDWIVB"
)'''
'''
odb_policy = IAMPolicy(name="AmazonODBFullAccess", arn="arn:aws:iam::aws:policy/AmazonODBFullAccess", id="ANPAZKAPJZG4JGUWSXDPO")
result = permission_from_policy(odb_policy, ["<some via path>"], "<some identit y>")
#print(len(result))

iaminventory = filterinventory
testpolicy2 = next(p for p in iaminventory.policies if p.name == "AmazonODBFullAccess")
print(testpolicy2)
#print(enumerate_policy_document('arn:aws:iam::944146429179:policy/testpolicy2'))
#result = permission_from_policy(policy,via_path,identity_arn)
#print(result)
'''