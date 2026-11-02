from policy_matcher import action_matches,resource_matches
from trust_policy_parser import parse_trust_policy
from iam_models import CanAssumeEdge
def find_assume_permissions(permissions,role_arn):
    result = []
    for permission in permissions:
        if action_matches("sts:AssumeRole",permission.action) and resource_matches(role_arn,permission.resource):
            result.append(permission) 
    return result

def account_id_from(identifier):
    if len(identifier) == 12 and identifier.isdigit():
        account_id = identifier
        return account_id
    
    splits = identifier.split(":")
    if len(splits)>=5 and splits[0] == "arn" and splits[4].isdigit():
        accound_id = splits[4]
        return accound_id

    return None
    
def classify_trust(trust_principles,role_arn,principal_arn):
    role_account = account_id_from(role_arn)
    caller_account = account_id_from(principal_arn)
    result = "none"

    for trust_principle in trust_principles:
        if trust_principle.principal_type != "AWS":
            continue
        ident = trust_principle.identifier
        if ident == principal_arn:
            if caller_account is not None and caller_account == role_account:
                result = "direct"
                return result
            else:
                result = "needs-permission"
        if ident == "*":
            result = "needs-permission"
        if (ident.endswith(":root") or (ident.isdigit() and len(ident) == 12)) \
                and caller_account is not None \
                and account_id_from(ident) == caller_account:
            result = "needs-permission"
    return result

def find_can_assume(inventory,permission_map):
    edges = []
    caller_list = inventory.users + inventory.roles
    for role in inventory.roles:
        trust_principles = parse_trust_policy(role.trust_policy)
        for caller in caller_list:
            if caller.arn == role.arn:
                continue
            trust_level = classify_trust(trust_principles=trust_principles,role_arn=role.arn,principal_arn=caller.arn)
            if trust_level == "none":
                continue
            elif trust_level == "direct":
                temp_edge = CanAssumeEdge(source=caller.arn,target=role.arn,reason = "direct-trust",evidence=[])
                edges.append(temp_edge)
            elif trust_level == "needs-permission":
                permissions = permission_map.get(caller.arn,[])
                assume_permissions = find_assume_permissions(permissions=permissions,role_arn=role.arn)
                if len(assume_permissions) != 0:
                    temp_edge = CanAssumeEdge(source=caller.arn,target=role.arn,reason="trust-and-permission",evidence=assume_permissions)
                    edges.append(temp_edge)
                
    return edges

#filterinventory = filter_inventory()
#print(find_can_assume(filterinventory,build_permission_map(filterinventory)))

'''
filterinventory = filter_inventory()
testuser = next(user for user in filterinventory.users if user.name == "testuser")
result = find_assume_permissions(resolve_user_permissions(testuser,filterinventory),"arn:aws:iam::944146429179:role/testrole")
print(result)
'''

