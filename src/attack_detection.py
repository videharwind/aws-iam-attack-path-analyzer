from graph import build_graph 
from IAM_Inventory import filter_inventory


def can_assume(user,role,graph):
    
'''
def detect_direct_assumerole(source_arn,privilege_targets,graph):
    findings = []   
    for target in graph.successors(source_arn):
        edge_type = graph.edges[source_arn,target]["type"]
        if target in privilege_targets and edge_type == "trusted-to-assume":
            findings.append(
                {
                    "source":source_arn,
                    "target": target,
                    "via":[source_arn,target],
                    "technique" : "AssumeRole"
                }
            )
    return findings


filterinventory = filter_inventory()
graph = build_graph(filterinventory)
print(detect_direct_assumerole("arn:aws:iam::944146429179:user/testuser",["arn:aws:iam::944146429179:role/testrole"],graph))
'''