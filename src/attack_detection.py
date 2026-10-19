from graph import build_graph 
from IAM_Inventory import filter_inventory

def detect_direct_assumerole(source_arn,privilege_targets,graph):
    findings = []   
    for target in graph.successors(source_arn):
        if target in privilege_targets and graph.has_edge(source_arn,target,key = "trusted-to-assume"):
            findings.append(
                {
                    "source":source_arn,
                    "target": target,
                    "via":[source_arn,target],
                    "technique" : "AssumeRole"
                }
            )
    return findings


