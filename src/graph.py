from IAM_Inventory import filter_inventory
import networkx as nx
from pyvis.network import Network
def build_graph(inventory):
    graph = nx.MultiDiGraph()
    
    for user in inventory.users:
        graph.add_node(user.arn,type = "User", name = user.name)
    for group in inventory.groups:
        graph.add_node(group.arn,type= "Group",name = group.name)
    for role in inventory.roles:
        graph.add_node(role.arn,type="Role",name = role.name)
    for policy in inventory.policies:
        graph.add_node(policy.arn,type="Policy",name = policy.name)
    
    for relationship in inventory.relationships:
        if relationship.source not in graph.nodes():
            graph.add_node(relationship.source,type="Service",name = relationship.source)
        if relationship.target not in graph.nodes():
            graph.add_node(relationship.target,type="Service",name = relationship.target)
        graph.add_edge(relationship.source,relationship.target,key=relationship.relationship,type = relationship.relationship)
    
    return graph

graph = build_graph(filter_inventory())
print(graph.edges.data())
'''
graph = build_graph(filterinventory)
nt = Network(directed = True)
nt.from_nx(graph)
nt.write_html('nx.html',notebook = False)
'''
'''
print(list(graph.successors("arn:aws:iam::944146429179:user/testuser2")))
print(list(graph.predecessors("arn:aws:iam::944146429179:role/testrole")))
print(nx.has_path(graph,'arn:aws:iam::944146429179:user/testuser2','arn:aws:iam::944146429179:role/testrole5'))
print(graph.number_of_edges())
'''