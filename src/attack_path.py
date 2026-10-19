from assume_role import find_can_assume
import networkx as nx
from graph import build_graph
from IAM_Inventory import filter_inventory
from pyvis.network import Network
from effective_permission import build_permission_map
TRAVERSABLE_EDGE_TYPES = frozenset({"can-assume"})

def add_can_assume_edges(graph,can_assume_edges):
    newgraph = graph
    for edge in can_assume_edges:
        if edge.source not in newgraph or edge.target not in newgraph:
            raise ValueError(
                f"can-assume edge reference unknown identity: "
                f"{edge.source} -> {edge.target}"
            )
    for edge in can_assume_edges:
        if edge.source in newgraph and edge.target in newgraph:
            newgraph.add_edge(edge.source,edge.target,key = 'can-assume',type="can-assume",reason=edge.reason,evidence=edge.evidence)

    return newgraph

def attack_view(graph):
    
    def filter_node(n):
        if graph.nodes[n]['type'] == 'User' or graph.nodes[n]['type'] == "Role":
            return True
        else:
            return False
    def filter_edge(source,target,key):
        return key in TRAVERSABLE_EDGE_TYPES
    
    view = nx.subgraph_view(
        graph,
        filter_node=filter_node,
        filter_edge=filter_edge
    )
    return view        

def find_reachable(graph,source_arn,max_hops = None):
    view = attack_view(graph)
    if source_arn not in view:
        raise ValueError("source node not present in graph view")
    if max_hops is not None and max_hops <0:
        raise ValueError("Max Hop can not be negative")
    reachables = nx.single_source_shortest_path(view,source_arn,cutoff=max_hops)
    reachables.pop(source_arn)
    return reachables
    


graph = attack_view(add_can_assume_edges(build_graph(filter_inventory()),find_can_assume(filter_inventory(),build_permission_map(filter_inventory()))))
print(find_reachable(graph,'arn:aws:iam::944146429179:user/testuser2'))
nt = Network(directed = True)
nt.from_nx(graph)
nt.write_html('nx2.html',notebook = False)


