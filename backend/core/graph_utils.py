"""
Graph utilities for GraphGuard.
Shared utilities for working with fallback store and seed data.
"""

from typing import Dict, Any
from backend.core.seed_data import SeedData


def ensure_seed_data_loaded(store: Dict[str, Any], graph_name: str) -> None:
    """
    Ensure fallback store has seed data loaded for the given graph.
    Thread-safe and idempotent.
    """
    if store is None:
        return
    
    nodes_key = f"{graph_name}_nodes"
    edges_key = f"{graph_name}_edges"
    
    # Check if already seeded
    existing_nodes = store.get(nodes_key, [])
    if existing_nodes:
        return  # Already seeded
    
    # Load seed data into fallback store
    for scenario in SeedData.get_all_scenarios():
        for node in scenario["nodes"]:
            existing_nodes.append({
                "id": node["id"], 
                "label": node["label"], 
                "props": node["props"]
            })
        for edge in scenario["edges"]:
            store.setdefault(edges_key, []).append({
                "from": edge["from"], 
                "to": edge["to"], 
                "type": edge["type"], 
                "props": edge.get("props", {})
            })
    
    store[nodes_key] = existing_nodes


def get_node_by_id(nodes: list, node_id: str) -> Dict[str, Any]:
    """Find a node by its ID (checks both id field and props.id)."""
    for n in nodes:
        n_id = n.get('props', {}).get('id') or n.get('id')
        if n_id == node_id:
            return n
    return None


def find_connected_nodes(nodes: list, edges: list, start_id: str, max_hops: int = 2, label_filter: str = None) -> list:
    """Find all nodes connected to start_id within max_hops, optionally filtering by label."""
    visited = set()
    queue = [(start_id, 0)]
    result = []
    
    while queue:
        node_id, hop = queue.pop(0)
        if node_id in visited or hop > max_hops:
            continue
        visited.add(node_id)
        
        # Find this node
        node = get_node_by_id(nodes, node_id)
        if node:
            if label_filter is None or node.get('label') == label_filter:
                result.append(node)
        
        # Find neighbors
        if hop < max_hops:
            for edge in edges:
                if edge.get('from') == node_id:
                    queue.append((edge.get('to'), hop + 1))
                if edge.get('to') == node_id:
                    queue.append((edge.get('from'), hop + 1))
    
    return result
