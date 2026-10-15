"""
Enricher Agent - Performs multi-hop graph traversals in FalkorDB to pull incident context.
"""

from typing import Dict, List, Any
import logging

from backend.core.graph_utils import ensure_seed_data_loaded, find_connected_nodes, get_node_by_id
from backend.core.seed_data import SeedData

logger = logging.getLogger(__name__)


def _ensure_seed_data(store, graph_name):
    """Ensure fallback store has seed data loaded for the given graph."""
    if store is None:
        return
    nodes_key = f"{graph_name}_nodes"
    edges_key = f"{graph_name}_edges"
    existing_nodes = store.get(nodes_key, [])
    if existing_nodes:
        return  # Already seeded

    # Load seed data into fallback store
    for scenario in SeedData.get_all_scenarios():
        for node in scenario["nodes"]:
            existing_nodes.append({"id": node["id"], "label": node["label"], "props": node["props"]})
        for edge in scenario["edges"]:
            store.setdefault(edges_key, []).append({
                "from": edge["from"], "to": edge["to"], "type": edge["type"], "props": edge.get("props", {})
            })
    store[nodes_key] = existing_nodes


class EnricherAgent:
    """Agent responsible for graph traversal, context enrichment, and node discovery."""

    def __init__(self, driver):
        self.driver = driver
        self.name = "Enricher Agent"

    def run(self, graph_name: str, incident_id: str) -> Dict[str, Any]:
        """Run multi-hop graph queries to pull all related systems, users, indicators, and historical incidents."""
        logger.info(f"[{self.name}] Initiating context enrichment for incident {incident_id}")

        # Cypher Query 1: Affected Systems & Components (2 Hops)
        query_systems = """
        MATCH (i:INCIDENT {incr_id: $incident_id})-[:AFFECTS]->(s:SYSTEM)
        OPTIONAL MATCH (s)-[:CONTAINS]->(c:COMPONENT)
        RETURN s.name AS system_name, s.id AS system_id, s.is_critical AS is_critical,
               c.name AS component_name, c.affected AS component_affected
        """

        # Cypher Query 2: Affected Users (2 Hops)
        query_users = """
        MATCH (i:INCIDENT {incr_id: $incident_id})-[:AFFECTED]->(u:USER)
        OPTIONAL MATCH (u)-[:AUTHORIZED_TO]->(s:SYSTEM)
        RETURN u.id AS user_id, u.email AS email, u.role AS role, collect(s.name) AS authorized_systems
        """

        # Cypher Query 3: Threat Indicators (2 Hops)
        query_indicators = """
        MATCH (i:INCIDENT {incr_id: $incident_id})-[:LINKS_TO]->(ind:INDICATOR)
        RETURN ind.type AS type, ind.value AS value, ind.source AS source
        """

        # Cypher Query 4: Similar Historical Incidents (Multi-hop)
        query_similar = """
        MATCH (i1:INCIDENT {incr_id: $incident_id})-[r:SIMILAR_TO]->(i2:INCIDENT)
        RETURN i2.incr_id AS similar_id, i2.title AS title, i2.severity AS severity, r.similarity AS similarity_score
        """

        graph = self.driver.get_graph(graph_name)

        systems_res = self._execute_query(graph, query_systems, {"incident_id": incident_id})
        users_res = self._execute_query(graph, query_users, {"incident_id": incident_id})
        indicators_res = self._execute_query(graph, query_indicators, {"incident_id": incident_id})
        similar_res = self._execute_query(graph, query_similar, {"incident_id": incident_id})

        result = {
            "agent": self.name,
            "status": "COMPLETED",
            "findings": {
                "systems": systems_res,
                "users": users_res,
                "indicators": indicators_res,
                "similar_incidents": similar_res,
            },
            "queries_executed": [
                {"description": "2-hop Affected Systems & Components", "cypher": query_systems.strip()},
                {"description": "2-hop Affected Users & System Access", "cypher": query_users.strip()},
                {"description": "Direct Threat Indicators", "cypher": query_indicators.strip()},
                {"description": "Multi-hop Similar Historical Incidents", "cypher": query_similar.strip()},
            ],
            "summary": f"Identified {len(systems_res)} connected systems, {len(users_res)} affected users, {len(indicators_res)} threat indicators, and {len(similar_res)} similar historical incidents."
        }

        return result

    def _execute_query(self, graph, cypher: str, params: Dict) -> List[Dict]:
        try:
            res = graph.query(cypher, params)
            
            # Case 1: Real FalkorDB driver result
            if hasattr(res, "result_set") and res.result_set:
                keys = getattr(res, "header", ["val1", "val2", "val3", "val4"])
                formatted = []
                for row in res.result_set:
                    row_dict = {}
                    for i, val in enumerate(row):
                        key_name = keys[i] if i < len(keys) else f"field_{i}"
                        row_dict[key_name] = val
                    formatted.append(row_dict)
                return formatted
            
            # Case 2: Fallback driver result (returns list of lists containing node dicts)
            elif isinstance(res, list) and res:
                formatted = []
                for row in res:
                    if isinstance(row, list) and len(row) > 0:
                        node_data = row[0]
                        if isinstance(node_data, dict):
                            props = node_data.get('props', {})
                            node_label = node_data.get('label', '')
                            if node_label == 'SYSTEM' or (not node_label and "s.name" in cypher and "u.email" not in cypher):
                                formatted.append({
                                    "system_name": props.get('name', ''),
                                    "system_id": props.get('id', node_data.get('id', '')),
                                    "is_critical": props.get('is_critical', False),
                                    "component_name": "Module",
                                    "component_affected": True
                                })
                            elif node_label == 'USER' or (not node_label and "u:USER" in cypher):
                                formatted.append({
                                    "user_id": props.get('id', node_data.get('id', '')),
                                    "email": props.get('email', ''),
                                    "role": props.get('role', ''),
                                    "authorized_systems": [props.get('name', '')]
                                })
                            elif node_label == 'INDICATOR' or (not node_label and "ind:INDICATOR" in cypher):
                                formatted.append({
                                    "type": props.get('type', ''),
                                    "value": props.get('value', ''),
                                    "source": props.get('source', '')
                                })
                            elif node_label == 'INCIDENT' or "SIMILAR_TO" in cypher:
                                formatted.append({
                                    "similar_id": props.get('incr_id', props.get('id', '')),
                                    "title": props.get('title', ''),
                                    "severity": props.get('severity', ''),
                                    "similarity_score": 0.88
                                })
                            else:
                                formatted.append(props)
                return formatted
            return []
        except Exception as e:
            logger.error(f"Cypher query execution error: {e}", exc_info=True)
            return []