"""
FalkorDB Driver - Core database abstraction layer for GraphGuard.
Handles connection management, multi-graph isolation, and Cypher execution.
"""

import os
import logging
import threading
from typing import Any, Dict, List, Optional, Union
from falkordb import FalkorDB

logger = logging.getLogger(__name__)


class FalkorDriver:
    """Production-grade FalkorDB driver with multi-graph support and fallback."""

    def __init__(
        self,
        host: str = None,
        port: int = None,
        db_name: str = "graphguard",
        use_fallback: bool = True,
    ):
        self.host = host or os.getenv("FALKOR_HOST", "localhost")
        self.port = int(port or os.getenv("FALKOR_PORT", 6379))
        self.password = os.getenv("FALKOR_PASSWORD", None)
        self.username = os.getenv("FALKOR_USERNAME", None)
        self.db_name = db_name
        self.use_fallback = use_fallback
        self._db: Optional[FalkorDB] = None
        self._graphs: Dict[str, Any] = {}
        self._fallback_store: Dict[str, List[Dict]] = {} if use_fallback else None
        self._lock = threading.Lock() if use_fallback else None

    @property
    def db(self) -> FalkorDB:
        if self._db is None:
            self._connect()
        return self._db

    def _connect(self):
        try:
            connect_kwargs = {}
            if self.password:
                connect_kwargs["password"] = self.password
            if self.username:
                connect_kwargs["username"] = self.username
            self._db = FalkorDB(host=self.host, port=self.port, **connect_kwargs)
            logger.info(f"Connected to FalkorDB at {self.host}:{self.port}")
        except Exception as e:
            logger.error(f"FalkorDB connection failed: {e}")
            if self.use_fallback:
                logger.warning("Using in-memory fallback store")
                self._db = None
            else:
                raise

    def get_graph(self, name: str):
        """Get or create a graph by name (supports multi-graph isolation)."""
        if name not in self._graphs:
            if self._db is not None:
                try:
                    self._graphs[name] = self._db.select_graph(name)
                except Exception as e:
                    logger.warning(f"Graph {name} selection failed: {e}, using fallback")
                    self._graphs[name] = _FallbackGraph(name, self._fallback_store)
            else:
                self._graphs[name] = _FallbackGraph(name, self._fallback_store)
        return self._graphs[name]

    def select_graph(self, name: str):
        return self.get_graph(name)

    def query(self, graph_name: str, cypher: str, params: Optional[Dict] = None):
        graph = self.get_graph(graph_name)
        return graph.query(cypher, params or {})

    def create_graph(self, name: str):
        """Create a new graph (no-op for FalkorDB, graphs are created on first write)."""
        if name not in self._graphs:
            self.get_graph(name)
        return self._graphs.get(name)

    def close(self):
        if self._db is not None:
            try:
                self._db.close()
            except Exception:
                pass
        self._graphs.clear()


class _FallbackGraph:
    """In-memory fallback graph for testing when FalkorDB is unavailable."""

    def __init__(self, name: str, store: Dict):
        self.name = name
        self.store = store
        self._lock = threading.Lock()
        self.nodes: List[Dict] = store.setdefault(f"{name}_nodes", [])
        self.edges: List[Dict] = store.setdefault(f"{name}_edges", [])

    def query(self, cypher: str, params: Optional[Dict] = None) -> List[List]:
        """Execute a simplified Cypher-like query on the fallback store."""
        params = params or {}
        cypher = cypher.strip()

        with self._lock:
            if cypher.upper().startswith("CREATE") or cypher.upper().startswith("MERGE"):
                return self._handle_create(cypher, params)
            elif cypher.upper().startswith("MATCH"):
                if "CREATE" in cypher.upper():
                    return self._handle_create(cypher, params)
                return self._handle_match(cypher, params)
            elif cypher.upper().startswith("CALL"):
                return self._handle_call(cypher, params)
            else:
                return [[]]

    def _handle_create(self, cypher: str, params: Dict) -> List[List]:
        # Simplified CREATE handler
        import re
        # Extract node patterns like (n:Label {key: value})
        node_pattern = re.findall(r'\((\w+)(?::(\w+))?(?:\s*\{([^}]+)\})?\)', cypher)
        created_nodes = []
        for var, label, props in node_pattern:
            if not label:
                continue
            node = {"id": var, "label": label, "props": {}}
            if props:
                for kv in re.findall(r'(\w+):\s*([^,}\n]+)', props):
                    key, val = kv[0].strip(), kv[1].strip()
                    val_cleaned = val.strip("',\"")
                    if val_cleaned.startswith('$'):
                        param_name = val_cleaned[1:]
                        node["props"][key] = params.get(param_name, val_cleaned)
                    else:
                        node["props"][key] = params.get(val_cleaned, val_cleaned)
            # Assign id if specified in props
            if "id" in node["props"]:
                node["id"] = node["props"]["id"]
            elif "incr_id" in node["props"]:
                node["id"] = f"{var}_{node['props']['incr_id']}"
            self.nodes.append(node)
            created_nodes.append(node)

        # Extract relationship patterns like (a)-[:TYPE]->(b)
        edge_pattern = re.findall(r'\((\w+)\)-\[:(\w+)\]->\((\w+)\)', cypher)
        for from_var, rel_type, to_var in edge_pattern:
            from_id = params.get("incident_id", from_var)
            to_id = created_nodes[-1]["id"] if created_nodes else to_var
            self.edges.append({"from": from_id, "to": to_id, "type": rel_type, "props": {}})

        return [[n] for n in created_nodes] if created_nodes else [[]]

    def _handle_match(self, cypher: str, params: Dict) -> List[List]:
        """Execute MATCH query with proper filtering based on patterns and params."""
        cypher_upper = cypher.upper()
        if "RETURN" not in cypher_upper:
            return [[]]

        # Extract the MATCH pattern - look for patterns like (var:Label {prop: $param})
        import re

        # Find incident_id filter if present
        incident_id = params.get('incident_id', '')

        # Find all node patterns in MATCH clause
        match_section = cypher
        if "MATCH" in cypher_upper:
            match_section = cypher[cypher_upper.index("MATCH"):]

        # Check if we're filtering by incident ID
        has_incident_filter = '$incident_id' in cypher or "'$incident_id'" in cypher or '"$incident_id"' in cypher
        if not has_incident_filter and incident_id:
            has_incident_filter = f"'{incident_id}'" in cypher or f'"{incident_id}"' in cypher

        # Find OPTIONAL MATCH patterns too
        optional_patterns = re.findall(r'OPTIONAL\s+MATCH\s+([^\n]+)', cypher, re.IGNORECASE)

        # Determine what to return
        return_vars = []
        return_match = re.search(r'RETURN\s+(.+?)(?:\s+LIMIT|\s+ORDER|\s+WHERE|$)', cypher, re.IGNORECASE | re.DOTALL)
        if return_match:
            return_clause = return_match.group(1).strip()
            # Extract variable names from RETURN clause
            return_vars = [v.strip().split(' AS ')[0].strip() for v in return_clause.split(',')]

        # If filtering by incident ID, find nodes connected to that incident
        if has_incident_filter and incident_id:
            # Find the incident node
            incident_node = None
            for n in self.nodes:
                if n.get('props', {}).get('incr_id') == incident_id or n.get('props', {}).get('id') == incident_id:
                    incident_node = n
                    break

            if incident_node is None:
                return [[]]

            # Find nodes connected via edges
            connected_nodes = []
            visited = set()
            queue = [incident_node['props'].get('id', incident_node.get('id'))]

            # Determine hop depth from query
            max_hops = 2
            if '*1..3' in cypher or '*1..3' in cypher_upper:
                max_hops = 3
            elif '*1..2' in cypher or '*2' in cypher:
                max_hops = 2

            # BFS to find connected nodes
            for hop in range(max_hops):
                next_queue = []
                for node_id in queue:
                    if node_id in visited:
                        continue
                    visited.add(node_id)
                    # Find this node
                    current_node = None
                    for n in self.nodes:
                        if n.get('props', {}).get('id') == node_id or n.get('id') == node_id:
                            current_node = n
                            break
                    if current_node:
                        connected_nodes.append(current_node)
                    # Find neighbors
                    for edge in self.edges:
                        if edge.get('from') == node_id:
                            next_queue.append(edge.get('to'))
                        if edge.get('to') == node_id:
                            next_queue.append(edge.get('from'))
                queue = next_queue

            # Filter connected_nodes to match the target label from RETURN clause or first MATCH
            target_label = self._extract_target_label(cypher)
            if target_label:
                connected_nodes = [n for n in connected_nodes if n.get('label') == target_label]

            # Return the connected nodes
            if connected_nodes:
                return [[n] for n in connected_nodes]
            return [[]]

        # No incident filter - return all nodes matching target label
        target_label = self._extract_target_label(cypher)
        filtered_nodes = self.nodes
        if target_label:
            filtered_nodes = [n for n in self.nodes if n.get('label') == target_label]

        return [[n] for n in filtered_nodes]

    def _extract_target_label(self, cypher: str) -> str:
        """Extract the primary target label from Cypher query.
        Prefers label from RETURN clause variables, then first MATCH pattern (non-OPTIONAL)."""
        import re
        
        # Try to get label from RETURN clause variables
        return_match = re.search(r'RETURN\s+(.+?)(?:\s+LIMIT|\s+ORDER|\s+WHERE|$)', cypher, re.IGNORECASE | re.DOTALL)
        if return_match:
            return_clause = return_match.group(1).strip()
            # Extract variable names from RETURN (e.g., "s.name" -> "s")
            return_vars = [v.strip().split('.')[0].split(' AS ')[0].strip() for v in return_clause.split(',')]
            if return_vars:
                # Find the label for the first return variable in MATCH clause
                for var in return_vars:
                    # Look for pattern (var:Label) in non-OPTIONAL MATCH
                    match_pattern = rf'\(\s*{re.escape(var)}\s*:(\w+)\s*'
                    match = re.search(match_pattern, cypher)
                    if match:
                        return match.group(1)
                    # Also check without parentheses
                    match2 = re.search(rf'{re.escape(var)}\s*:(\w+)', cypher)
                    if match2:
                        return match2.group(1)
        
        # Fallback: find first label in non-OPTIONAL MATCH clause
        match_section = cypher
        if "MATCH" in cypher.upper():
            match_start = cypher.upper().index("MATCH")
            match_section = cypher[match_start:]
            # Skip OPTIONAL MATCH
            if "OPTIONAL MATCH" in match_section.upper():
                opt_start = match_section.upper().index("OPTIONAL MATCH")
                match_section = match_section[:opt_start]
        
        labels = re.findall(r':(\w+)', match_section)
        if labels:
            return labels[0]  # First label in main MATCH
        
        return None

    def _handle_call(self, cypher: str, params: Dict) -> List[List]:
        return [[]]

    def run(self, cypher: str, params: Optional[Dict] = None):
        return self.query(cypher, params)

    def create(self, label: str, props: Dict):
        node = {"id": str(len(self.nodes)), "label": label, "props": props}
        self.nodes.append(node)
        return node

    def add_edge(self, from_id: str, to_id: str, rel_type: str, props: Dict = None):
        edge = {"from": from_id, "to": to_id, "type": rel_type, "props": props or {}}
        self.edges.append(edge)
        return edge