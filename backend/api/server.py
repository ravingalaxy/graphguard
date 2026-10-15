"""
FastAPI REST Server for GraphDB - Multi-Agent Security Investigation Platform.
"""

from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from typing import Dict, Any, List, Optional
import uvicorn
import logging
import sys
import os

# Add project root to Python path
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)

if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.core.falkor_driver import FalkorDriver
from backend.core.graph_schema import GraphSchema
from backend.core.seed_data import SeedData
from backend.agents.orchestrator import OrchestratorAgent
from backend.agents.mcp_tools import GraphGuardMCPTools
from backend.api.models import InvestigationRequest, ContainmentActionRequest, MCPCallRequest

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(
    title="GraphGuard API",
    description="Multi-Agent Security Threat Investigation Platform powered by FalkorDB (Track 01)",
    version="1.0.0"
)

# Mount static files for frontend
frontend_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "frontend")
app.mount("/css", StaticFiles(directory=os.path.join(frontend_path, "css")), name="css")
app.mount("/js", StaticFiles(directory=os.path.join(frontend_path, "js")), name="js")
assets_dir = os.path.join(frontend_path, "assets")
if os.path.exists(assets_dir):
    app.mount("/assets", StaticFiles(directory=assets_dir), name="assets")

# Initialize FalkorDB driver
driver = FalkorDriver(
    host="localhost",
    port=6379,
    db_name="graphguard",
    use_fallback=True
)

# Initialize Fallback Store with Pre-loaded Seed Scenarios
for scenario in SeedData.get_all_scenarios():
    graph_name = f"graphguard_tenant_east"
    store = driver._fallback_store
    nodes_list = store.setdefault(f"{graph_name}_nodes", [])
    for node in scenario["nodes"]:
        # Use top-level id if props.id is not available (for THREAT, INDICATOR, INCIDENT nodes)
        node_id = node["props"].get("id") or node["id"]
        if not any((n["props"].get("id") or n["id"]) == node_id for n in nodes_list):
            nodes_list.append({"id": node["id"], "label": node["label"], "props": node["props"]})
    edges_list = store.setdefault(f"{graph_name}_edges", [])
    for edge in scenario["edges"]:
        if not any(e["from"] == edge["from"] and e["to"] == edge["to"] and e["type"] == edge["type"] for e in edges_list):
            edges_list.append({"from": edge["from"], "to": edge["to"], "type": edge["type"], "props": edge.get("props", {})})

# Initialize Orchestrator and MCP Tools
orchestrator = OrchestratorAgent(driver)
mcp_tools = GraphGuardMCPTools(driver)


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main dashboard HTML."""
    frontend_index_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 
        "frontend", "index.html"
    )
    with open(frontend_index_path, "r", encoding="utf-8") as f:
        return f.read()

@app.get("/api/health")
async def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "falkor_fallback": driver.use_fallback}


class CypherRequest(BaseModel):
    """Request model for executing Cypher queries."""
    graph_name: str
    cypher: str
    params: Optional[Dict[str, Any]] = None


class GraphDataRequest(BaseModel):
    """Request model for adding nodes and edges via GUI."""
    graph_name: str
    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []


@app.post("/api/cypher")
async def execute_cypher(request: CypherRequest):
    """Execute a custom Cypher query against the FalkorDB graph."""
    # Validate Cypher query
    if not request.cypher or not isinstance(request.cypher, str):
        raise HTTPException(status_code=400, detail="Invalid Cypher query")
    
    if len(request.cypher) > 10000:
        raise HTTPException(status_code=400, detail="Cypher query too long")
    
    # Basic Cypher injection prevention - only allow read-only operations
    cypher_upper = request.cypher.upper()
    write_ops = ['DROP', 'DELETE', 'REMOVE', 'CREATE', 'MERGE', 'SET ']
    for op in write_ops:
        if op in cypher_upper:
            raise HTTPException(status_code=403, detail=f"Write operations ({op.strip()}) not allowed via this endpoint")
    
    try:
        graph = driver.get_graph(request.graph_name)
        result = graph.query(request.cypher, request.params or {})
        
        # Debug logging
        logger.info(f"Cypher result type: {type(result)}, value: {result}")
        
        # Handle both FalkorDB result format and fallback driver format
        rows = []
        if hasattr(result, 'result_set') and result.result_set:
            # Real FalkorDB result format
            keys = getattr(result, 'header', ['val1', 'val2', 'val3'])
            for row in result.result_set:
                row_dict = {}
                for i, val in enumerate(row):
                    key_name = keys[i] if i < len(keys) else f"field_{i}"
                    row_dict[key_name] = val
                rows.append(row_dict)
        elif isinstance(result, list) and result:
            # Fallback driver format: list of lists
            logger.info(f"Processing fallback driver result: {len(result)} rows")
            for row in result:
                logger.info(f"Processing row: {row}")
                if isinstance(row, list) and len(row) > 0:
                    # Each row is a list, first element is the node
                    node = row[0]
                    if isinstance(node, dict):
                        rows.append(node)
                    else:
                        rows.append({'value': str(node)})
                else:
                    rows.append({'value': str(row)})
        
        return {
            "success": True,
            "graph_name": request.graph_name,
            "rows": rows,
            "row_count": len(rows)
        }
    except Exception as e:
        logger.error(f"Cypher execution error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/graph-data")
async def add_graph_data(request: GraphDataRequest):
    """Add nodes and edges to the graph via GUI form."""
    try:
        graph = driver.get_graph(request.graph_name)
        added_nodes = []
        added_edges = []
        
        # Add nodes
        for node in request.nodes:
            label = node.get('label', 'Node')
            props = node.get('props', {})
            node_id = props.get('id', f"node_{len(request.nodes)}_{hash(str(props))}")
            
            # Build Cypher for node creation
            prop_str = ', '.join([f"{k}: ${k}" for k in props.keys()])
            cypher = f"MERGE (n:{label} {{id: $id}}) SET n += $props"
            params = {'id': node_id, 'props': props}
            
            graph.query(cypher, params)
            added_nodes.append({'id': node_id, 'label': label, 'props': props})
        
        # Add edges
        for edge in request.edges:
            from_id = edge.get('from')
            to_id = edge.get('to')
            rel_type = edge.get('type', 'RELATED_TO')
            props = edge.get('props', {})
            
            cypher = f"""
            MATCH (from {{id: '{from_id}'}}), (to {{id: '{to_id}'}})
            MERGE (from)-[:{rel_type}]->(to)
            """
            graph.query(cypher)
            added_edges.append({'from': from_id, 'to': to_id, 'type': rel_type})
        
        return {
            "success": True,
            "graph_name": request.graph_name,
            "nodes_added": len(added_nodes),
            "edges_added": len(added_edges),
            "nodes": added_nodes,
            "edges": added_edges
        }
    except Exception as e:
        logger.error(f"Graph data addition error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/graphs")
async def list_graphs():
    """List all available graphs in FalkorDB."""
    return {
        "graphs": [
            {"name": "graphguard_tenant_east", "description": "East Tenant Investigation Graph"},
            {"name": "graphguard_tenant_west", "description": "West Tenant Investigation Graph"}
        ]
    }


@app.get("/api/graph-data")
async def get_graph_data(graph_name: str, node_label: Optional[str] = None):
    """Retrieve all nodes and edges from a graph for visualization."""
    try:
        graph = driver.get_graph(graph_name)
        
        # Helper function to extract nodes from result (handles both FalkorDB and fallback formats)
        def extract_nodes_from_result(result):
            nodes = []
            if hasattr(result, 'result_set') and result.result_set:
                # Real FalkorDB result format
                keys = getattr(result, 'header', ['n'])
                for row in result.result_set:
                    node_data = row[0] if len(row) > 0 else {}
                    if isinstance(node_data, dict):
                        nodes.append(node_data)
                    else:
                        nodes.append({'value': str(node_data)})
            elif isinstance(result, list) and result:
                # Fallback driver format: list of lists
                for row in result:
                    if isinstance(row, list) and len(row) > 0:
                        node_data = row[0]
                        if isinstance(node_data, dict):
                            nodes.append(node_data)
                        else:
                            nodes.append({'value': str(node_data)})
                    else:
                        nodes.append({'value': str(row)})
            return nodes
        
        # Build Cypher query based on label filter
        if node_label:
            cypher = f"MATCH (n:{node_label}) RETURN n LIMIT 100"
        else:
            cypher = "MATCH (n) RETURN n LIMIT 100"
        
        result = graph.query(cypher)
        
        # Extract nodes using helper
        nodes = extract_nodes_from_result(result)
        
        # Also get edges - read directly from fallback store since fallback driver doesn't support relationship queries
        edges = []
        store = driver._fallback_store
        if store:
            graph_edges_key = f"{graph_name}_edges"
            if graph_edges_key in store:
                for edge in store[graph_edges_key]:
                    edges.append({
                        'from': edge.get('from', ''),
                        'to': edge.get('to', ''),
                        'type': edge.get('type', '')
                    })
        
        return {
            "success": True,
            "graph_name": graph_name,
            "nodes": nodes,
            "edges": edges,
            "node_count": len(nodes),
            "edge_count": len(edges)
        }
    except Exception as e:
        logger.error(f"Graph data retrieval error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/investigation", response_model=Dict[str, Any])
async def create_investigation(request: InvestigationRequest):
    """Create and execute a multi-agent security investigation."""
    # Validate incident ID format
    if not request.incident_id or not isinstance(request.incident_id, str):
        raise HTTPException(status_code=400, detail="Invalid incident_id")
    
    if len(request.incident_id) > 100:
        raise HTTPException(status_code=400, detail="incident_id too long")
    
    try:
        result = orchestrator.run_investigation(
            incident_id=request.incident_id,
            tenant_id=request.tenant_id
        )
        return result
    except Exception as e:
        logger.error(f"Investigation error for incident {request.incident_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail="Investigation failed")


@app.post("/api/seed/{scenario_id}", response_model=Dict[str, Any])
async def seed_scenario(scenario_id: str):
    """Seed a pre-built test scenario into the graph."""
    try:
        for scenario in SeedData.get_all_scenarios():
            if scenario["scenario_id"] == scenario_id:
                graph_name = "graphguard_tenant_east"
                logger.info(f"Seeding scenario {scenario_id}")
                # Create investigation node
                logger.info("Creating investigation node")
                try:
                    driver.query(
                        graph_name,
                        """
                        MERGE (i:INVESTIGATION {incr_id: $incident_id})
                        SET i.started_at = $timestamp, i.status = 'INVESTIGATING', i.tenant_id = $tenant_id
                        """,
                        {"incident_id": scenario_id, "timestamp": 1728745600, "tenant_id": "tenant_east"}
                    )
                except Exception as e:
                    logger.error(f"Error creating investigation node: {e}")
                    raise

                # Create incident node
                incident = next((n for n in scenario["nodes"] if n["label"] == "INCIDENT"), None)
                logger.info(f"Creating incident node: {incident['props']}")
                try:
                    # Always convert integer values to strings for the fallback driver
                    safe_props = {k: str(v) if isinstance(v, int) else v for k, v in incident["props"].items()}
                    driver.query(
                        graph_name,
                        """
                        MERGE (i:INCIDENT {incr_id: $id})
                        SET i.ticket_id = $ticket_id, i.severity = $severity, i.status = $status,
                            i.first_seen = $first_seen, i.last_seen = $last_seen, i.title = $title, i.description = $description
                        """,
                        safe_props
                    )
                    logger.info("MERGE with safe props succeeded")
                except Exception as e:
                    logger.error(f"Error creating incident node: {e}")
                    raise

                # Create systems
                for node in scenario["nodes"]:
                    if node["label"] == "SYSTEM":
                        safe_props = {k: str(v) if isinstance(v, int) else v for k, v in node["props"].items()}
                        driver.query(
                            graph_name,
                            "MERGE (s:SYSTEM {id: $id}) SET s.name = $name, s.domain = $domain, s.is_critical = $critical, s.has_internet_exposure = $exposure, s.last_patched = $patched",
                            safe_props
                        )

                # Create components
                for node in scenario["nodes"]:
                    if node["label"] == "COMPONENT":
                        safe_props = {k: str(v) if isinstance(v, int) else v for k, v in node["props"].items()}
                        driver.query(
                            graph_name,
                            "MERGE (c:COMPONENT {id: $id}) SET c.name = $name, c.deployed_at = $deployed, c.affected = $affected",
                            safe_props
                        )

                # Create users
                for node in scenario["nodes"]:
                    if node["label"] == "USER":
                        safe_props = {k: str(v) if isinstance(v, int) else v for k, v in node["props"].items()}
                        driver.query(
                            graph_name,
                            "MERGE (u:USER {id: $id}) SET u.email = $email, u.role = $role, u.location = $location, u.access_hash = $hash",
                            safe_props
                        )

                # Create threats
                for node in scenario["nodes"]:
                    if node["label"] == "THREAT":
                        safe_props = {k: str(v) if isinstance(v, int) else v for k, v in node["props"].items()}
                        safe_props["id"] = scenario_id + "_" + node["id"]
                        driver.query(
                            graph_name,
                            "MERGE (t:THREAT {id: $id}) SET t.actor = $actor, t.technique = $tech, t.confidence = $conf, t.tlp_level = $tlp",
                            safe_props
                        )

                # Create indicators
                for node in scenario["nodes"]:
                    if node["label"] == "INDICATOR":
                        safe_props = {k: str(v) if isinstance(v, int) else v for k, v in node["props"].items()}
                        driver.query(
                            graph_name,
                            "MERGE (ind:INDICATOR {id: $id}) SET ind.type = $type, ind.value = $val, ind.source = $src, ind.first_seen = $first, ind.last_seen = $last",
                            safe_props
                        )

                # Create edges - manually store in fallback store since fallback driver doesn't support relationship queries
                for edge in scenario["edges"]:
                    from_id = edge["from"]
                    to_id = edge["to"]
                    rel_type = edge["type"]
                    edge_data = {"from": from_id, "to": to_id, "type": rel_type}
                    
                    # Store in fallback store
                    store = driver._fallback_store
                    if store:
                        graph_edges_key = f"{graph_name}_edges"
                        if graph_edges_key not in store:
                            store[graph_edges_key] = []
                        store[graph_edges_key].append({"from": from_id, "to": to_id, "type": rel_type})

                return {
                    "success": True,
                    "scenario_id": scenario_id,
                    "title": scenario["title"],
                    "nodes_added": len(scenario["nodes"]),
                    "edges_added": len(scenario["edges"])
                }

        raise HTTPException(status_code=404, detail="Scenario not found")

    except Exception as e:
        logger.error(f"Seed scenario error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scenarios")
async def list_scenarios():
    """List available test scenarios."""
    return {
        "scenarios": [
            {
                "id": "INC-2026-0447",
                "title": "SQL Injection in Payment Gateway (APT29)",
                "severity": "CRITICAL",
                "description": "Exploit targeting Payment Gateway API v2.1"
            },
            {
                "id": "INC-2026-0891",
                "title": "Ransomware Lateral Movement (LAPSUS$)",
                "severity": "CRITICAL",
                "description": "Mimikatz credential dump on Domain Controller"
            }
        ]
    }


# ============================================================================
# Track 01 Specific Endpoints: MCP Tools & Graph-Driven Actions
# ============================================================================

@app.get("/api/mcp/tools")
async def list_mcp_tools():
    """Return standard Model Context Protocol (MCP) tool specifications."""
    return {
        "schema_version": "2024-11-05",
        "provider": "GraphGuard Autonomous Defense (FalkorDB)",
        "tools": mcp_tools.get_tool_definitions()
    }


@app.post("/api/mcp")
async def call_mcp_tool(request: Dict[str, Any]):
    """
    Handle MCP Tool Call requests.
    Supports both standard JSON-RPC format and direct tool execution requests.
    """
    # JSON-RPC format support: {"jsonrpc": "2.0", "method": "tools/call", "params": {"name": "...", "arguments": {...}}, "id": 1}
    if request.get("method") == "tools/call":
        params = request.get("params", {})
        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        call_id = request.get("id", 1)
        res = mcp_tools.call_tool(tool_name, arguments)
        return {
            "jsonrpc": "2.0",
            "id": call_id,
            "result": res
        }
    
    # Direct tool invocation format: {"tool": "...", "arguments": {...}}
    tool_name = request.get("tool") or request.get("name")
    arguments = request.get("arguments") or {}
    if not tool_name:
        raise HTTPException(status_code=400, detail="Missing tool name in MCP request")
    
    return mcp_tools.call_tool(tool_name, arguments)


@app.post("/api/action/containment")
async def execute_containment_action(request: ContainmentActionRequest):
    """
    Execute autonomous containment action based on graph findings.
    Satisfies Track 01 requirement: 'Actions based on what the graph shows'.
    """
    logger.info(f"Executing containment action {request.action_type} for incident {request.incident_id}")
    graph_name = f"graphguard_{request.tenant_id}"
    
    result = mcp_tools._execute_containment(
        incident_id=request.incident_id,
        action_type=request.action_type,
        target_id=request.target_id,
        graph_name=graph_name
    )
    return result


if __name__ == "__main__":
    logger.info("Starting GraphGuard API server...")
    logger.info("Routes: %s", [route.path for route in app.routes])
    logger.info("FalkorDB fallback mode enabled")
    uvicorn.run(app, host="0.0.0.0", port=8000)
