#!/usr/bin/env python3
"""
Comprehensive API & MCP Endpoint Test Suite for GraphGuard (Track 01).
Tests all REST endpoints, FalkorDB queries, MCP tool execution, and containment actions.
"""

import sys
import os

project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from fastapi.testclient import TestClient
from backend.api.server import app


def test_api():
    print("=" * 70)
    print("=== GRAPHGUARD FULL API & MCP ENDPOINT VERIFICATION ===")
    print("=" * 70)
    print("")

    client = TestClient(app)
    results = []

    # 1. Health Endpoint
    res = client.get("/api/health")
    ok = res.status_code == 200 and res.json().get("status") == "healthy"
    print(f"1. Health Check (/api/health): {res.status_code} -> {'PASS' if ok else 'FAIL'}")
    results.append(("Health Check", ok))

    # 2. Scenarios Endpoint
    res = client.get("/api/scenarios")
    ok = res.status_code == 200 and len(res.json().get("scenarios", [])) >= 2
    print(f"2. Scenarios (/api/scenarios): {res.status_code} ({len(res.json().get('scenarios', []))} scenarios) -> {'PASS' if ok else 'FAIL'}")
    results.append(("Scenarios List", ok))

    # 3. Seed Scenario Endpoint
    res = client.post("/api/seed/INC-2026-0447")
    ok = res.status_code == 200 and res.json().get("success") is True
    print(f"3. Seed Scenario (/api/seed/INC-2026-0447): {res.status_code} -> {'PASS' if ok else 'FAIL'}")
    results.append(("Seed Scenario", ok))

    # 4. Multi-Agent Investigation Endpoint
    res = client.post("/api/investigation", json={
        "incident_id": "INC-2026-0447",
        "tenant_id": "tenant_east"
    })
    ok = res.status_code == 200 and res.json().get("status") == "COMPLETED"
    print(f"4. Investigation (/api/investigation): {res.status_code} (Status: {res.json().get('status')}) -> {'PASS' if ok else 'FAIL'}")
    results.append(("Investigation Pipeline", ok))

    # 5. List Graphs Endpoint
    res = client.get("/api/graphs")
    ok = res.status_code == 200 and len(res.json().get("graphs", [])) >= 2
    print(f"5. List Graphs (/api/graphs): {res.status_code} -> {'PASS' if ok else 'FAIL'}")
    results.append(("List Graphs", ok))

    # 6. Graph Data Topology Endpoint
    res = client.get("/api/graph-data?graph_name=graphguard_tenant_east")
    ok = res.status_code == 200 and res.json().get("success") is True
    node_count = res.json().get("node_count", 0)
    print(f"6. Graph Data (/api/graph-data): {res.status_code} ({node_count} nodes) -> {'PASS' if ok else 'FAIL'}")
    results.append(("Graph Data Topology", ok))

    # 7. Model Context Protocol Tools Discovery (/api/mcp/tools)
    res = client.get("/api/mcp/tools")
    ok = res.status_code == 200 and len(res.json().get("tools", [])) >= 5
    tool_names = [t["name"] for t in res.json().get("tools", [])]
    print(f"7. MCP Tool Discovery (/api/mcp/tools): {res.status_code} ({len(tool_names)} tools: {', '.join(tool_names[:3])}...) -> {'PASS' if ok else 'FAIL'}")
    results.append(("MCP Tool Discovery", ok))

    # 8. MCP Tool Execution: Blast Radius
    res = client.post("/api/mcp", json={
        "tool": "calculate_blast_radius",
        "arguments": {"incident_id": "INC-2026-0447", "max_hops": 2}
    })
    ok = res.status_code == 200 and res.json().get("isError") is False
    print(f"8. MCP Tool Call (/api/mcp - blast_radius): {res.status_code} (Latency: {res.json().get('latency_ms')}ms) -> {'PASS' if ok else 'FAIL'}")
    results.append(("MCP Blast Radius Call", ok))

    # 9. MCP Tool Execution via Standard JSON-RPC 2.0 format
    res = client.post("/api/mcp", json={
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {
            "name": "calculate_centrality",
            "arguments": {"graph_name": "graphguard_tenant_east"}
        },
        "id": 101
    })
    ok = res.status_code == 200 and res.json().get("result", {}).get("isError") is False
    print(f"9. MCP JSON-RPC 2.0 Tool Call (/api/mcp): {res.status_code} (ID: {res.json().get('id')}) -> {'PASS' if ok else 'FAIL'}")
    results.append(("MCP JSON-RPC Tool Call", ok))

    # 10. Autonomous Containment Action Endpoint
    res = client.post("/api/action/containment", json={
        "incident_id": "INC-2026-0447",
        "action_type": "CONTAIN_ALL",
        "tenant_id": "tenant_east"
    })
    ok = res.status_code == 200 and res.json().get("status") == "CONTAINMENT_SUCCESSFUL"
    mutated = res.json().get("mutated_nodes_count", 0)
    print(f"10. Containment Action (/api/action/containment): {res.status_code} ({mutated} nodes mutated) -> {'PASS' if ok else 'FAIL'}")
    results.append(("Containment Action", ok))

    # 11. HTML Dashboard Endpoint
    res = client.get("/")
    ok = res.status_code == 200 and "GraphGuard" in res.text
    print(f"11. Frontend Dashboard (/): {res.status_code} -> {'PASS' if ok else 'FAIL'}")
    results.append(("Frontend Dashboard", ok))

    print("\n" + "=" * 70)
    all_passed = all(passed for _, passed in results)
    print(f"TOTAL TESTS: {len(results)} | PASSED: {sum(1 for _, p in results if p)} | FAILED: {sum(1 for _, p in results if not p)}")
    print("=" * 70)
    
    if all_passed:
        print("ALL GRAPHGUARD API & MCP ENDPOINTS PASSED WITH 100% SUCCESS!")
    else:
        print("SOME TESTS FAILED - Review logs above.")
        sys.exit(1)


if __name__ == "__main__":
    test_api()
