#!/usr/bin/env python3
"""
Test Suite for GraphGuard Threat Scenarios (Track 01).
Tests automated multi-agent investigation across all pre-loaded scenarios:
- INC-2026-0447: APT29 Cozy Bear (SQL Injection on Payment Gateway)
- INC-2026-0891: LAPSUS$ Group (Mimikatz Credential Dumping on Domain Controller)
"""

import sys
import os

project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.core.falkor_driver import FalkorDriver
from backend.core.seed_data import SeedData
from backend.agents.orchestrator import OrchestratorAgent


def seed_scenario_to_store(driver, scenario, graph_name):
    store = driver._fallback_store
    nodes_list = store.setdefault(f"{graph_name}_nodes", [])
    for node in scenario["nodes"]:
        node_id = node["props"].get("id") or node["id"]
        if not any((n["props"].get("id") or n["id"]) == node_id for n in nodes_list):
            nodes_list.append({"id": node["id"], "label": node["label"], "props": node["props"]})
    edges_list = store.setdefault(f"{graph_name}_edges", [])
    for edge in scenario["edges"]:
        if not any(e["from"] == edge["from"] and e["to"] == edge["to"] and e["type"] == edge["type"] for e in edges_list):
            edges_list.append({"from": edge["from"], "to": edge["to"], "type": edge["type"], "props": edge.get("props", {})})


def run_scenario_tests():
    print("=" * 65)
    print("=== TESTING GRAPHGUARD MULTI-SCENARIO INVESTIGATIONS ===")
    print("=" * 65)
    print("")

    driver = FalkorDriver(use_fallback=True)
    orchestrator = OrchestratorAgent(driver)
    scenarios = SeedData.get_all_scenarios()

    for idx, sc in enumerate(scenarios, start=1):
        scenario_id = sc["scenario_id"]
        title = sc["title"]
        tenant = "tenant_east" if idx == 1 else "tenant_west"
        graph_name = f"graphguard_{tenant}"

        print(f"--- Running Scenario {idx}: {scenario_id} [{tenant}] ---")
        print(f"Title: {title}")

        # Seed data
        seed_scenario_to_store(driver, sc, graph_name)

        # Run investigation
        res = orchestrator.run_investigation(scenario_id, tenant_id=tenant)
        assert res["status"] == "COMPLETED"
        assert res["incident_id"] == scenario_id
        assert res["tenant_id"] == tenant

        attr = res["threat_attribution"]
        print(f"  [+] Threat Actor: {attr.get('threat_actor')}")
        print(f"  [+] Attack Vector: {attr.get('attack_vector')}")
        print(f"  [+] Severity: {attr.get('severity')}")
        print(f"  [+] Confidence: {int(res['overall_confidence'] * 100)}%")
        print(f"  [+] Evidence Cards Generated: {len(res['evidence_cards'])}")

        # Validate that each evidence card has traceable Cypher and graph paths
        for card in res["evidence_cards"]:
            assert "cypher_query" in card and len(card["cypher_query"]) > 10
            assert "graph_path" in card and len(card["graph_path"]) > 5
            assert card["confidence"] > 0.0

        print(f"  [+] Multi-hop Cypher queries executed: {len(res['all_executed_queries'])}")
        print("  [+] Scenario passed validation successfully!\n")

    print("=" * 65)
    print("ALL SCENARIO TESTS PASSED (100% SUCCESSFUL)")
    print("=" * 65)


if __name__ == "__main__":
    run_scenario_tests()
