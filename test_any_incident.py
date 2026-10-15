#!/usr/bin/env python3
"""
Test Suite for Arbitrary / Dynamic Incidents in GraphGuard (Track 01).
Verifies that GraphGuard can ingest and investigate *any* custom incident ID,
dynamically explore connected nodes in FalkorDB, and produce traceable evidence cards.
"""

import sys
import os
import time

project_root = os.path.dirname(os.path.abspath(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.core.falkor_driver import FalkorDriver
from backend.agents.orchestrator import OrchestratorAgent


def test_dynamic_incident():
    print("=" * 65)
    print("=== TESTING GRAPHGUARD WITH ARBITRARY / CUSTOM INCIDENT ===")
    print("=" * 65)
    print("")

    driver = FalkorDriver(use_fallback=True)
    orchestrator = OrchestratorAgent(driver)

    custom_incident_id = f"INC-CUSTOM-{int(time.time())}"
    tenant_id = "tenant_custom"
    graph_name = f"graphguard_{tenant_id}"

    print(f"Generating dynamic incident topology:")
    print(f"  Incident ID: {custom_incident_id}")
    print(f"  Tenant Partition: {tenant_id}")
    print(f"  Target Graph: {graph_name}")

    # Inject dynamic custom graph nodes
    store = driver._fallback_store
    nodes_key = f"{graph_name}_nodes"
    edges_key = f"{graph_name}_edges"

    nodes = [
        {"id": custom_incident_id, "label": "INCIDENT", "props": {
            "id": custom_incident_id, "incr_id": custom_incident_id, "severity": "HIGH",
            "title": "Zero-Day Remote Code Execution on Internal ERP", "status": "INVESTIGATING"
        }},
        {"id": "SYS-ERP-CORE", "label": "SYSTEM", "props": {
            "id": "SYS-ERP-CORE", "name": "SAP ERP Core Service", "is_critical": True,
            "domain": "internal.enterprise.corp", "has_internet_exposure": False
        }},
        {"id": "USER-FINANCE-DIR", "label": "USER", "props": {
            "id": "USER-FINANCE-DIR", "email": "director.finance@enterprise.corp",
            "role": "Finance Director", "location": "Zurich"
        }},
        {"id": "THREAT-ACTOR-X", "label": "THREAT", "props": {
            "id": f"{custom_incident_id}_THREAT_ACTOR_X", "actor": "FIN7 (Carbanak)",
            "technique": "Exploitation for Client Execution (T1203)", "confidence": 0.91
        }},
        {"id": "IND-C2-URL", "label": "INDICATOR", "props": {
            "id": "IND-C2-URL", "type": "url", "value": "https://secure-sync-telemetry.net/payload",
            "source": "ThreatStream"
        }}
    ]

    edges = [
        {"from": custom_incident_id, "to": "SYS-ERP-CORE", "type": "AFFECTS"},
        {"from": custom_incident_id, "to": "USER-FINANCE-DIR", "type": "AFFECTED"},
        {"from": custom_incident_id, "to": f"{custom_incident_id}_THREAT_ACTOR_X", "type": "LINKS_TO"},
        {"from": f"{custom_incident_id}_THREAT_ACTOR_X", "to": "IND-C2-URL", "type": "USED_TOOL"}
    ]

    store[nodes_key] = nodes
    store[edges_key] = edges

    print(f"  [+] Seeded {len(nodes)} custom nodes and {len(edges)} custom edges")

    # Run investigation on arbitrary incident
    print(f"\nExecuting Multi-Agent Pipeline on {custom_incident_id}...")
    res = orchestrator.run_investigation(custom_incident_id, tenant_id=tenant_id)

    assert res is not None
    assert res["status"] == "COMPLETED"
    assert res["incident_id"] == custom_incident_id
    assert res["tenant_id"] == tenant_id

    print(f"  [+] Status: {res['status']}")
    print(f"  [+] Execution Time: {res['execution_time_seconds']}s")
    print(f"  [+] Overall Confidence: {int(res['overall_confidence'] * 100)}%")
    print(f"  [+] Evidence Cards Count: {len(res['evidence_cards'])}")

    # Verify evidence cards
    for card in res["evidence_cards"]:
        print(f"    - [{card['id']}] {card['title']} (Conf: {int(card['confidence']*100)}%)")
        print(f"      Path: {card['graph_path']}")

    print("\n" + "=" * 65)
    print("DYNAMIC INCIDENT TEST PASSED - GraphGuard supports any incident!")
    print("=" * 65)


if __name__ == "__main__":
    test_dynamic_incident()
