"""
Orchestrator Agent - Synthesizes insights from all sub-agents and produces traceable report cards.
"""

from typing import Dict, List, Any
import time
import logging

from .enricher import EnricherAgent
from .threatographer import ThreatographerAgent
from .memory import MemoryAgent

logger = logging.getLogger(__name__)


class OrchestratorAgent:
    """Master Orchestrator Agent for GraphGuard threat investigation."""

    def __init__(self, driver):
        self.driver = driver
        self.name = "Orchestrator Agent"
        self.enricher = EnricherAgent(driver)
        self.threatographer = ThreatographerAgent(driver)
        self.memory = MemoryAgent(driver)

    def run_investigation(self, incident_id: str, tenant_id: str = "tenant_east") -> Dict[str, Any]:
        """Execute complete multi-agent investigation pipeline."""
        start_time = time.time()
        logger.info(f"[{self.name}] Starting investigation pipeline for incident {incident_id} (Tenant: {tenant_id})")

        graph_name = f"graphguard_{tenant_id}"
        agent_timings = {}

        # Step 1: Enricher Agent - Multi-hop Graph Traversal
        enrich_start = time.time()
        enrich_results = self.enricher.run(graph_name, incident_id)
        self.memory.run(
            graph_name=graph_name,
            incident_id=incident_id,
            stage="ENRICHMENT_COMPLETE",
            agent_name=self.enricher.name,
            summary=enrich_results["summary"],
            evidence=[]
        )
        agent_timings['enricher'] = round(time.time() - enrich_start, 3)

        # Step 2: Threatographer Agent - Pattern Recognition & Centrality
        threat_start = time.time()
        threat_results = self.threatographer.run(graph_name, incident_id, enrich_results)
        self.memory.run(
            graph_name=graph_name,
            incident_id=incident_id,
            stage="THREATOGRAPHY_COMPLETE",
            agent_name=self.threatographer.name,
            summary=threat_results["summary"],
            evidence=[]
        )
        agent_timings['threatographer'] = round(time.time() - threat_start, 3)

        # Step 3: Synthesis & Evidence Card Generation
        duration = round(time.time() - start_time, 2)

        # Generate evidence cards dynamically from actual findings
        evidence_cards = []

        # EVID-01: Threat Actor Attribution
        threat_actor = threat_results["findings"].get("primary_actor", "Unknown")
        attack_vector = threat_results["findings"].get("attack_vector", "Unknown")
        threat_confidence = 0.0
        if threat_results["findings"].get("threat_actor"):
            threat_confidence = threat_results["findings"]["threat_actor"][0].get("base_confidence", 0.9)
        # Find associated indicators
        indicators = []
        if threat_results["findings"].get("threat_actor"):
            indicators = threat_results["findings"]["threat_actor"][0].get("associated_indicators", [])
        indicator_str = ", ".join(indicators[:2]) if indicators else "various indicators"

        evidence_cards.append({
            "id": "EVID-01",
            "title": f"Threat Actor Attribution: {threat_actor}",
            "confidence": threat_confidence,
            "statement": f"Incident {incident_id} exhibits {int(threat_confidence*100)}% correlation with {threat_actor} tactics, focusing on {attack_vector} with indicators: {indicator_str}.",
            "source_agent": "Threatographer Agent",
            "graph_path": f"INCIDENT -> LINKS_TO -> THREAT ({threat_actor}) -> USED_TOOL -> INDICATOR ({indicator_str[:50]})",
            "cypher_query": f"MATCH (i:INCIDENT {{incr_id: '{incident_id}'}})-[:LINKS_TO]->(t:THREAT) OPTIONAL MATCH (t)-[:USED_TOOL]->(ind:INDICATOR) RETURN t.actor, t.technique, t.confidence, collect(ind.value)"
        })

        # EVID-02: Blast Radius & Affected Systems
        systems = enrich_results["findings"].get("systems", [])
        critical_systems = [s for s in systems if s.get("is_critical")]
        system_names = [s.get("system_name", s.get("system_id", "")) for s in systems[:2]]
        system_str = " and ".join(system_names) if system_names else "multiple systems"
        evidence_cards.append({
            "id": "EVID-02",
            "title": f"Blast Radius & Affected {'Critical ' if critical_systems else ''}Systems",
            "confidence": 0.95 if critical_systems else 0.85,
            "statement": f"The attack breached {len(systems)} system node(s): {system_str}.",
            "source_agent": "Enricher Agent",
            "graph_path": f"INCIDENT -> AFFECTS -> SYSTEM ({system_names[0] if system_names else 'Unknown'}) -> CONTAINS -> COMPONENT",
            "cypher_query": f"MATCH (i:INCIDENT {{incr_id: '{incident_id}'}})-[:AFFECTS]->(s:SYSTEM) OPTIONAL MATCH (s)-[:CONTAINS]->(c:COMPONENT) RETURN s.name, s.is_critical, c.name, c.affected"
        })

        # EVID-03: Compromised User Identity Accounts
        users = enrich_results["findings"].get("users", [])
        if users:
            user_descs = [f"{u.get('email', u.get('user_id', ''))} - {u.get('role', '')}" for u in users[:2]]
            user_str = ", ".join(user_descs)
            evidence_cards.append({
                "id": "EVID-03",
                "title": "Compromised User Identity Accounts",
                "confidence": 0.88,
                "statement": f"Identified {len(users)} credentialed user account(s): {user_str} with authorized access to affected systems.",
                "source_agent": "Enricher Agent",
                "graph_path": "INCIDENT -> AFFECTED -> USER -> AUTHORIZED_TO -> SYSTEM",
                "cypher_query": f"MATCH (i:INCIDENT {{incr_id: '{incident_id}'}})-[:AFFECTED]->(u:USER) OPTIONAL MATCH (u)-[:AUTHORIZED_TO]->(s:SYSTEM) RETURN u.id, u.email, u.role, collect(s.name)"
            })

        # EVID-04: Historical Incident Correlation
        similar = enrich_results["findings"].get("similar_incidents", [])
        if similar:
            sim = similar[0]
            sim_id = sim.get("similar_id", "Unknown")
            sim_title = sim.get("title", "Unknown")
            sim_severity = sim.get("severity", "UNKNOWN")
            sim_score = sim.get("similarity_score", 0.8)
            evidence_cards.append({
                "id": "EVID-04",
                "title": "Historical Incident Correlation",
                "confidence": sim_score,
                "statement": f"Found {int(sim_score*100)}% structural graph similarity to resolved incident {sim_id} ({sim_title}).",
                "source_agent": "Enricher Agent",
                "graph_path": f"INCIDENT ({incident_id}) -[SIMILAR_TO]-> INCIDENT ({sim_id})",
                "cypher_query": f"MATCH (i1:INCIDENT {{incr_id: '{incident_id}'}})-[r:SIMILAR_TO]->(i2:INCIDENT) RETURN i2.incr_id, i2.title, i2.severity, r.similarity"
            })

        # Record final orchestration state
        self.memory.run(
            graph_name=graph_name,
            incident_id=incident_id,
            stage="INVESTIGATION_SYNTHESIZED",
            agent_name=self.name,
            summary=f"Investigation synthesized with 4 traceable evidence cards in {duration}s.",
            evidence=evidence_cards
        )

        # Calculate overall confidence from threat attribution confidence and evidence quality
        threat_conf = threat_results["findings"].get("attribution_confidence", 0.9)
        # Scale evidence quality: 4 cards = 1.0, fewer = proportionally less
        evidence_quality = min(len(evidence_cards) / 4.0, 1.0)
        overall_conf = round((threat_conf * 0.6 + evidence_quality * 0.4), 2)

        # Determine severity based on systems affected and criticality
        systems = enrich_results["findings"].get("systems", [])
        critical_systems = [s for s in systems if s.get("is_critical")]
        severity = "CRITICAL" if critical_systems else "HIGH" if systems else "MEDIUM"

        return {
            "incident_id": incident_id,
            "tenant_id": tenant_id,
            "graph_name": graph_name,
            "status": "COMPLETED",
            "execution_time_seconds": duration,
            "overall_confidence": round(overall_conf, 2),
            "affected_systems_count": len(enrich_results["findings"].get("systems", [])),
            "compromised_users_count": len(enrich_results["findings"].get("users", [])),
            "threat_attribution": {
                "actor": threat_results["findings"]["primary_actor"],
                "attack_vector": threat_results["findings"]["attack_vector"],
                "severity": severity
            },
            "summary_narrative": (
                f"Incident {incident_id} has been investigated using multi-agent FalkorDB graph traversals. "
                f"The attack was initiated by {threat_results['findings']['primary_actor']} utilizing {threat_results['findings']['attack_vector']}. "
                f"Multi-hop traversals identified {len(enrich_results['findings']['systems'])} affected systems and "
                f"{len(enrich_results['findings']['users'])} compromised user accounts. "
                f"All conclusions are traceable back to raw FalkorDB Cypher query paths."
            ),
            "evidence_cards": evidence_cards,
            "graph_visualization_data": {
                "nodes": self._build_viz_nodes(incident_id, enrich_results, threat_results),
                "edges": self._build_viz_edges(incident_id, enrich_results, threat_results)
            },
            "agent_timeline": [
                {
                    "step": 1,
                    "agent": "Enricher Agent",
                    "action": "Context Discovery & 2-hop Graph Traversal",
                    "status": "COMPLETED",
                    "duration_seconds": agent_timings.get('enricher', 0),
                    "queries_count": len(enrich_results["queries_executed"])
                },
                {
                    "step": 2,
                    "agent": "Threatographer Agent",
                    "action": "Pattern Matching & Centrality Scoring",
                    "status": "COMPLETED",
                    "duration_seconds": agent_timings.get('threatographer', 0),
                    "queries_count": len(threat_results["queries_executed"])
                },
                {
                    "step": 3,
                    "agent": "Memory Agent",
                    "action": "State Persistence & Handoff Logging",
                    "status": "COMPLETED",
                    "duration_seconds": 0,
                    "queries_count": 3
                },
                {
                    "step": 4,
                    "agent": "Orchestrator Agent",
                    "action": "Traceable Evidence Card Synthesis",
                    "status": "COMPLETED",
                    "duration_seconds": round(time.time() - start_time, 3),
                    "queries_count": 1
                }
            ],
            "all_executed_queries": (
                enrich_results["queries_executed"] +
                threat_results["queries_executed"]
            )
        }

    def _build_viz_nodes(self, incident_id, enrich_results, threat_results):
        """Build visualization nodes from investigation results."""
        nodes = []
        # Incident node
        nodes.append({"id": incident_id, "label": "INCIDENT", "name": incident_id, "group": "incident"})
        # System nodes
        for s in enrich_results["findings"].get("systems", []):
            sid = s.get("system_id", s.get("system_name", ""))
            nodes.append({"id": sid, "label": "SYSTEM", "name": s.get("system_name", sid), "group": "system", "is_critical": s.get("is_critical", False)})
        # User nodes
        for u in enrich_results["findings"].get("users", []):
            uid = u.get("user_id", u.get("email", ""))
            nodes.append({"id": uid, "label": "USER", "name": u.get("email", uid), "group": "user", "role": u.get("role", "")})
        # Threat nodes
        actor = threat_results["findings"].get("primary_actor", "Unknown")
        nodes.append({"id": f"threat-{actor}", "label": "THREAT", "name": actor, "group": "threat"})
        # Indicator nodes
        for ind in enrich_results["findings"].get("indicators", []):
            iid = ind.get("value", "")
            nodes.append({"id": f"ind-{iid[:20]}", "label": "INDICATOR", "name": f"{ind.get('type', '')}: {iid[:30]}", "group": "indicator"})
        # Similar incident nodes
        for sim in enrich_results["findings"].get("similar_incidents", []):
            nodes.append({"id": sim.get("similar_id", ""), "label": "INCIDENT", "name": sim.get("similar_id", ""), "group": "historical"})
        return nodes

    def _build_viz_edges(self, incident_id, enrich_results, threat_results):
        """Build visualization edges from investigation results."""
        edges = []
        actor = threat_results["findings"].get("primary_actor", "Unknown")
        # Incident -> Systems
        for s in enrich_results["findings"].get("systems", []):
            sid = s.get("system_id", s.get("system_name", ""))
            edges.append({"source": incident_id, "target": sid, "type": "AFFECTS"})
        # Incident -> Users
        for u in enrich_results["findings"].get("users", []):
            uid = u.get("user_id", u.get("email", ""))
            edges.append({"source": incident_id, "target": uid, "type": "AFFECTED"})
        # Incident -> Threat
        edges.append({"source": incident_id, "target": f"threat-{actor}", "type": "LINKS_TO"})
        # Threat -> Indicators
        for ind in enrich_results["findings"].get("indicators", []):
            iid = ind.get("value", "")
            edges.append({"source": f"threat-{actor}", "target": f"ind-{iid[:20]}", "type": "USED_TOOL"})
        # Incident -> Similar
        for sim in enrich_results["findings"].get("similar_incidents", []):
            edges.append({"source": incident_id, "target": sim.get("similar_id", ""), "type": "SIMILAR_TO"})
        return edges
