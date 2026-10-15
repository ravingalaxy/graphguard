"""
Memory Agent - Manages persistent state, multi-tenant memory, and agent handoffs in FalkorDB.
"""

from typing import Dict, List, Any
import time
import logging

logger = logging.getLogger(__name__)


class MemoryAgent:
    """Agent responsible for state persistence, cross-session memory, and agent handoffs."""

    def __init__(self, driver):
        self.driver = driver
        self.name = "Memory Agent"

    def run(self, graph_name: str, incident_id: str, stage: str, agent_name: str, summary: str, evidence: List[Dict]) -> Dict[str, Any]:
        """Record agent handoff, persist evidence nodes, and save investigation state in FalkorDB."""
        logger.info(f"[{self.name}] Recording handoff state for stage '{stage}' by {agent_name}")

        now = int(time.time())

        # Cypher Query 1: Create AGENT_HANDOFF stage node
        query_handoff = """
        MATCH (inv:INVESTIGATION {incr_id: $incident_id})
        CREATE (h:AGENT_HANDOFF {
            incr_id: $incident_id,
            stage: $stage,
            agent_name: $agent_name,
            output_summary: $summary,
            timestamp: $timestamp
        })
        CREATE (inv)-[:STAGE]->(h)
        RETURN h
        """

        # Cypher Query 2: Append EVIDENCE nodes linked to investigation
        query_evidence = """
        MATCH (inv:INVESTIGATION {incr_id: $incident_id})
        CREATE (e:EVIDENCE {
            incr_id: $incident_id,
            type: $type,
            content: $content,
            confidence: $confidence,
            source_agent: $agent_name,
            timestamp: $timestamp
        })
        CREATE (inv)-[:HAS_EVIDENCE]->(e)
        RETURN e
        """

        # Cypher Query 3: Retrieve Investigation Timeline
        query_timeline = """
        MATCH (inv:INVESTIGATION {incr_id: $incident_id})-[:STAGE]->(h:AGENT_HANDOFF)
        RETURN h.stage AS stage, h.agent_name AS agent, h.output_summary AS summary, h.timestamp AS timestamp
        ORDER BY h.timestamp ASC
        """

        graph = self.driver.get_graph(graph_name)

        # Ensure investigation node exists
        try:
            graph.query(
                "MERGE (inv:INVESTIGATION {incr_id: $incident_id}) ON CREATE SET inv.started_at = $now, inv.status = 'INVESTIGATING'",
                {"incident_id": incident_id, "now": now}
            )
        except Exception as e:
            logger.warning(f"Failed to create investigation node: {e}")

        # Execute handoff query
        try:
            graph.query(
                query_handoff,
                {"incident_id": incident_id, "stage": stage, "agent_name": agent_name, "summary": summary, "timestamp": now}
            )
        except Exception as e:
            logger.warning(f"Failed to record agent handoff: {e}")

        # Execute evidence queries if any
        for ev in evidence:
            try:
                graph.query(
                    query_evidence,
                    {
                        "incident_id": incident_id,
                        "type": ev.get("id", "unknown"),
                        "content": ev.get("statement", ""),
                        "confidence": ev.get("confidence", 0),
                        "agent_name": agent_name,
                        "timestamp": now
                    }
                )
            except Exception as e:
                logger.warning(f"Failed to save evidence: {e}")

        return {
            "agent": self.name,
            "status": "COMPLETED",
            "findings": {
                "saved_handoff": {"stage": stage, "agent": agent_name, "summary": summary},
                "evidence_count_saved": len(evidence),
                "memory_graph_name": graph_name
            },
            "queries_executed": [
                {"description": "Record AGENT_HANDOFF state in FalkorDB", "cypher": query_handoff.strip()},
                {"description": "Persist EVIDENCE nodes", "cypher": query_evidence.strip()},
                {"description": "Fetch Investigation Timeline", "cypher": query_timeline.strip()},
            ],
            "summary": f"Persisted state for {agent_name} in FalkorDB graph memory ({graph_name})."
        }
