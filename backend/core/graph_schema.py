"""
Graph Schema Definitions for GraphGuard.
Defines all node labels, relationship types, and property schemas.
"""

from typing import Dict, List, Any


class GraphSchema:
    """Schema definitions for the GraphGuard threat investigation system."""

    # Node labels
    INCIDENT = "INCIDENT"
    SYSTEM = "SYSTEM"
    COMPONENT = "COMPONENT"
    USER = "USER"
    THREAT = "THREAT"
    INDICATOR = "INDICATOR"
    EVIDENCE = "EVIDENCE"
    INVESTIGATION = "INVESTIGATION"
    AGENT_HANDOFF = "AGENT_HANDOFF"

    # Relationship types
    AFFECTS = "AFFECTS"
    AFFECTED = "AFFECTED"
    LINKS_TO = "LINKS_TO"
    CONTAINS = "CONTAINS"
    EXPOSED_BY = "EXPOSED_BY"
    AUTHORIZED_TO = "AUTHORIZED_TO"
    USED_TOOL = "USED_TOOL"
    PERPETRATED_BY = "PERPETRATED_BY"
    HAS_EVIDENCE = "HAS_EVIDENCE"
    STAGE = "STAGE"
    FOLLOWS = "follows"
    SIMILAR_TO = "SIMILAR_TO"
    ASSOCIATED_WITH = "ASSOCIATED_WITH"
    NOTE = "NOTE"
    HAS_CONFIG = "HAS_CONFIG"

    @staticmethod
    def get_all_labels() -> List[str]:
        return [
            GraphSchema.INCIDENT,
            GraphSchema.SYSTEM,
            GraphSchema.COMPONENT,
            GraphSchema.USER,
            GraphSchema.THREAT,
            GraphSchema.INDICATOR,
            GraphSchema.EVIDENCE,
            GraphSchema.INVESTIGATION,
            GraphSchema.AGENT_HANDOFF,
        ]

    @staticmethod
    def get_all_relationships() -> List[str]:
        return [
            GraphSchema.AFFECTS,
            GraphSchema.AFFECTED,
            GraphSchema.LINKS_TO,
            GraphSchema.CONTAINS,
            GraphSchema.EXPOSED_BY,
            GraphSchema.AUTHORIZED_TO,
            GraphSchema.USED_TOOL,
            GraphSchema.PERPETRATED_BY,
            GraphSchema.HAS_EVIDENCE,
            GraphSchema.STAGE,
            GraphSchema.FOLLOWS,
            GraphSchema.SIMILAR_TO,
            GraphSchema.ASSOCIATED_WITH,
            GraphSchema.NOTE,
            GraphSchema.HAS_CONFIG,
        ]

    @staticmethod
    def get_node_properties() -> Dict[str, Dict[str, str]]:
        return {
            GraphSchema.INCIDENT: {
                "incr_id": "string",
                "ticket_id": "string",
                "severity": "enum",
                "status": "enum",
                "first_seen": "timestamp",
                "last_seen": "timestamp",
                "title": "string",
                "description": "string",
            },
            GraphSchema.SYSTEM: {
                "id": "string",
                "name": "string",
                "domain": "string",
                "is_critical": "boolean",
                "has_internet_exposure": "boolean",
                "last_patched": "timestamp",
            },
            GraphSchema.COMPONENT: {
                "id": "string",
                "name": "string",
                "deployed_at": "timestamp",
                "affected": "boolean",
            },
            GraphSchema.USER: {
                "id": "string",
                "email": "string",
                "role": "enum",
                "location": "string",
                "access_hash": "string",
            },
            GraphSchema.THREAT: {
                "tlp_level": "enum",
                "actor": "string",
                "technique": "enum",
                "confidence": "float",
            },
            GraphSchema.INDICATOR: {
                "type": "enum",
                "value": "string",
                "source": "string",
                "first_seen": "timestamp",
                "last_seen": "timestamp",
            },
            GraphSchema.EVIDENCE: {
                "incr_id": "string",
                "type": "enum",
                "content": "string",
                "confidence": "float",
                "verified": "boolean",
                "timestamp": "timestamp",
                "source_agent": "string",
                "graph_query": "string",
            },
            GraphSchema.INVESTIGATION: {
                "incr_id": "string",
                "started_at": "timestamp",
                "completed_at": "timestamp",
                "status": "enum",
                "tenant_id": "string",
            },
            GraphSchema.AGENT_HANDOFF: {
                "incr_id": "string",
                "stage": "enum",
                "agent_name": "string",
                "input_context": "string",
                "output_summary": "string",
            },
        }