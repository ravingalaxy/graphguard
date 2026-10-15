"""
Pydantic models for GraphGuard API requests and responses.
"""

from pydantic import BaseModel
from typing import List, Dict, Any, Optional
import datetime


class InvestigationRequest(BaseModel):
    incident_id: str
    tenant_id: str = "tenant_east"


class InvestigationResponse(BaseModel):
    incident_id: str
    tenant_id: str
    status: str
    execution_time_seconds: float
    overall_confidence: float
    threat_attribution: Dict[str, Any]
    summary_narrative: str
    evidence_cards: List[Dict[str, Any]]
    agent_timeline: List[Dict[str, Any]]
    all_executed_queries: List[Dict[str, Any]]


class ScenarioRequest(BaseModel):
    scenario_id: str


class EvidenceCard(BaseModel):
    id: str
    title: str
    confidence: float
    statement: str
    source_agent: str
    graph_path: str
    cypher_query: str


class ContainmentActionRequest(BaseModel):
    incident_id: str
    action_type: str = "CONTAIN_ALL"  # ISOLATE_HOST, REVOKE_CREDENTIALS, BLOCK_INDICATOR, CONTAIN_ALL
    target_id: Optional[str] = None
    tenant_id: str = "tenant_east"


class MCPCallRequest(BaseModel):
    tool: str
    arguments: Dict[str, Any] = {}