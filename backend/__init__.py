"""
GraphGuard Backend Package - Multi-Agent Security Threat Investigation Platform
Track 01: Agents That Act on Connected Data
"""

__version__ = "1.0.0"

# Re-export key components
from backend.core.falkor_driver import FalkorDriver
from backend.core.graph_schema import GraphSchema
from backend.core.seed_data import SeedData
from backend.agents.orchestrator import OrchestratorAgent

__all__ = ["FalkorDriver", "GraphSchema", "SeedData", "OrchestratorAgent"]