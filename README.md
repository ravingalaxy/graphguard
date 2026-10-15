# GraphGuard 🛡️ — Multi-Agent Threat Intelligence & Autonomous Containment

[![Hackathon](https://img.shields.io/badge/WeMakeDevs-Graph%20Hacks%202026-6366f1.svg)](https://www.wemakedevs.org/hackathons/falkordb)
[![Track](https://img.shields.io/badge/Track%2001-Agents%20That%20Act%20on%20Connected%20Data-22d3ee.svg)](https://www.wemakedevs.org/hackathons/falkordb#tracks)
[![Live Demo](https://img.shields.io/badge/Live%20Demo-graphguard--pro9.onrender.com-success.svg?logo=render)](https://graphguard-pro9.onrender.com/)
[![Database](https://img.shields.io/badge/Powered%20by-FalkorDB%20Graph%20Database-f59e0b.svg)](https://falkordb.com)
[![Protocol](https://img.shields.io/badge/Protocol-MCP%20Model%20Context%20Protocol-10b981.svg)](https://modelcontextprotocol.io)
[![Tests](https://img.shields.io/badge/Tests-11%2F11%20Passing%20(100%25)-brightgreen.svg)](test_all_endpoints.py)
[![Docker](https://img.shields.io/badge/Docker-Optional%20(Auto--Fallback)-blue.svg)](#)

> 🌐 **Live Web Application:** [https://graphguard-pro9.onrender.com/](https://graphguard-pro9.onrender.com/)  
> **Submission for Graph Hacks: Context for AI Agents (Track 01: Agents That Act on Connected Data)**  
> **Core Innovation:** Coordinates 4 collaborative AI agents traversing multi-hop FalkorDB topology to attribute threats, compute blast radiuses, expose tools via Model Context Protocol (MCP), and **autonomously execute real graph containment actions**.

---

## 🎯 Track 01 Rubric Alignment Matrix

| Hackathon Rubric Requirement | How GraphGuard Implements It | Verified In Code |
| :--- | :--- | :--- |
| **Multi-Hop Reasoning** | 3-hop traversal: `(INCIDENT)-[:AFFECTS]->(SYSTEM)-[:CONTAINS]->(COMPONENT)` and `(INCIDENT)-[:LINKS_TO]->(THREAT)-[:USED_TOOL]->(INDICATOR)` | `backend/agents/enricher.py` |
| **Graph Queries & Algorithms as Tools** | Cypher traversals, Breadth-First Shortest Attack Path, Degree & Betweenness Centrality | `backend/agents/threatographer.py`, `mcp_tools.py` |
| **Tool Selection through MCP** | Official **Model Context Protocol (MCP)** tool server (`/api/mcp/tools` & `/api/mcp`) exposing 5 callable graph tools for LLMs | `backend/agents/mcp_tools.py`, `backend/api/server.py` |
| **Actions Based on Connected Data** | Autonomous containment engine that mutates graph state: isolates compromised hosts, revokes user sessions, and blocks C2 indicators | `POST /api/action/containment` |
| **Explainable Results** | 100% deterministic Evidence Cards linking each finding directly to its Cypher traversal path and subgraph provenance | `backend/agents/orchestrator.py` |

---

## 🧠 System Architecture

```
┌────────────────────────────────────────────────────────────────────────┐
│               FRONTEND WORKSPACE (HTML5 / D3.js Force Graph)           │
│  - Interactive Multi-Hop Graph Topology Visualizer                     │
│  - Autonomous Containment Action Trigger Bar                           │
│  - Traceable Evidence Cards with Copyable Cypher Queries               │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTP / REST / MCP
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                        FASTAPI REST & MCP BACKEND                      │
│  - /api/investigation        - /api/action/containment                 │
│  - /api/mcp/tools            - /api/mcp (JSON-RPC 2.0 Call)            │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
    ┌───────────────────────────────┼──────────────────────────────┐
    ▼                               ▼                              ▼
┌──────────────────────┐ ┌──────────────────────┐ ┌──────────────────────┐
│    ENRICHER AGENT    │ │ THREATOGRAPHER AGENT │ │  MCP TOOL PROVIDER   │
│ Multi-Hop Traversal  │ │ Centrality & MITRE   │ │ Tool Selection API   │
└──────────┬───────────┘ └──────────┬───────────┘ └──────────┬───────────┘
           │                        │                        │
           └────────────────────────┼────────────────────────┘
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         FALKORDB GRAPH ENGINE                          │
│  - Multi-tenant isolated subgraphs (graphguard_tenant_east / west)     │
│  - Native Cypher queries & GraphBLAS matrix operations                 │
│  - Node state mutations (ISOLATED, REVOKED, BLOCKED)                   │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start (Zero Friction)

### Prerequisites
- **Python 3.10+** (Tested on Python 3.12)
- **pip**
- *Docker is completely optional:* GraphGuard includes an automatic in-memory fallback driver that faithfully simulates FalkorDB query execution.

### Installation & Run

#### Option A: Local Python Run (Zero Docker Needed)
```bash
cd "GraphGuard"
pip install -r requirements.txt
python main.py
```
*Open [http://localhost:8000](http://localhost:8000) in your browser.*

#### Option B: Full Docker Compose (App + FalkorDB Container)
```bash
docker-compose up --build
```

#### Option C: 1-Click Cloud Deployment
Deploy free to Render or Hugging Face Spaces in under 2 minutes. See [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md).

---

## 🧪 Comprehensive Verification Suite

Run our automated verification suites to validate all components, graph algorithms, and endpoints:

```bash
# 1. Main multi-agent verification (orchestrator, evidence cards, MCP tools, containment)
python test.py

# 2. Multi-scenario verification (APT29 SQLi, LAPSUS$ Active Directory)
python test_scenarios.py

# 3. Dynamic arbitrary incident verification (proves support for custom incidents)
python test_any_incident.py

# 4. Full API & MCP endpoint test (11/11 endpoints passing)
python test_all_endpoints.py
```

---

## 🤖 Model Context Protocol (MCP) Integration

GraphGuard exposes its FalkorDB graph capabilities through the open **Model Context Protocol (MCP)** specification:

### 1. List Available Tools
```bash
curl -X GET http://localhost:8000/api/mcp/tools
```

### 2. Execute a Graph Tool via MCP
```bash
curl -X POST http://localhost:8000/api/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "calculate_blast_radius",
    "arguments": {
      "incident_id": "INC-2026-0447",
      "max_hops": 2
    }
  }'
```

### 3. Standard JSON-RPC 2.0 Format
```bash
curl -X POST http://localhost:8000/api/mcp \
  -H "Content-Type: application/json" \
  -d '{
    "jsonrpc": "2.0",
    "method": "tools/call",
    "params": {
      "name": "calculate_centrality",
      "arguments": { "graph_name": "graphguard_tenant_east" }
    },
    "id": 1
  }'
```

---

## 🚨 Autonomous Containment: Act on Connected Data

GraphGuard doesn't just display data; it **acts on the connected graph topology**:

```bash
curl -X POST http://localhost:8000/api/action/containment \
  -H "Content-Type: application/json" \
  -d '{
    "incident_id": "INC-2026-0447",
    "action_type": "CONTAIN_ALL",
    "tenant_id": "tenant_east"
  }'
```

**Actions Executed:**
1. Mutates compromised system nodes to `status: 'ISOLATED'` in FalkorDB.
2. Revokes compromised user tokens to `status: 'REVOKED'`.
3. Blocks external C2 indicators to `status: 'BLOCKED'`.
4. Writes an immutable `(INCIDENT)-[:CONTAINED_BY]->(CONTAINMENT_ACTION)` audit node into the graph.

---

## 👥 Authors
Built for **Graph Hacks: Context for AI Agents** by the GraphGuard Team (Ravindra).
