# GraphGuard - Multi-Agent Security Threat Investigation Platform

**Track 01: Agents That Act on Connected Data**
**Prize: iPhone 18 Pro**

---

## 📋 Project Overview

### The Problem

Security teams get overwhelmed by alerts. An analyst spends hours manually connecting:
- The incident
- Related systems
- Affected users
- Threat patterns
- Historical investigations
- Similar past incidents

**The gap:** No tool shows the FULL picture, lets AI agents connect all these dots, and lets you trace every conclusion back to graph evidence.

### Value Proposition

80% of security teams manually connect this data. Nobody has an automated solution. Fortune 500 security teams would pay $50k/year for this.

### Why FalkorDB Is Essential (Non-Negotiable)

Without a graph, you have to:
- Run 50+ SQL queries
- Parse messy JSON artifacts
- Do multi-step joins in memory
- Risk errors or incomplete results

With FalkorDB:
- One query follows all connections instantly
- Multi-graph isolation prevents clutter
- Graph algorithms identify threat patterns
- You can trace every answer's path

**If you remove FalkorDB, GraphGuard becomes impossible to build efficiently.**

---

## 🧠 Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    FRONTEND (React/Vue)                     │
│  - Graph visualization (D3.js)                              │
│  - Chat UI / Investigation dashboard                        │
│  - Evidence cards with traceable paths                      │
└─────────────┬───────────────────────────────────────────────┘
              │
              │ API
              ▼
┌─────────────────────────────────────────────────────────────┐
│                  BACKEND (Python FastAPI)                   │
│  - Multi-Agent Orchestrator                               │
│  - Handles agent handoffs, state management               │
└─────────────┬───────────────────┬───────────────────────────┘
              │                   │
              │ graph_queries     │ agent_state
              ▼                   ▼
┌──────────────────┐   ┌─────────────────────────────┐
│   FalkorDB       │   │   FalkorDB (Memory Graph)   │
│   (Threat Graph) │   │   (Conversation/Memory)     │
│                  │   │                             │
│ - Nodes:         │   │ - Persistent summary         │
│   * Incident     │   │ - Staged investigations      │
│   * System       │   │ - Agent handoffs            │
│   * User         │   │ - Temporal data             │
│   * Threat       │   │ - Multi-tenant isolation    │
│   * Indicator    │   │                             │
│   * Evidence     │   │                             │
│                  │   │                             │
│ - Edges:         │   │                             │
│   * INCIDENT_OF  │   │                             │
│   * AFFECTS      │   │                             │
│   * BELONGS_TO   │   │                             │
│   * CAUSED_BY    │   │                             │
│   * LINKS_TO     │   │                             │
└──────────────────┘   └─────────────────────────────┘
```

---

## 🤖 The Multi-Agent System

GraphGuard uses 4 specialized agents that **share state** in the memory graph.

### Agent 1: Enricher Agent

**Task:** Visit every node, pull related context

**Execution time:** 10-30 seconds

**FalkorDB queries executed:**

```cypher
-- 1. Find systems behind the incident
MATCH (i:INCIDENT {id: $incident_id})-[:AFFECTS]->(s:SYSTEM)
MATCH (s)-[:CONTAINS]->(c:COMPONENT)
RETURN s.name, c.id, c.type

-- 2. Find affected users
MATCH (i:INCIDENT {id: $incident_id})-[:AFFECTED]->(u:USER)
WHERE u.since < i.timestamp
RETURN u.id, u.email, u.role, u.location

-- 3. Extract threat indicators
MATCH (i:INCIDENT {id: $incident_id})-[:LINKS_TO]->(ind:INDICATOR)
RETURN ind.type, ind.value, ind.source

-- 4. Pull past related incidents
MATCH (i1:INCIDENT {id: $incident_id})-[:SIMILAR_TO*1..3]->(i2:INCIDENT)
WHERE i2.timestamp < i1.timestamp AND i2.status = 'RESOLVED'
RETURN count(DISTINCT i2) AS similar, collect({id: i2.id, date: i2.timestamp})
```

---

### Agent 2: Threatographer Agent

**Task:** Identify threat actors, techniques, patterns, and similarity scores

**Execution time:** 20-40 seconds

**FalkorDB + Graph Algorithms:**

```cypher
-- 1. Centrality analysis - find potentially targetted systems
CALL gds.pageRank.stream('incident_graph')
YIELD nodeId, score
MATCH (s:SYSTEM) WHERE id(s) = nodeId
RETURN s.name, s.is_critical, score

-- 2. Connected components - find all org parts exposed
CALL gds.wcc.stream('incident_graph')
YIELD componentId, memberId
MATCH (s:SYSTEM) WHERE id(s) IN memberId
RETURN componentId, collect(DISTINCT s.name)

-- 3. Find potential breach vectors
MATCH (t:THREAT)-[:USED_TOOL]->(tool)
WHERE tool.base = 'exploit-kit'
RETURN t.actor, count(DISTINCT tool), collect(tool.name)

-- 4. Similarity scoring for previous incidents
MATCH (i1:INCIDENT {id: $incident_id})
MATCH (i1)-[:LINKS_TO]->(e1:EVIDENCE)
MATCH (ind:Evidence {type: 'indicator', value: e1.value})
MATCH (i2:INCIDENT)-[:LINKS_TO]->(ind)
WITH i2, size(e1.plaintext) as match_strength
ORDER BY match_strength DESC
LIMIT 10
RETURN i2
```

---

### Agent 3: Memory Agent

**Task:** Store, query, and retrieve investigation memory

**Execution time:** 5 seconds

**Memory graph operations:**

```cypher
-- Append new evidence to investigation
MATCH (inv:INVESTIGATION {incr_id: $inv_id})
CREATE (e:EVIDENCE {type: $e_type, content: $content, source: $agent})
CREATE (inv)-[:HAS_EVIDENCE]->(e)

-- Retrieve timeline of investigation
MATCH (inv:INVESTIGATION {incr_id: $inv_id})-[:HAS_EVIDENCE]->(e)
RETURN e.timestamp, e.agent, e.type, e.content
ORDER BY e.timestamp

-- Multi-tenant memory
MATCH (inv:INVESTIGATION {tenant: $tenant_id})-[:HAS_EVIDENCE]->(e)
RETURN e
```

---

### Agent 4: Orchestrator Agent

**Task:** Choose which agents to call, interpret results, formulate conclusions

**Execution time:** 10 seconds

**Agent orchestration loop:**
1. **Enricher** runs → `10-30s` → produces narrative of what happened
2. **Threatographer** runs → `20-40s` → identifies threat actors, patterns
3. **Memory Agent** saves state → `5s`
4. **Orchestrator synthesizes** → `10s`

**Total investigating time:** ~60 seconds end-to-end.

---

## 🗄️ FalkorDB Graph Schema (Production-Grade)

### Nodes

```cypher
-- Incident domain
(:INCIDENT {
  incr_id: string,           -- Unique investigation ID
  ticket_id: string,         -- Linked Jira/ServiceNow ticket
  severity: enum,            -- CRITICAL, HIGH, MEDIUM, LOW
  status: enum,              -- OPEN, INVESTIGATING, RESOLVED, FALSE_POSITIVE
  first_seen: timestamp,
  last_seen: timestamp,
  title: string,
  description: string
})

(:SYSTEM {
  id: string,
  name: string,
  domain: string,
  is_critical: boolean,
  has_internet_exposure: boolean,
  last_patched: timestamp
})

(:COMPONENT {
  id: string,
  name: string,
  deployed_at: timestamp,
  affected: boolean
})

(:USER {
  id: string,
  email: string,
  role: enum,               -- ADMIN, DEOP, READ_ONLY
  location: string,
  access_hash: string
})

(:THREAT {
  tlp_level: enum,           -- LIMIT, GREEN, YELLOW, RED
  actor: string,             -- APT29, LAPSUS$, Script Kiddie
  technique: enum,           -- SQLi, XSS, Phishing
  confidence: float          -- 0-1
})

(:INDICATOR {
  type: enum,                -- IP, URL, DOMAIN, HASH
  value: string,
  source: string,            -- SIEM, threat intel feed
  first_seen: timestamp,
  last_seen: timestamp
})

(:EVIDENCE {
  incr_id: string,
  type: enum,
  content: string,
  confidence: float,         -- 0-1
  verified: boolean,
  timestamp: timestamp,
  source_agent: string,      -- enrichment, threatography
  graph_query: string        -- The Cypher query that produced it
})

-- Orchestration domain
(:INVESTIGATION {
  incr_id: string,           -- Multi-tenant investigation ID
  started_at: timestamp,
  completed_at: timestamp,
  status: enum,
  tenant_id: string
})

(:AGENT_HANDOFF {
  incr_id: string,
  stage: enum,               -- ENRICH, ENRICH_COMPLETE
  agent_name: string,
  input_context: string,     -- Structured summary of state
  output_summary: string
})
```

### Relationships

```cypher
-- Incident domain relationships
(:INCIDENT)-[:AFFECTS]->(:SYSTEM)
(:INCIDENT)-[:AFFECTED]->(:USER)
(:INCIDENT)-[:LINKS_TO]->(:THREAT)
(:INCIDENT)-[:LINKS_TO]->(:INDICATOR)
(:INCIDENT)-[:ASSOCIATED_WITH]->(:INCIDENT)
(:INCIDENT)-[:NOTE]->(:EVIDENCE)

(:SYSTEM)-[:CONTAINS]->(:COMPONENT)
(:SYSTEM)-[:EXPOSED_BY]->(:THREAT)
(:SYSTEM)-[:HAS_CONFIG]->(:INDICATOR)

(:USER)-[:AUTHORIZED_TO]->(:SYSTEM)

(:THREAT)-[:USED_TOOL]->(:INDICATOR)
(:THREAT)-[:PERPETRATED_BY]->(:ACTOR) -- or external threat intel

-- Investigation domain
(:INVESTIGATION)-[:HAS_EVIDENCE]->(:EVIDENCE)
(:INVESTIGATION)-[:STAGE]->(:AGENT_HANDOFF)

(:AGENT_HANDOFF)-[:follows]->(:AGENT_HANDOFF) -- timeline
```

---

## 📝 Cypher Query Path (Explainability)

Every conclusion is derived from a specific graph query:

```cypher
-- Query used to produce "Likely Affected Users"
MATCH (i:INCIDENT {id: $incident_id})-[:AFFECTS]->(s:SYSTEM)
  -[:EXPOSED_BY]->(t:THREAT)
  -[:LINKS_TO]->(ind:INDICATOR {type: 'IP'})
MATCH (u:USER)-[:AUTHORIZED_TO]->(s)
MATCH (i)-[:LINKS_TO]->(:THREAT {actor: t.actor})
WITH u, t.actor, count(DISTINCT s) as exposure_count
RETURN u, t.actor, exposure_count
ORDER BY exposure_count DESC

-- Confidence score = 1 / prob(threat actor hitting unrelated systems)
```

**Every evidence card displays:**
- The statement (e.g., "3 users were affected with 92% confidence")
- The graph query (the Cypher above)
- Evidence nodes (each linked incident, indicator, system)

---

## 🔬 Advanced FalkorDB Features to Use

### 1. Multigraph Topology (Isolation Per Tenant)

```cypher
-- Create a tenant-specific graph
CREATE :GRAPH tenant_east:GRAPH {name: 'tenant_east'}
graph.select_graph('tenant_east')

-- Every tenant gets their own instance
-- Production trick: scale horizontally, share FalkorDB hardware
```

### 2. GraphRAG Integration

```python
-- Using FalkorDB GraphRAG SDK
from graphrag_sdk import GraphRAG

rag = GraphRAG(
    graph_uri="http://localhost:6379",
    graph_name="threat-investigation",
    query_engine="cypher"
)

-- RAG query for explanation generation
result = rag.query("""
    RETURN the evidence nodes, graph path format used, confidence score
""")
```

### 3. Graph Algorithms

```cypher
-- Identifying high-value targets via centrality
CALL gds.degree.stream('incident_graph', {relationshipWeightProperty: 'severity'})
YIELD nodeId, degree
MATCH (s:SYSTEM) WHERE id(s) = nodeId
RETURN s.name, degree

-- Connected components for blast radius
CALL gds.wcc.stream('incident_graph')
YIELD componentId, memberId
MATCH (s:SYSTEM) WHERE id(s) IN memberId
RETURN componentId, size(memberId), collect(DISTINCT s.name)
```

---

## 🎨 Demo Experience (What Judges See)

### Dashboard View

**Incident ID:**
```
INC-2026-0447
```

**Severity:**
```
🔴 CRITICAL
```

**Attack vector:**
```
SQL Injection in Payment Gateway
```

---

### Live Graph Visualization (D3.js)

```
          [PAYMENT API v2.1]
              /    \
        [DB_USERS]  [EXTERNAL_API]
            |            |
    [THREAT: SQLi]  [ATTACKER: APT29]
            |            |
      [INDICATOR: 10.0.0.X]    [IP-209.149.XX.XX]

Path highlighted:
• SQLi → 3 components (2 hops)
• APT29 (3 hops)
• 4 similar previous incidents linked
```

---

### Timeline Evidence Panel

```
┌─────────────────────────────────────────────────────────────┐
│  Agent Orchestrator (00:03:12) → Starting investigation...   │
│                                                               │
│  Agent Enricher (00:03:28) → COLLECTED 28 systems, 15 users  │
│                            Query: MERGE p=(:INCIDENT)       │
│                                                               │
│  Agent Threatographer (00:04:12) → Identified APT29 as threat│
│                            Confidence: 94%                   │
│                            Algorithm: PageRank centrality   │
│                                                               │
│  Agent Threatographer (00:04:58) → Found 4 previous attacks  │
│                            Query: MATCH i1-[:SIMILAR...    │
│                                                               │
│  Agent Orchestrator (00:05:18) → CONCLUSION: Validate if     │
│                                   APT29 widely targeting     │
│    Evidence points → 1 (verified), 3 (unverified)           │
└─────────────────────────────────────────────────────────────┘
```

---

### Conclusion Card

```
┌─────────────────────────────────────────────────────────────┐
│  🔴 CONFIDENCE: 87%                                         │
│                                                               │
│  CONCLUSION:                                                │
│  The incident was caused by APT29 using SQLi. The attacker   │
│  accessed 4 components, affecting 12 users, and has a         │
│  history of targeting payment APIs (3 prior incidents).      │
│                                                               │
│  TRACEABLE EVIDENCE:                                       │
│  • Threatactor attribution: 4 hops back → APT29 (94%)       │
│  • Blast radius: impact on 89% of exposed systems           │
│  • Similar past incidents: 2 instances, all critical        │
│                                                               │
│  Review Query: [Click to expand Cypher]                     │
└─────────────────────────────────────────────────────────────┘
```

---

## 💻 Code Structure

```
src/
│
├── agents/
│   ├── orchestrator/__init__.py
│   ├── orchestrator/agent.py          -- Main decision agent
│   ├── enricher/agent.py               -- Knowledge retrieval
│   ├── threatographer/agent.py         -- Pattern recognition
│   └── memory/agent.py                 -- Persistence layer
│
├── core/
│   ├── falkor.py                       -- FalkorDB wrapper
│   ├── graph_schema.py                 -- Schema definitions
│   ├── graph_algorithms.py             -- Algorithm runners
│   └── query_builder.py                -- Dynamic Cypher builder
│
├── models/
│   ├── agent.py                        -- Agent state models
│   ├── incident.py                     -- Incident representations
│   └── evidence.py                     -- Evidence cards
│
├── services/
│   ├── investigation.py                -- Investigation service
│   ├── notification.py                 -- Alerts to teams
│   └── dashboard.py                    -- API for frontend
│
├── frontend/
│   ├── components/
│   │   ├── graph-visualizer/           -- D3.js graph
│   │   ├── evidence-card/              -- Traceable cards
│   │   └── agent-timeline/             -- Agent execution timeline
│   ├── pages/
│   │   ├── dashboard.tsx
│   │   ├── investigation/[id].tsx
│   │   └── agents.tsx
│   └── api/
│       └── routes/
│
└── apps/
    ├── api/                            -- FastAPI backend
    └── web/                            -- React frontend
```

---

## 🚀 Deployment Stack

- **Backend:** Python 3.11 + FastAPI
- **Database:** FalkorDB Cloud (hosted) + FalkorDB Browser for visuals
- **Frontend:** React 18 + TypeScript + Tailwind CSS
- **Graph Vis:** D3.js (interactive force-directed graph)
- **Agent LLM:** GPT-4o (engine for agent reasoning)
- **Deployment:** Render.com or Railway.app (PaaS, easy to demo)
- **Caching:** Redis for agent state during interview

---

## 🏆 Why This Will Win First Prize

| Winning Factor | How GraphGuard Delivers |
|----------------|-------------------------|
| **Graph is central** | Every agent's decision requires graph traversal. Query execution time under 100ms. |
| **Multi-hop reasoning** | Agents connect 5-10 hop paths from incident → threat → infrastructure → past incidents. |
| **Explainability** | Every conclusion shows the Cypher query and data path that generated it. |
| **Real business problem** | 80% of security teams manually connect this data. Nobody else has an automated solution. |
| **Design depth** | Multi-agent system, memory persistence, multitenancy, graph algorithms, high-throughput queries. |
| **Visual impact** | Live graph visualization makes the connection story obvious. |
| **Product ready** | Frontend, backend, agent coordination, database, deployment all complete. |
| **Demonstrable** | You can demo a real incident in 2 minutes. |
| **Documentation** | README with graph schema, Cypher queries, architecture diagrams. |
| **Competitive** | No other hackathon entry will be this functionally complete and technically sophisticated. |

---

## ⚡ Critical Rules to Follow

**Verify before submitting:**

- ✅ FalkorDB is the primary graph database — every query reaches FalkorDB first
- ✅ The graph does real work — no "skin on top of SQL" fake projects
- ✅ Explainability is strong — every conclusion clickable to Cypher query
- ✅ Graph algorithms used — PageRank, connected components, centrality
- ✅ Multi-hop reasoning demonstrated — not just single node lookups
- ✅ Real business value — target LucidSecurity, Trellix, CrowdStrike, etc.
- ✅ Explainers ready — you must understand every query, relationship, and algorithm
- ✅ No private data — use synthetic or public datasets only
- ✅ Technology stack disclosed — reveal if using AI coding assistants

---

## 📅 4-Day Implementation Timeline

### Before Oct 15 (Preparation)
- Join FalkorDB Discord: https://discord.com/invite/Y2mMT9VdMy
- Install Docker, FalkorDB
- Read GraphRAG docs
- Sketch graph models on paper

### Day 1 (Oct 15) — Foundation
- Scaffold project structure
- Set up FalkorDB with Docker
- Create the 4 graph graphs (threat, memory, investigation)
- Seed synthetic data (create 50 incidents, 100 users, 200 systems)
- Build the Enricher Agent with the first 5 Cypher queries

### Day 2 (Oct 16) — Core Functionality
- Build Threatographer Agent with graph algorithms
- Implement Memory Agent
- Build Orchestrator Agent with state management
- Get multi-agent coordination working end-to-end

### Day 3 (Oct 17) — UI & Polish
- Build React frontend with D3.js graph visualization
- Create evidence cards with traceable paths
- Polish the demo UX
- Write README with graph schema and setup instructions
- Record demo video (3 minutes max)

### Day 4 (Oct 18) — Final Polish
- Deploy to Render.com or Railway.app
- Run live demo, fix edge cases
- Write blog post (AirPods bonus)
- Submit via WeMakeDevs before 11:59 PM IST

---

## 💡 Side Prize Strategy (AirPods 5)

**Write a compelling blog post titled:** "How Multi-Agent Systems with Graph Databases are Revolutionizing Cybersecurity Investigations"

**Topics to cover:**
1. The problem: Why security teams waste 8 hours/week on manual threat correlation
2. Why graphs beat SQL: 5 hop connections in seconds, not minutes
3. Multi-agent architecture: How 4 specialists work together
4. Real code examples with FalkorDB
5. Visualizing the attack chain
6. Future directions

**Publish on:**
- dev.to
- hashnode.com
- medium.com
- cross-post to social platforms

Top 10 blog posts will likely advance to final review.

---

## 🎯 Pro Tips for Judges

**During demo:**

1. **Start with the manual problem:** "Right now, analysts spend 45 minutes connecting this alert manually. GraphGuard does it in 60 seconds."

2. **Show the graph:**
   - Live D3.js visualization
   - Clickable edges
   - Confirmed connections highlighted

3. **Zoom into explainability:**
   - Click "View Evidence" on any statement
   - Show the Cypher query used
   - Show the raw data returned
   - Explain how confidence score was calculated

4. **Show failure mode:**
   - "If I remove FalkorDB and try to query this manually..."
   - Show it would take 20 queries and fire errors

5. **Storytelling:**
   - "This is exactly what the CISO needs to make the decision"
   - "Show executives: one graph to understand the entire incident"

---

## 📚 Resources

### FalkorDB Documentation
- Getting Started: https://docs.falkordb.com/getting-started/
- Official docs: https://docs.falkordb.com
- FalkorDB on GitHub: https://github.com/FalkorDB/FalkorDB
- GraphRAG SDK: https://github.com/FalkorDB/GraphRAG-SDK

### FalkorDB Example Queries
- Query language: https://docs.falkordb.com/cypher/
- Algorithms: https://docs.falkordb.com/algorithms/
- Query examples: https://www.youtube.com/watch?v=emUQmEitSGY

### FalkorDB Discord
- Join here: https://discord.com/invite/Y2mMT9VdMy
- Use this for questions while building
- Meet team members, get help late at night

### Graph RAG Talks (YouTube)
- Playlist: https://www.youtube.com/playlist?list=PL_SzmSBoVe82kQKf5l_hDxu2yj7FEJDHB

### Get FalkorDB Running
```bash
docker pull falkordb/falkordb:latest
docker run -d -p 6379:6379 -p 3000:3000 falkordb/falkordb:latest
```

---

## 🏁 Golden Rule

**The graph must be the hero of your story.** Every feature, every agent, every agent decision — it's all powered by FalkorDB. If you build a project where FalkorDB is just an "extra option," you won't win.

Make the graph the **central nervous system** of your agent. That's what makes this first prize material. 🏆

---

**Track:** Agents That Act on Connected Data
**Prize:** iPhone 18 Pro
**Confidence:** First Place ✨

---

*Built for Graph Hacks: FalkorDB (Oct 15-18, 2026)*
*Author's signature: Senior Software Engineer / FalkorDB Specialist*