# GraphGuard: Step-by-Step User & Developer Guide

Welcome to **GraphGuard**, a multi-agent security threat investigation platform built for **Graph Hacks: Context for AI Agents** (Track 01: Agents That Act on Connected Data), powered by **FalkorDB**.

---

## 📋 Table of Contents
1. [Prerequisites](#1-prerequisites)
2. [Project Setup & Installation](#2-project-setup--installation)
3. [Running the Test Suite](#3-running-the-test-suite)
4. [Running the Application](#4-running-the-application)
5. [Using the Web GUI Dashboard](#5-using-the-web-gui-dashboard)
6. [API Endpoints Reference](#6-api-endpoints-reference)
7. [Architecture & How It Works](#7-architecture--how-it-works)
8. [Developer Deep-Dive](#8-developer-deep-dive)

---

## 1. Prerequisites

Before you begin, ensure you have the following installed:
- **Python 3.12+**
- **pip** (Python package manager)
- **Docker** (Optional — GraphGuard includes an automatic in-memory fallback mode, so you don't even need Docker installed to test and run it locally!)

---

## 2. Project Setup & Installation

1. Open your terminal in the project root directory (`F:\hackathon\Track 1 - GraphGuard`).
2. Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

---

## 3. Running the Test Suite

Verify that all multi-agent pipelines, seed data, and FalkorDB query generators are working correctly by running the test script:
```bash
python test.py
```
**Expected Output:**
```
=== TESTING GRAPHGUARD MULTI-AGENT SYSTEM ===

Initializing FalkorDB Driver...
Driver initialized in fallback mode (no Docker required)

Verifying Seed Data Generator...
Loaded 2 test scenarios
Scenario INC-2026-0447 loaded
  Nodes: 12
  Edges: 15
  Title: SQL Injection in Payment Gateway API

Initializing Orchestrator Agent...
Orchestrator initialized with all 4 sub-agents
  Enricher Agent: Enricher Agent
  Threatographer Agent: Threatographer Agent
  Memory Agent: Memory Agent

Running Investigation Pipeline...
Investigation completed successfully
  Status: COMPLETED
  Execution Time: 0.0s
  Overall Confidence: 92%

Verifying Evidence Card generation...
Generated 4 traceable evidence cards
...
============================================================
ALL TESTS PASSED - System is ready for production
============================================================
```

To verify the system works for **any incident ID** (not just the hardcoded ones):
```bash
python test_scenarios.py
python test_any_incident.py
```

---

## 4. Running the Application

To start the FastAPI web server and GUI dashboard:
```bash
python main.py
```
**Expected Output:**
```
============================================================
Starting GraphGuard Multi-Agent Security Investigation Platform
============================================================
Track 01: Agents That Act on Connected Data
Powered by FalkorDB
============================================================

FalkorDB Mode: In-Memory Fallback (No Docker required)
Server URL: http://localhost:8000
Documentation URL: http://localhost:8000/docs
```

---

## 5. Using the Web GUI Dashboard

1. Open your web browser and go to:
   ```
   http://localhost:8000
   ```
2. **Launch an Investigation:**
   - Enter an Incident ID (e.g., `INC-2026-0447`).
   - Enter a Tenant ID (e.g., `tenant_east`).
   - Click **"Start Investigation"**.
3. **Use Pre-loaded Scenarios:**
   - Click **"Scenario 1: SQL Injection (APT29)"** to automatically populate the incident ID.
   - Click **"Scenario 2: Ransomware (LAPSUS$)"** to load alternate test data.
4. **Inspect Results:**
   - View the **Multi-Agent Timeline** showing step-by-step agent handoffs.
   - Read the **Traceable Evidence Cards** containing confidence scores, natural language summaries, and raw FalkorDB Cypher queries.
5. **Create Custom Scenarios & Graph Data:**
   - Use the **💾 Custom Scenarios** card to save and reload your own incident templates.
   - Use **➕ Add Graph Data** to manually insert nodes, edges, and relationships.
   - Use **🔍 View Graph Data** and **⚡ Run Cypher Query** to explore and query the graph directly.

---

## 6. API Endpoints Reference

GraphGuard exposes a clean REST API:

- **GET `/`** — Serves the interactive Web GUI Dashboard.
- **GET `/health`** — System health check and FalkorDB connection status.
- **POST `/api/investigation`** — Triggers the multi-agent investigation pipeline.
  - *Request Body:*
    ```json
    {
      "incident_id": "INC-2026-0447",
      "tenant_id": "tenant_east"
    }
    ```
- **GET `/api/scenarios`** — Lists pre-built test incident scenarios.
- **POST `/api/seed/{scenario_id}`** — Seeds scenario graph nodes and edges into FalkorDB.
- **POST `/api/cypher`** — Executes custom Cypher queries.
- **POST `/api/graph-data`** — Adds nodes and edges via GUI forms.
- **GET `/api/graph-data`** — Retrieves nodes and edges for graph visualization.

---

## 7. Architecture & How It Works

GraphGuard is structured around 4 specialized AI agents working together:

1. **Enricher Agent** — Performs multi-hop graph traversals (`INCIDENT → AFFECTS → SYSTEM → COMPONENT`) to pull context.
2. **Threatographer Agent** — Performs pattern matching and graph centrality algorithms to attribute threat actors (e.g., APT29).
3. **Memory Agent** — Persists investigation state and cross-agent handoffs in FalkorDB multigraph storage.
4. **Orchestrator Agent** — Synthesizes findings into traceable evidence cards with raw Cypher queries for total explainability.

---

## 8. Developer Deep-Dive

For comprehensive architectural explanations, file-by-file breakdowns, technology rationale, schema definitions, extension patterns, and advanced troubleshooting, please read the complete **[GUIDE.md](./GUIDE.md)**.

The **GUIDE.md** includes:
- Complete directory and file blueprint
- Technology stack justifications
- Detailed component walkthroughs (database layer, agent pipeline, API layer)
- Graph schema definitions (nodes, edges, properties)
- Verification and testing procedures
- Instructions for extending agents, schemas, and API endpoints
- Thread-safety and in-memory graph traversal mechanics