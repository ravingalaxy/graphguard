# GraphGuard — 3-Minute Demo Video Script & Production Guide
> **Track 01:** Agents That Act on Connected Data  
> **Live App:** https://graphguard-pro9.onrender.com/  
> **Target Length:** 2:45 – 3:00 minutes (1080p HD)

---

## 🎬 Free AI Tooling Setup
- **Recorder & Editor:** **Microsoft Clipchamp** (Pre-installed on Windows 11, free 1080p export, no watermark) or **OBS Studio**
- **AI Voiceover:** Built-in Clipchamp Text-to-Speech (Voice: *en-US-ChristopherNeural* or *en-US-AndrewNeural*, Pitch: Medium, Speed: Regular) OR **ElevenLabs** (Free Tier)
- **Subtitles:** Clipchamp 1-Click AI Auto-Captions

---

## ⏱️ Video Walkthrough & Script Timeline

### 0:00 – 0:30 | Hook & Problem Statement
- **Screen Action:** Open `https://graphguard-pro9.onrender.com/` in full-screen (F11). Show the dark cybersecurity interface and the D3.js force-directed graph.
- **Voiceover:**
  > "Welcome to GraphGuard — an autonomous multi-agent threat intelligence and containment platform powered by FalkorDB for Track 01: Agents That Act on Connected Data.
  > Modern Security Operations Centers are overwhelmed with alerts. When a critical breach occurs, analysts spend hours manually connecting SQL tables and JSON logs. GraphGuard solves this by making FalkorDB's connected graph the central nervous system of collaborating AI agents."

---

### 0:30 – 1:15 | Multi-Hop Traversal & Agent Reasoning
- **Screen Action:** Click **"Run Multi-Agent Investigation"** on incident `INC-2026-0447`. Show the status badges progress from *Enricher* to *Threatographer* to *Orchestrator*.
- **Voiceover:**
  > "Let's investigate Incident 2026-0447, a critical SQL Injection alert targeting our Payment Gateway API. 
  > When we trigger the investigation, four specialized agents query FalkorDB in parallel.
  > The Enricher Agent traverses multi-hop paths from the incident to compromised web servers, database clusters, and active user sessions.
  > Next, the Threatographer Agent matches attack patterns against MITRE ATT&CK subgraphs, running degree and betweenness centrality to pinpoint high-value assets."

---

### 1:15 – 1:55 | Traceable Evidence Cards & Cypher Provenance
- **Screen Action:** Scroll down to the **Traceable Evidence Cards**. Click to expand an evidence card and highlight the raw Cypher query and confidence score.
- **Voiceover:**
  > "Unlike black-box AI tools, GraphGuard provides 100% explainability. 
  > Every finding is backed by an interactive Evidence Card linked directly to its underlying Cypher query and subgraph provenance. 
  > Analysts can inspect the exact traversal path, verify the data lineage, and copy the Cypher query with one click."

---

### 1:55 – 2:30 | Model Context Protocol (MCP) Integration
- **Screen Action:** Open a new tab to `https://graphguard-pro9.onrender.com/api/mcp/tools`. Show the JSON listing the 5 callable graph tools.
- **Voiceover:**
  > "GraphGuard implements the official Model Context Protocol (MCP) specification. 
  > Through standard MCP endpoints, any LLM agent can discover and invoke our FalkorDB tools — such as calculating blast radiuses, querying threat graphs, and identifying shortest attack paths — all returning sub-100 millisecond GraphBLAS results."

---

### 2:30 – 3:00 | Autonomous Graph Containment & Conclusion
- **Screen Action:** Switch back to dashboard. Click the highlighted button **"Execute Full Graph Containment"**. Show the success toast and the 11 mutated graph nodes (`status: ISOLATED, REVOKED, BLOCKED`).
- **Voiceover:**
  > "Finally, GraphGuard doesn't just display data — it acts on connected data.
  > With autonomous containment, GraphGuard mutates graph state directly in FalkorDB: isolating compromised servers, revoking user credentials, and blocking command-and-control indicators in real-time.
  > GraphGuard turns graph intelligence into autonomous defense. Thank you."

---

## 📌 Checklist Before Submitting
1. Record in 1080p (1920x1080) with browser address bar visible at start.
2. Ensure live Render link (`https://graphguard-pro9.onrender.com/`) is shown.
3. Upload as **Unlisted** on YouTube or Loom.
4. Paste video link into the WeMakeDevs Track 1 submission form.
