# GraphGuard — Live Cloud Deployment & Setup Guide

This guide provides step-by-step instructions for deploying **GraphGuard** to production cloud platforms for the **Graph Hacks Hackathon (Track 01)**.

---

## ⚡ Option 1: 1-Click Deploy to Render (Recommended & Free)

Render provides free hosting for Python web services and automatically reads `render.yaml`.

### Step-by-Step:
1. Push this repository to your GitHub account (e.g. `https://github.com/<your-username>/graphguard`).
2. Log into [Render.com](https://render.com) and click **"New +"** $\rightarrow$ **"Web Service"**.
3. Select **"Build and deploy from a Git repository"** and choose your `graphguard` repository.
4. Render will auto-detect settings from `render.yaml`:
   - **Environment:** `Python`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python main.py`
5. Click **"Deploy Web Service"**.
6. In ~2 minutes, your live public URL will be ready (e.g. `https://graphguard-xxxx.onrender.com`).
7. Enter this live URL into your hackathon submission form on WeMakeDevs!

---

## 🤗 Option 2: 1-Click Deploy to Hugging Face Spaces (100% Free)

Hugging Face Spaces allows free Docker hosting with instant public URLs.

### Step-by-Step:
1. Go to [huggingface.co/spaces](https://huggingface.co/spaces) and click **"Create new Space"**.
2. Name it `graphguard` and select **SDK: Docker** (Blank).
3. Set Space hardware to **Free CPU (2 vCPU, 16GB RAM)**.
4. Clone the Hugging Face git repo locally, copy this project's files into it, or upload them via the web interface.
5. Commit and push. Hugging Face will automatically build using the included [Dockerfile](Dockerfile) and launch your live application at `https://huggingface.co/spaces/<username>/graphguard`.

---

## 🚂 Option 3: Deploy to Railway

1. Install Railway CLI or visit [railway.app](https://railway.app).
2. Click **"New Project"** $\rightarrow$ **"Deploy from GitHub repo"**.
3. Select `graphguard`.
4. Railway will automatically build and deploy the app. Under **Settings $\rightarrow$ Domains**, click **"Generate Domain"** to get your public URL.

---

## 🐳 Option 4: Full Production Local Deployment (with FalkorDB Docker)

Run both the official FalkorDB GraphBLAS database engine and GraphGuard in isolated containers:

```bash
docker-compose up --build
```

- **GraphGuard Web UI:** `http://localhost:8000`
- **FalkorDB Instance:** `localhost:6379`
- **API Documentation:** `http://localhost:8000/docs`

---

## ☁️ Optional: Connecting to FalkorDB Cloud

GraphGuard automatically runs in high-performance in-memory mode if no database is reachable. However, if you want to connect to a persistent managed cloud cluster:

1. Sign up for free at [app.falkordb.cloud](https://app.falkordb.cloud).
2. Create a free database instance.
3. In your Render / Railway / local environment variables, set:
   ```env
   FALKOR_HOST=<your-cloud-endpoint>.falkordb.cloud
   FALKOR_PORT=6379
   FALKOR_PASSWORD=<your-cloud-password>
   ```
4. GraphGuard will automatically establish encrypted graph connection on startup.
