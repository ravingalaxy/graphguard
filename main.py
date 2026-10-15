"""
GraphGuard Main Entry Point - Starts the FastAPI server.
"""

import sys
import os

if __name__ == "__main__":
    # Set up Python path to the project root
    os.chdir(os.path.dirname(os.path.abspath(__file__)))

    # Import app directly from server module
    from backend.api.server import app

    host = os.getenv("HOST", "0.0.0.0")
    port = int(os.getenv("PORT", 8000))

    print("=" * 60)
    print("Starting GraphGuard Multi-Agent Security Investigation Platform")
    print("=" * 60)
    print("Track 01: Agents That Act on Connected Data")
    print("Powered by FalkorDB")
    print("=" * 60)
    print("")
    print("FalkorDB Mode: In-Memory Fallback (No Docker required)")
    print(f"Server URL: http://{host}:{port}")
    print(f"Documentation URL: http://{host}:{port}/docs")
    print("")
    print("=" * 60)
    print("Press Ctrl+C to stop the server")
    print("=" * 60)
    print("")

    import uvicorn
    uvicorn.run(app, host=host, port=port)