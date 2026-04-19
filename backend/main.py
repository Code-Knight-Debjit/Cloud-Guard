"""
FastAPI Backend for Cloud Misconfiguration Detection System
"""

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
import sys
import os

sys.path.insert(0, os.path.dirname(__file__))

from analyzer import run_full_analysis

app = FastAPI(
    title="Cloud Threat Detection API",
    description="Intelligent AWS Misconfiguration Detection and Threat Correlation",
    version="1.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def root():
    dashboard_path = os.path.join(os.path.dirname(__file__), "..", "frontend", "dashboard.html")
    return FileResponse(dashboard_path)


@app.get("/api/scan")
def scan(mock: bool = Query(default=True, description="Use mock data (True) or live AWS scan (False)")):
    """Run full AWS security scan and return analysis report."""
    try:
        result = run_full_analysis(use_mock=mock)
        return JSONResponse(content=result)
    except Exception as e:
        return JSONResponse(
            status_code=500,
            content={"error": str(e), "message": "Scan failed. Check AWS credentials or use mock=true"}
        )


@app.get("/api/health")
def health():
    return {"status": "healthy", "boto3_available": True}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=True)
