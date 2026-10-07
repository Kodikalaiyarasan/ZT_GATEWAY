"""
Zero Trust Gateway — Target Backend (Mock Internal Microservice)

This simulates a hidden internal API that is NEVER exposed to the
public internet.  Only the C++ data-plane proxy on the internal
Docker network can reach it.
"""

from datetime import datetime, timezone
from typing import Any, Dict

import uvicorn
from fastapi import FastAPI, Request

app = FastAPI(
    title="ZT Internal Microservice",
    version="1.0.0",
    docs_url=None,      # hide Swagger from internal service
    redoc_url=None,
)


@app.get("/api/v1/user/data")
async def user_data(request: Request) -> Dict[str, Any]:
    """Return mock user data — only accessible to authenticated users."""
    return {
        "service": "internal-user-service",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "users": [
                {"id": "u-1001", "name": "Alice Chen",    "department": "Engineering",  "clearance": "L3"},
                {"id": "u-1002", "name": "Bob Martinez",  "department": "Security Ops", "clearance": "L4"},
                {"id": "u-1003", "name": "Diana Kim",     "department": "Data Science", "clearance": "L2"},
                {"id": "u-1004", "name": "Grace Nakamura","department": "DevOps",       "clearance": "L3"},
            ],
            "total": 4,
            "page": 1,
        },
        "meta": {
            "served_by": "target-backend",
            "network": "zt-internal",
            "client_ip": request.client.host if request.client else "unknown",
        },
    }


@app.get("/api/v1/admin/metrics")
async def admin_metrics(request: Request) -> Dict[str, Any]:
    """Return operational metrics — admin-only endpoint."""
    return {
        "service": "internal-metrics-service",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "metrics": {
            "requests_total":        128_450,
            "requests_denied":        3_217,
            "avg_latency_ms":         12.4,
            "p99_latency_ms":         89.2,
            "active_sessions":        342,
            "rate_limit_triggers":    58,
            "sandbox_scans_total":    1_204,
            "sandbox_threats_found":  7,
            "uptime_seconds":         864_000,
        },
        "health": {
            "postgres": "healthy",
            "redis":    "healthy",
            "opa":      "healthy",
        },
        "meta": {
            "served_by": "target-backend",
            "network": "zt-internal",
        },
    }


@app.get("/api/v1/public/health")
async def public_health() -> Dict[str, str]:
    """Public health check — accessible to any authenticated user."""
    return {"status": "UP", "service": "target-backend"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
