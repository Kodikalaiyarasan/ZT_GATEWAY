"""
Internal Microservice — Product Catalog & Company Analytics

This is a regular business application that has NO knowledge of the
Zero Trust Gateway sitting in front of it. It simply serves its own
API endpoints. The gateway handles all security transparently.
"""

import random
import uuid
from datetime import datetime, timezone, timedelta

import uvicorn
from fastapi import FastAPI

app = FastAPI(title="Internal Business API", version="2.1.0")

# ── Sample data pools ────────────────────────────────────────

FIRST_NAMES = ["Liam", "Olivia", "Noah", "Emma", "Aiden", "Sophia", "Jackson", "Ava",
               "Lucas", "Mia", "Caden", "Isabella", "Mateo", "Luna", "Ethan", "Harper"]
LAST_NAMES = ["Patel", "Garcia", "Nguyen", "Kim", "Tanaka", "Mueller", "Silva", "Johansson",
              "Chen", "Williams", "Brown", "Ali", "Rossi", "Larsson", "Nakamura", "Singh"]
DEPARTMENTS = ["Engineering", "Marketing", "Sales", "HR", "Finance", "Legal", "Design", "Support"]
PRODUCTS = [
    {"name": "CloudSync Pro", "category": "SaaS", "base_price": 29.99},
    {"name": "DataVault Enterprise", "category": "Storage", "base_price": 149.00},
    {"name": "PixelForge Studio", "category": "Creative Tools", "base_price": 59.99},
    {"name": "NetPulse Monitor", "category": "DevOps", "base_price": 89.00},
    {"name": "DocuFlow Lite", "category": "Productivity", "base_price": 12.99},
    {"name": "InsightIQ Dashboard", "category": "Analytics", "base_price": 199.00},
    {"name": "SecureChat Teams", "category": "Communication", "base_price": 8.99},
    {"name": "CodeDeploy CI", "category": "DevOps", "base_price": 45.00},
]
CITIES = ["San Francisco", "London", "Tokyo", "Berlin", "Sydney", "Toronto",
          "Mumbai", "Sao Paulo", "Singapore", "Amsterdam"]
STATUSES = ["active", "trial", "churned", "pending"]


def _random_person():
    return {
        "id": str(uuid.uuid4())[:8],
        "name": f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}",
        "email": f"{random.choice(FIRST_NAMES).lower()}.{random.choice(LAST_NAMES).lower()}@example.com",
        "department": random.choice(DEPARTMENTS),
        "joined": (datetime.now(timezone.utc) - timedelta(days=random.randint(30, 1200))).strftime("%Y-%m-%d"),
    }


def _random_product():
    p = random.choice(PRODUCTS)
    qty = random.randint(1, 500)
    return {
        "sku": f"SKU-{random.randint(10000, 99999)}",
        "name": p["name"],
        "category": p["category"],
        "unit_price": p["base_price"],
        "stock": qty,
        "warehouse": random.choice(CITIES),
    }


def _random_order():
    p = random.choice(PRODUCTS)
    qty = random.randint(1, 10)
    return {
        "order_id": f"ORD-{random.randint(100000, 999999)}",
        "customer": f"{random.choice(FIRST_NAMES)} {random.choice(LAST_NAMES)}",
        "product": p["name"],
        "quantity": qty,
        "total": round(p["base_price"] * qty, 2),
        "status": random.choice(["shipped", "processing", "delivered", "returned"]),
        "city": random.choice(CITIES),
        "ordered_at": (datetime.now(timezone.utc) - timedelta(hours=random.randint(1, 720))).isoformat(),
    }


# ── API Endpoints ─────────────────────────────────────────────

@app.get("/api/v1/user/data")
async def user_data():
    """Employee directory — returns random employees each time."""
    employees = [_random_person() for _ in range(random.randint(3, 8))]
    return {
        "service": "employee-directory",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "employees": employees,
        "total": len(employees),
        "page": 1,
    }


@app.get("/api/v1/admin/metrics")
async def admin_metrics():
    """Business KPIs — returns randomized analytics each time."""
    return {
        "service": "business-analytics",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "kpis": {
            "monthly_revenue": round(random.uniform(50000, 500000), 2),
            "active_subscriptions": random.randint(800, 5000),
            "new_signups_today": random.randint(5, 120),
            "churn_rate_percent": round(random.uniform(0.5, 5.0), 2),
            "avg_ticket_resolution_hours": round(random.uniform(1.5, 24.0), 1),
            "nps_score": random.randint(30, 90),
        },
        "top_products": [
            {"name": p["name"], "revenue": round(random.uniform(5000, 80000), 2)}
            for p in random.sample(PRODUCTS, 4)
        ],
        "recent_orders": [_random_order() for _ in range(5)],
        "inventory_snapshot": [_random_product() for _ in range(4)],
    }


@app.get("/api/v1/public/health")
async def public_health():
    """Standard health check."""
    return {"status": "UP", "service": "internal-business-api", "version": "2.1.0"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
