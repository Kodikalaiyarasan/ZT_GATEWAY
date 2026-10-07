"""
Zero Trust Gateway — MCP Server (Model Context Protocol)

Exposes security operations tools to AI assistants (Claude, Cursor)
via the FastMCP framework.  Each tool queries PostgreSQL or Redis
to retrieve audit data, revoke tokens, or identify high-risk users.
"""

import json
import os
from datetime import datetime, timezone

import psycopg2
import psycopg2.extras
import redis
from mcp.server.fastmcp import FastMCP

# ── Configuration ─────────────────────────────────────────────

PG_DSN = os.getenv("PG_DSN", "dbname=ztgateway user=ztadmin password=ztadmin_secret host=postgres port=5432")
REDIS_HOST = os.getenv("REDIS_HOST", "redis")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))

# ── Connections ───────────────────────────────────────────────

redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0, decode_responses=True)

def _pg_conn():
    """Create a new PostgreSQL connection (short-lived, per-tool-call)."""
    return psycopg2.connect(PG_DSN)

# ── MCP Server ────────────────────────────────────────────────

mcp = FastMCP(
    name="Zero Trust Gateway Security Operations",
    instructions=(
        "This MCP server provides security operations tools for the "
        "Zero Trust Microservice Access Gateway.  Use these tools to "
        "query audit logs, revoke compromised tokens, and identify "
        "high-risk user accounts."
    ),
)


@mcp.tool()
def get_failed_access_logs(limit: int = 20) -> str:
    """
    Retrieve the most recent DENIED access log entries.

    Args:
        limit: Maximum number of log entries to return (default 20, max 200).

    Returns:
        JSON array of denied access events with timestamp, user, IP,
        endpoint, risk score, and denial reason.
    """
    limit = min(max(1, limit), 200)
    conn = _pg_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT id, created_at, user_id, client_ip, endpoint,
                       decision, risk_score, reason
                FROM audit_logs
                WHERE decision = 'DENIED'
                ORDER BY created_at DESC
                LIMIT %s
                """,
                (limit,),
            )
            rows = cur.fetchall()
            # Convert datetime objects to ISO strings
            for row in rows:
                if isinstance(row.get("created_at"), datetime):
                    row["created_at"] = row["created_at"].isoformat()
            return json.dumps(rows, indent=2, default=str)
    finally:
        conn.close()


@mcp.tool()
def revoke_user_token(user_id: str) -> str:
    """
    Revoke all active tokens for a specific user by writing a
    revocation key to Redis.  The Control Plane checks this key
    on every evaluation request.

    Args:
        user_id: The user ID whose tokens should be revoked.

    Returns:
        Confirmation message with the revocation details.
    """
    if not user_id or not user_id.strip():
        return json.dumps({"error": "user_id is required"})

    user_id = user_id.strip()
    key = f"revoked:{user_id}"
    timestamp = datetime.now(timezone.utc).isoformat()

    redis_client.set(key, timestamp)
    # Revocation persists for 24 hours then auto-expires
    redis_client.expire(key, 86400)

    result = {
        "action": "token_revoked",
        "user_id": user_id,
        "revoked_at": timestamp,
        "expires_in_seconds": 86400,
        "message": f"All tokens for user '{user_id}' have been revoked. "
                   f"The user will be denied access for the next 24 hours "
                   f"or until the revocation is manually cleared.",
    }
    return json.dumps(result, indent=2)


@mcp.tool()
def get_high_risk_users() -> str:
    """
    Retrieve all users with a risk score above 40 from the
    user_risk_profiles table.

    Returns:
        JSON array of high-risk user profiles with user_id,
        risk_score, and last_updated timestamp.
    """
    conn = _pg_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute(
                """
                SELECT user_id, risk_score, last_updated
                FROM user_risk_profiles
                WHERE risk_score > 40
                ORDER BY risk_score DESC
                """
            )
            rows = cur.fetchall()
            for row in rows:
                if isinstance(row.get("last_updated"), datetime):
                    row["last_updated"] = row["last_updated"].isoformat()
            return json.dumps(rows, indent=2, default=str)
    finally:
        conn.close()


@mcp.tool()
def get_access_summary() -> str:
    """
    Get a summary of access decisions — total allowed, total denied,
    and top denied users.

    Returns:
        JSON object with decision counts and top-5 denied users.
    """
    conn = _pg_conn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            # Overall counts
            cur.execute(
                """
                SELECT decision, COUNT(*) as count
                FROM audit_logs
                GROUP BY decision
                """
            )
            counts = {row["decision"]: row["count"] for row in cur.fetchall()}

            # Top denied users
            cur.execute(
                """
                SELECT user_id, COUNT(*) as denied_count
                FROM audit_logs
                WHERE decision = 'DENIED'
                GROUP BY user_id
                ORDER BY denied_count DESC
                LIMIT 5
                """
            )
            top_denied = cur.fetchall()

            summary = {
                "total_allowed": counts.get("ALLOWED", 0),
                "total_denied": counts.get("DENIED", 0),
                "top_denied_users": [dict(r) for r in top_denied],
            }
            return json.dumps(summary, indent=2)
    finally:
        conn.close()


if __name__ == "__main__":
    mcp.run(transport="stdio")
