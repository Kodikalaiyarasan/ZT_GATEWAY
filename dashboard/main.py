"""
Zero Trust Gateway — Interactive Operations Dashboard
Built with clean, human-designed responsive styling (tasteful muted palette),
React-style interactive tab switching, file uploading to the sandbox,
and "Show 30 / Show All" pagination for audit logs.
"""

import os
import json
import psycopg2
import psycopg2.extras
import requests
import uvicorn
from fastapi import FastAPI, Form, File, UploadFile, Request
from fastapi.responses import HTMLResponse

app = FastAPI(title="ZT Dashboard", docs_url=None, redoc_url=None)

PG_DSN = os.getenv("PG_DSN", "dbname=ztgateway user=ztadmin password=ztadmin_secret host=postgres port=5432")
PROXY_URL = os.getenv("PROXY_URL", "http://data-plane-proxy:8000")


def _pg():
    return psycopg2.connect(PG_DSN)


def _get_audit_logs(limit=None):
    conn = _pg()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            if limit:
                cur.execute(
                    "SELECT id, created_at, user_id, client_ip, endpoint, decision, risk_score, reason "
                    "FROM audit_logs ORDER BY created_at DESC LIMIT %s",
                    (limit,)
                )
            else:
                cur.execute(
                    "SELECT id, created_at, user_id, client_ip, endpoint, decision, risk_score, reason "
                    "FROM audit_logs ORDER BY created_at DESC"
                )
            return cur.fetchall()
    finally:
        conn.close()


def _get_risk_profiles():
    conn = _pg()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT user_id, risk_score, last_updated FROM user_risk_profiles ORDER BY risk_score DESC")
            return cur.fetchall()
    finally:
        conn.close()


CSS = """
<style>
  :root {
    --bg: #f8fafc;
    --card: #ffffff;
    --border: #e2e8f0;
    --text-primary: #1e293b;
    --text-muted: #64748b;
    --accent: #2563eb;
    --accent-hover: #1d4ed8;
    --allowed-bg: #ecfdf5;
    --allowed-text: #065f46;
    --denied-bg: #fef2f2;
    --denied-text: #991b1b;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
    background-color: var(--bg);
    color: var(--text-primary);
    line-height: 1.5;
    padding: 24px;
  }
  .container { max-width: 1100px; margin: 0 auto; }
  .header {
    background: var(--card);
    padding: 20px 24px;
    border-radius: 8px;
    border: 1px solid var(--border);
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .header h1 { font-size: 20px; font-weight: 600; color: #0f172a; }
  .header .tagline { font-size: 13px; color: var(--text-muted); }
  .nav-tabs {
    display: flex;
    gap: 8px;
    margin-bottom: 20px;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
  }
  .nav-btn {
    background: transparent;
    border: none;
    padding: 8px 16px;
    font-size: 14px;
    font-weight: 500;
    color: var(--text-muted);
    cursor: pointer;
    border-radius: 6px;
    text-decoration: none;
  }
  .nav-btn:hover { background: #f1f5f9; color: var(--text-primary); }
  .nav-btn.active {
    background: #e2e8f0;
    color: #0f172a;
    font-weight: 600;
  }
  .card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 24px;
    margin-bottom: 24px;
  }
  .card-title {
    font-size: 16px;
    font-weight: 600;
    margin-bottom: 16px;
    color: #0f172a;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 16px;
    margin-bottom: 24px;
  }
  .stat-card {
    background: var(--card);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 16px;
  }
  .stat-label { font-size: 12px; color: var(--text-muted); text-transform: uppercase; font-weight: 600; }
  .stat-val { font-size: 22px; font-weight: 700; margin-top: 4px; }
  table {
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
    text-align: left;
  }
  th {
    background: #f8fafc;
    color: var(--text-muted);
    font-weight: 600;
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
  }
  td {
    padding: 10px 12px;
    border-bottom: 1px solid var(--border);
  }
  tr:hover td { background-color: #f8fafc; }
  .badge {
    display: inline-block;
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 11px;
    font-weight: 600;
  }
  .badge-allowed { background: var(--allowed-bg); color: var(--allowed-text); }
  .badge-denied { background: var(--denied-bg); color: var(--denied-text); }
  .badge-warn { background: #fef9c3; color: #854d0e; }
  .btn {
    background: var(--accent);
    color: #fff;
    border: none;
    padding: 8px 16px;
    border-radius: 6px;
    font-size: 14px;
    cursor: pointer;
    font-weight: 500;
  }
  .btn:hover { background: var(--accent-hover); }
  .btn-outline {
    background: transparent;
    border: 1px solid var(--border);
    color: var(--text-primary);
  }
  .btn-outline:hover { background: #f1f5f9; }
  .form-group { margin-bottom: 16px; }
  .form-group label {
    display: block;
    font-size: 13px;
    font-weight: 600;
    margin-bottom: 6px;
    color: #334155;
  }
  .form-control {
    width: 100%;
    padding: 8px 12px;
    border: 1px solid var(--border);
    border-radius: 6px;
    font-size: 13px;
    background: #fff;
  }
  .form-control:focus { outline: none; border-color: var(--accent); }
  .row-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }
  .url-presets {
    display: flex;
    gap: 8px;
    margin-top: 8px;
    flex-wrap: wrap;
  }
  .preset-chip {
    font-size: 11px;
    background: #e2e8f0;
    padding: 3px 8px;
    border-radius: 4px;
    cursor: pointer;
    user-select: none;
  }
  .preset-chip:hover { background: #cbd5e1; }
  pre {
    background: #0f172a;
    color: #f8fafc;
    padding: 14px;
    border-radius: 6px;
    font-size: 12px;
    overflow-x: auto;
    line-height: 1.4;
  }
</style>
"""


def _build_shell(active_tab, body_content):
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Zero Trust Gateway Dashboard</title>
  {CSS}
</head>
<body>
  <div class="container">
    <div class="header">
      <div>
        <h1>Zero Trust Access Gateway</h1>
        <div class="tagline">Control Plane &bull; OPA Policy &bull; Redis Rate Limiter &bull; Sandbox Scanner</div>
      </div>
      <div>
        <a href="/test" class="btn" style="text-decoration:none;">+ Test Gateway Request</a>
      </div>
    </div>

    <div class="nav-tabs">
      <a href="/" class="nav-btn {'active' if active_tab == 'details' else ''}">System Details &amp; Logs</a>
      <a href="/test" class="nav-btn {'active' if active_tab == 'test' else ''}">Test Gateway (Form &amp; Upload)</a>
    </div>

    {body_content}

    <div style="text-align: center; color: var(--text-muted); font-size: 12px; margin-top: 30px;">
      Zero Trust Microservice Access Gateway &bull; Port 9000
    </div>
  </div>
</body>
</html>
"""


@app.get("/", response_class=HTMLResponse)
async def details_page(view: str = "30"):
    show_all = (view == "all")
    logs = _get_audit_logs(limit=None if show_all else 30)
    all_logs_summary = _get_audit_logs(limit=None)
    
    total = len(all_logs_summary)
    allowed = sum(1 for l in all_logs_summary if l["decision"] == "ALLOWED")
    denied = sum(1 for l in all_logs_summary if l["decision"] == "DENIED")
    denial_rate = round(denied / max(total, 1) * 100, 1)

    # Build Stats Grid
    stats_html = f"""
    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-label">Total Requests</div>
        <div class="stat-val">{total}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Allowed Requests</div>
        <div class="stat-val" style="color: var(--allowed-text);">{allowed}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Blocked / Denied</div>
        <div class="stat-val" style="color: var(--denied-text);">{denied}</div>
      </div>
      <div class="stat-card">
        <div class="stat-label">Denial Rate</div>
        <div class="stat-val">{denial_rate}%</div>
      </div>
    </div>
    """

    # Build Log Rows
    rows = ""
    for log in logs:
        is_allow = (log["decision"] == "ALLOWED")
        badge_class = "badge-allowed" if is_allow else "badge-denied"
        rows += f"""
        <tr>
          <td>#{log['id']}</td>
          <td style="color:var(--text-muted);">{str(log['created_at'])[:19]}</td>
          <td><b>{log['user_id']}</b></td>
          <td><code>{log['endpoint']}</code></td>
          <td><span class="badge {badge_class}">{log['decision']}</span></td>
          <td>{log['risk_score']}</td>
          <td style="font-size:12px;">{log['reason']}</td>
        </tr>
        """

    see_more_btn = ""
    if not show_all and total > 30:
        see_more_btn = f'<a href="/?view=all" class="btn btn-outline" style="text-decoration:none; font-size:12px;">See More (Show All {total} Logs)</a>'
    elif show_all:
        see_more_btn = '<a href="/?view=30" class="btn btn-outline" style="text-decoration:none; font-size:12px;">Show Last 30 Only</a>'

    audit_card = f"""
    <div class="card">
      <div class="card-title">
        <span>Recent Audit Logs ({len(logs)} shown)</span>
        <div>{see_more_btn}</div>
      </div>
      <table>
        <thead>
          <tr>
            <th>ID</th><th>Time</th><th>User</th><th>Endpoint</th>
            <th>Decision</th><th>Risk</th><th>Reason</th>
          </tr>
        </thead>
        <tbody>
          {rows if rows else '<tr><td colspan="7" style="text-align:center;">No audit logs recorded yet.</td></tr>'}
        </tbody>
      </table>
    </div>
    """

    # Risk Profiles Card
    profiles = _get_risk_profiles()
    p_rows = ""
    for p in profiles:
        warn = '<span class="badge badge-warn">ELEVATED</span>' if p["risk_score"] > 40 else ''
        p_rows += f"""
        <tr>
          <td><b>{p['user_id']}</b></td>
          <td>{p['risk_score']} {warn}</td>
          <td style="color:var(--text-muted);">{str(p['last_updated'])[:19]}</td>
        </tr>
        """

    profiles_card = f"""
    <div class="card">
      <div class="card-title">User Risk Profiles</div>
      <table>
        <thead>
          <tr><th>User ID</th><th>Current Risk Score</th><th>Last Updated</th></tr>
        </thead>
        <tbody>
          {p_rows}
        </tbody>
      </table>
    </div>
    """

    return HTMLResponse(_build_shell("details", stats_html + audit_card + profiles_card))


@app.get("/test", response_class=HTMLResponse)
async def test_page_get():
    return HTMLResponse(_build_shell("test", _render_test_form()))


@app.post("/test", response_class=HTMLResponse)
async def test_page_post(
    request: Request,
    target_path: str = Form("/api/v1/user/data"),
    authorization: str = Form("Bearer my-token"),
    user_id: str = Form("alice"),
    role: str = Form("user"),
    risk_score: str = Form("12"),
    method: str = Form("GET"),
    file: UploadFile = File(None)
):
    url = PROXY_URL + target_path
    headers = {
        "X-User-ID": user_id,
        "X-Role": role,
        "X-Risk-Score": risk_score,
    }
    if authorization.strip():
        headers["Authorization"] = authorization.strip()

    status_code = 0
    resp_text = ""
    sent_file_name = None

    try:
        files = None
        if file and file.filename:
            sent_file_name = file.filename
            content = await file.read()
            files = {"file": (file.filename, content, file.content_type or "application/octet-stream")}

        if method == "GET":
            r = requests.get(url, headers=headers, timeout=10)
        elif method == "POST":
            r = requests.post(url, headers=headers, files=files, timeout=10)
        elif method == "PUT":
            r = requests.put(url, headers=headers, files=files, timeout=10)
        elif method == "DELETE":
            r = requests.delete(url, headers=headers, timeout=10)
        else:
            r = requests.request(method, url, headers=headers, timeout=10)

        status_code = r.status_code
        try:
            resp_text = json.dumps(r.json(), indent=2)
        except Exception:
            resp_text = r.text
    except Exception as e:
        resp_text = f"Gateway Connection Error: {str(e)}"
        status_code = 502

    status_badge = '<span class="badge badge-allowed">200 OK</span>' if status_code == 200 else f'<span class="badge badge-denied">{status_code}</span>'

    result_card = f"""
    <div class="card" style="border-left: 4px solid {'#10b981' if status_code == 200 else '#ef4444'};">
      <div class="card-title">
        <span>Execution Result</span>
        <span>{status_badge}</span>
      </div>
      <p style="font-size:13px; margin-bottom: 8px;"><b>Target:</b> <code>{method} {url}</code></p>
      {f'<p style="font-size:13px; margin-bottom: 8px;"><b>File Attached:</b> <code>{sent_file_name}</code> (sent to Sandbox scanner)</p>' if sent_file_name else ''}
      <div style="margin-top: 12px;">
        <label style="font-size: 12px; font-weight: 600; color: var(--text-muted);">RESPONSE PAYLOAD</label>
        <pre>{resp_text}</pre>
      </div>
    </div>
    """

    form_rendered = _render_test_form(target_path, authorization, user_id, role, risk_score, method)
    return HTMLResponse(_build_shell("test", result_card + form_rendered))


def _render_test_form(path="/api/v1/user/data", auth="Bearer my-token",
                      uid="alice", role="user", risk="12", method="GET"):
    return f"""
    <div class="card">
      <div class="card-title">Configure &amp; Dispatch Request</div>
      <form method="post" action="/test" enctype="multipart/form-data">
        <div class="row-2">
          <div class="form-group">
            <label>HTTP Method</label>
            <select name="method" class="form-control" id="methodSelect">
              <option value="GET" {'selected' if method == 'GET' else ''}>GET</option>
              <option value="POST" {'selected' if method == 'POST' else ''}>POST</option>
              <option value="PUT" {'selected' if method == 'PUT' else ''}>PUT</option>
              <option value="DELETE" {'selected' if method == 'DELETE' else ''}>DELETE</option>
            </select>
          </div>
          <div class="form-group">
            <label>Target URL Endpoint</label>
            <input type="text" name="target_path" id="targetPath" class="form-control" value="{path}">
            <div class="url-presets">
              <span class="preset-chip" onclick="setEndpoint('/api/v1/user/data', 'GET')">/api/v1/user/data (User)</span>
              <span class="preset-chip" onclick="setEndpoint('/api/v1/user/upload', 'POST')">/api/v1/user/upload (File Scan)</span>
              <span class="preset-chip" onclick="setEndpoint('/api/v1/admin/metrics', 'GET')">/api/v1/admin/metrics (Admin)</span>
              <span class="preset-chip" onclick="setEndpoint('/api/v1/public/status', 'GET')">/api/v1/public/status (Public)</span>
            </div>
          </div>
        </div>

        <div class="form-group">
          <label>Authorization Header (e.g. Bearer my-token)</label>
          <input type="text" name="authorization" class="form-control" value="{auth}">
          <small style="color: var(--text-muted); font-size: 11px;">Leave empty or remove 'Bearer' to test unauthenticated rejection.</small>
        </div>

        <div class="row-2">
          <div class="form-group">
            <label>X-User-ID</label>
            <input type="text" name="user_id" class="form-control" value="{uid}">
          </div>
          <div class="form-group">
            <label>X-Role</label>
            <select name="role" class="form-control">
              <option value="user" {'selected' if role == 'user' else ''}>user</option>
              <option value="admin" {'selected' if role == 'admin' else ''}>admin</option>
            </select>
          </div>
        </div>

        <div class="row-2">
          <div class="form-group">
            <label>X-Risk-Score (0 - 100)</label>
            <input type="number" name="risk_score" class="form-control" value="{risk}" min="0" max="100">
            <small style="color: var(--text-muted); font-size: 11px;">Threshold is 50. &ge;50 is blocked by OPA.</small>
          </div>
          <div class="form-group">
            <label>Upload File (Triggers Sandbox Scanner)</label>
            <input type="file" name="file" class="form-control" style="padding: 5px;">
            <small style="color: var(--text-muted); font-size: 11px;">Files containing malicious strings will be quarantined with 422.</small>
          </div>
        </div>

        <button type="submit" class="btn" style="margin-top: 10px; width: 100%; padding: 10px;">Send Request Through Gateway</button>
      </form>
    </div>

    <script>
      function setEndpoint(path, method) {{
        document.getElementById('targetPath').value = path;
        document.getElementById('methodSelect').value = method;
      }}
    </script>
    """


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9000)
