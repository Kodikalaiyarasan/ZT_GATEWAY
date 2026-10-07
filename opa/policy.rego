# ============================================================
# Zero Trust Mesh — OPA Authorization Policy (v0 Rego)
# Compatible with OPA 0.64.x
# ============================================================
package ztmesh.authz

default allow = false

# Main authorization rule — all sub-conditions must pass
allow {
    input.jwt_valid == true
    input.risk_score < 50
    path_authorized
}

# Admins can access every path
path_authorized {
    input.role == "admin"
}

# Regular users may access /api/v1/public/* and /api/v1/user/*
path_authorized {
    input.role == "user"
    startswith(input.path, "/api/v1/public/")
}

path_authorized {
    input.role == "user"
    startswith(input.path, "/api/v1/user/")
}

# Deny reason helpers — used by the control plane for audit logging
reason = msg {
    not input.jwt_valid
    msg := "JWT validation failed — token invalid or expired"
}

reason = msg {
    input.jwt_valid == true
    input.risk_score >= 50
    msg := sprintf("Risk score %d exceeds threshold of 50", [input.risk_score])
}

reason = msg {
    input.jwt_valid == true
    input.risk_score < 50
    not path_authorized
    msg := sprintf("Role \"%s\" cannot access %s", [input.role, input.path])
}
