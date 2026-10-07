package com.ztgateway.controlplane.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Inbound evaluation request sent by the C++ data-plane proxy.
 * Contains the identity and context attributes extracted from the
 * original client HTTP request.
 */
public class AccessRequest {

    @JsonProperty("user_id")
    private String userId;

    @JsonProperty("role")
    private String role;

    @JsonProperty("jwt_valid")
    private boolean jwtValid;

    @JsonProperty("client_ip")
    private String clientIp;

    @JsonProperty("path")
    private String path;

    @JsonProperty("risk_score")
    private int riskScore;

    public AccessRequest() {
    }

    public AccessRequest(String userId, String role, boolean jwtValid,
                         String clientIp, String path, int riskScore) {
        this.userId = userId;
        this.role = role;
        this.jwtValid = jwtValid;
        this.clientIp = clientIp;
        this.path = path;
        this.riskScore = riskScore;
    }

    public String getUserId()       { return userId; }
    public void setUserId(String v) { this.userId = v; }

    public String getRole()       { return role; }
    public void setRole(String v) { this.role = v; }

    public boolean isJwtValid()       { return jwtValid; }
    public void setJwtValid(boolean v) { this.jwtValid = v; }

    public String getClientIp()       { return clientIp; }
    public void setClientIp(String v) { this.clientIp = v; }

    public String getPath()       { return path; }
    public void setPath(String v) { this.path = v; }

    public int getRiskScore()      { return riskScore; }
    public void setRiskScore(int v) { this.riskScore = v; }
}
