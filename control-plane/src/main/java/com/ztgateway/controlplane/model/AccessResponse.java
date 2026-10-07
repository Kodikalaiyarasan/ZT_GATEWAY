package com.ztgateway.controlplane.model;

import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Response returned to the data-plane proxy after policy evaluation.
 */
public class AccessResponse {

    @JsonProperty("allowed")
    private boolean allowed;

    @JsonProperty("reason")
    private String reason;

    public AccessResponse() {
    }

    public AccessResponse(boolean allowed, String reason) {
        this.allowed = allowed;
        this.reason = reason;
    }

    public boolean isAllowed()       { return allowed; }
    public void setAllowed(boolean v) { this.allowed = v; }

    public String getReason()       { return reason; }
    public void setReason(String v) { this.reason = v; }
}
