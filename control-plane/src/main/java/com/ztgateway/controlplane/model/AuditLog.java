package com.ztgateway.controlplane.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import java.time.LocalDateTime;

/**
 * JPA entity mapped to the {@code audit_logs} table in PostgreSQL.
 */
@Entity
@Table(name = "audit_logs")
public class AuditLog {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "created_at", nullable = false)
    private LocalDateTime createdAt;

    @Column(name = "user_id", nullable = false, length = 128)
    private String userId;

    @Column(name = "client_ip", nullable = false, length = 45)
    private String clientIp;

    @Column(name = "endpoint", nullable = false, length = 512)
    private String endpoint;

    @Column(name = "decision", nullable = false, length = 16)
    private String decision;

    @Column(name = "risk_score", nullable = false)
    private int riskScore;

    @Column(name = "reason", columnDefinition = "TEXT")
    private String reason;

    public AuditLog() {
    }

    public AuditLog(String userId, String clientIp, String endpoint,
                    String decision, int riskScore, String reason) {
        this.createdAt = LocalDateTime.now();
        this.userId = userId;
        this.clientIp = clientIp;
        this.endpoint = endpoint;
        this.decision = decision;
        this.riskScore = riskScore;
        this.reason = reason;
    }

    // ── Getters & Setters ──────────────────────────────────────────

    public Long getId()                       { return id; }
    public void setId(Long id)                { this.id = id; }

    public LocalDateTime getCreatedAt()       { return createdAt; }
    public void setCreatedAt(LocalDateTime v) { this.createdAt = v; }

    public String getUserId()       { return userId; }
    public void setUserId(String v) { this.userId = v; }

    public String getClientIp()       { return clientIp; }
    public void setClientIp(String v) { this.clientIp = v; }

    public String getEndpoint()       { return endpoint; }
    public void setEndpoint(String v) { this.endpoint = v; }

    public String getDecision()       { return decision; }
    public void setDecision(String v) { this.decision = v; }

    public int getRiskScore()      { return riskScore; }
    public void setRiskScore(int v) { this.riskScore = v; }

    public String getReason()       { return reason; }
    public void setReason(String v) { this.reason = v; }
}
