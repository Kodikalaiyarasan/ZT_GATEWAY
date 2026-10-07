package com.ztgateway.controlplane.service;

import com.ztgateway.controlplane.model.AuditLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

/**
 * Asynchronously persists {@link AuditLog} entries to PostgreSQL.
 *
 * Running on a separate thread ensures the main evaluation path
 * is not blocked by database I/O.
 */
@Service
public class AuditLogService {

    private static final Logger log = LoggerFactory.getLogger(AuditLogService.class);

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Persist an audit log entry asynchronously.
     */
    @Async
    @Transactional
    public void record(String userId, String clientIp, String endpoint,
                       boolean allowed, int riskScore, String reason) {
        try {
            String decision = allowed ? "ALLOWED" : "DENIED";
            AuditLog entry = new AuditLog(userId, clientIp, endpoint,
                                          decision, riskScore, reason);
            entityManager.persist(entry);
            log.debug("Audit log persisted: user={} endpoint={} decision={}",
                      userId, endpoint, decision);
        } catch (Exception ex) {
            log.error("Failed to persist audit log: {}", ex.getMessage(), ex);
        }
    }
}
