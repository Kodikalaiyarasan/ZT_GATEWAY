package com.ztgateway.controlplane.controller;

import com.ztgateway.controlplane.model.AuditLog;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * Read-only audit trail API — used by the MCP server and operational
 * dashboards to query recent access decisions.
 */
@RestController
@RequestMapping("/v1/audit")
public class AuditController {

    @PersistenceContext
    private EntityManager entityManager;

    /**
     * Fetch the most recent audit log entries.
     *
     * @param limit maximum number of entries to return (default 50)
     */
    @GetMapping("/logs")
    public ResponseEntity<List<AuditLog>> getLogs(
            @RequestParam(defaultValue = "50") int limit) {

        @SuppressWarnings("unchecked")
        List<AuditLog> logs = entityManager
                .createQuery("SELECT a FROM AuditLog a ORDER BY a.createdAt DESC")
                .setMaxResults(Math.min(limit, 500))
                .getResultList();

        return ResponseEntity.ok(logs);
    }

    /**
     * Fetch denied-only audit entries for incident investigation.
     */
    @GetMapping("/logs/denied")
    public ResponseEntity<List<AuditLog>> getDeniedLogs(
            @RequestParam(defaultValue = "50") int limit) {

        @SuppressWarnings("unchecked")
        List<AuditLog> logs = entityManager
                .createQuery("SELECT a FROM AuditLog a WHERE a.decision = 'DENIED' ORDER BY a.createdAt DESC")
                .setMaxResults(Math.min(limit, 500))
                .getResultList();

        return ResponseEntity.ok(logs);
    }
}
