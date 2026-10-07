package com.ztgateway.controlplane.controller;

import com.ztgateway.controlplane.model.AccessRequest;
import com.ztgateway.controlplane.model.AccessResponse;
import com.ztgateway.controlplane.service.AuditLogService;
import com.ztgateway.controlplane.service.PolicyEvaluationService;
import com.ztgateway.controlplane.service.PolicyEvaluationService.PolicyResult;
import com.ztgateway.controlplane.service.RateLimiterService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

/**
 * Primary evaluation endpoint consumed by the C++ data-plane proxy.
 *
 * Flow:
 * <ol>
 *   <li>Check Redis token-revocation list.</li>
 *   <li>Enforce per-IP rate limit.</li>
 *   <li>Delegate to OPA for fine-grained authorization.</li>
 *   <li>Log the decision asynchronously to PostgreSQL.</li>
 * </ol>
 */
@RestController
@RequestMapping("/v1")
public class AccessController {

    private static final Logger log = LoggerFactory.getLogger(AccessController.class);

    private final PolicyEvaluationService policyService;
    private final RateLimiterService rateLimiter;
    private final AuditLogService auditLogService;
    private final StringRedisTemplate redis;

    public AccessController(PolicyEvaluationService policyService,
                            RateLimiterService rateLimiter,
                            AuditLogService auditLogService,
                            StringRedisTemplate redis) {
        this.policyService = policyService;
        this.rateLimiter = rateLimiter;
        this.auditLogService = auditLogService;
        this.redis = redis;
    }

    @PostMapping("/evaluate")
    public ResponseEntity<AccessResponse> evaluate(@RequestBody AccessRequest request) {

        log.info("Evaluate: user={} ip={} path={} role={} risk={}",
                 request.getUserId(), request.getClientIp(),
                 request.getPath(), request.getRole(), request.getRiskScore());

        // ── 1. Token revocation check ────────────────────────────
        String revokeKey = "revoked:" + request.getUserId();
        Boolean revoked = redis.hasKey(revokeKey);
        if (Boolean.TRUE.equals(revoked)) {
            String reason = "Token revoked for user " + request.getUserId();
            auditLogService.record(request.getUserId(), request.getClientIp(),
                                   request.getPath(), false,
                                   request.getRiskScore(), reason);
            return ResponseEntity.ok(new AccessResponse(false, reason));
        }

        // ── 2. Rate limit ────────────────────────────────────────
        if (!rateLimiter.isAllowed(request.getClientIp())) {
            String reason = "Rate limit exceeded for IP " + request.getClientIp();
            auditLogService.record(request.getUserId(), request.getClientIp(),
                                   request.getPath(), false,
                                   request.getRiskScore(), reason);
            return ResponseEntity.status(429)
                    .body(new AccessResponse(false, reason));
        }

        // ── 3. OPA policy evaluation ─────────────────────────────
        PolicyResult result = policyService.evaluate(request);

        // ── 4. Asynchronous audit log ────────────────────────────
        auditLogService.record(request.getUserId(), request.getClientIp(),
                               request.getPath(), result.isAllowed(),
                               request.getRiskScore(), result.getReason());

        AccessResponse response = new AccessResponse(result.isAllowed(), result.getReason());
        return ResponseEntity.ok(response);
    }

    /**
     * Liveness probe — does not hit any downstream dependency.
     */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("{\"status\":\"UP\"}");
    }
}
