package com.ztgateway.controlplane.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.ztgateway.controlplane.model.AccessRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

/**
 * Evaluates an {@link AccessRequest} against the Open Policy Agent (OPA)
 * sidecar over its REST Data API.
 *
 * <p>The OPA endpoint returns JSON of the form:
 * <pre>{@code
 * {
 *   "result": {
 *     "allow": true,
 *     "reason": "..."
 *   }
 * }
 * }</pre>
 */
@Service
public class PolicyEvaluationService {

    private static final Logger log = LoggerFactory.getLogger(PolicyEvaluationService.class);

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private final String opaUrl;

    public PolicyEvaluationService(
            @Value("${zt.opa.url:http://opa:8181/v1/data/ztmesh/authz}") String opaUrl) {
        this.restTemplate = new RestTemplate();
        this.objectMapper = new ObjectMapper();
        this.opaUrl = opaUrl;
    }

    /**
     * Call OPA and return a two-element result: [allowed, reason].
     */
    public PolicyResult evaluate(AccessRequest req) {
        try {
            // Build the OPA input document
            ObjectNode input = objectMapper.createObjectNode();
            input.put("jwt_valid", req.isJwtValid());
            input.put("role", req.getRole());
            input.put("risk_score", req.getRiskScore());
            input.put("path", req.getPath());
            input.put("user_id", req.getUserId());
            input.put("client_ip", req.getClientIp());

            ObjectNode body = objectMapper.createObjectNode();
            body.set("input", input);

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);

            HttpEntity<String> entity = new HttpEntity<>(objectMapper.writeValueAsString(body), headers);

            log.debug("Calling OPA at {} with body={}", opaUrl, body);
            ResponseEntity<String> response = restTemplate.postForEntity(opaUrl, entity, String.class);

            if (response.getStatusCode().is2xxSuccessful() && response.getBody() != null) {
                JsonNode root = objectMapper.readTree(response.getBody());
                JsonNode result = root.path("result");

                boolean allowed = result.path("allow").asBoolean(false);
                String reason = result.path("reason").asText("No reason provided by policy");

                if (allowed) {
                    reason = "Policy passed — access granted";
                }

                log.info("OPA decision: allowed={} reason=\"{}\" user={} path={}",
                         allowed, reason, req.getUserId(), req.getPath());
                return new PolicyResult(allowed, reason);
            }

            log.warn("OPA returned non-2xx or empty body: status={}", response.getStatusCode());
            return new PolicyResult(false, "OPA unavailable — fail-closed");

        } catch (Exception ex) {
            log.error("OPA evaluation failed: {}", ex.getMessage(), ex);
            return new PolicyResult(false, "OPA evaluation error — fail-closed: " + ex.getMessage());
        }
    }

    /**
     * Simple record-like holder for the evaluation result.
     */
    public static class PolicyResult {
        private final boolean allowed;
        private final String reason;

        public PolicyResult(boolean allowed, String reason) {
            this.allowed = allowed;
            this.reason = reason;
        }

        public boolean isAllowed() { return allowed; }
        public String getReason()  { return reason; }
    }
}
