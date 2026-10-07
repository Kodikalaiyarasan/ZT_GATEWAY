package com.ztgateway.controlplane;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

/**
 * Zero Trust Gateway — Control Plane
 *
 * Central decision engine that validates JWTs, evaluates OPA policies,
 * enforces Redis-backed rate limits, and writes audit trails to PostgreSQL.
 */
@SpringBootApplication
@EnableAsync
public class ControlPlaneApplication {

    public static void main(String[] args) {
        SpringApplication.run(ControlPlaneApplication.class, args);
    }
}
