package com.ztgateway.controlplane.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

/**
 * Fixed-window rate limiter backed by Redis atomic counters.
 *
 * Each unique client IP gets a key in Redis whose value is incremented
 * atomically on every request.  The key expires after {@code windowSeconds},
 * effectively resetting the counter.
 *
 * If the counter exceeds {@code maxRequests} within the window the request
 * is rejected.
 */
@Service
public class RateLimiterService {

    private static final Logger log = LoggerFactory.getLogger(RateLimiterService.class);

    private final StringRedisTemplate redis;
    private final int maxRequests;
    private final int windowSeconds;

    public RateLimiterService(
            StringRedisTemplate redis,
            @Value("${zt.rate-limit.max-requests:10}") int maxRequests,
            @Value("${zt.rate-limit.window-seconds:10}") int windowSeconds) {
        this.redis = redis;
        this.maxRequests = maxRequests;
        this.windowSeconds = windowSeconds;
    }

    /**
     * @return {@code true} if the request is within the rate limit,
     *         {@code false} if the client should be throttled.
     */
    public boolean isAllowed(String clientIp) {
        String key = "rl:" + clientIp;

        try {
            Long count = redis.opsForValue().increment(key);
            if (count == null) {
                log.warn("Redis INCR returned null for key={}", key);
                return true;  // fail-open on Redis issues to avoid total outage
            }

            // Set expiry only on the first request in the window
            if (count == 1L) {
                redis.expire(key, Duration.ofSeconds(windowSeconds));
            }

            if (count > maxRequests) {
                log.info("Rate limit exceeded for IP={} count={}/{}", clientIp, count, maxRequests);
                return false;
            }

            return true;
        } catch (Exception ex) {
            log.error("Redis rate-limiter error for IP={}: {}", clientIp, ex.getMessage(), ex);
            return true;  // fail-open
        }
    }
}
