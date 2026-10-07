-- ============================================================
-- Zero Trust Microservice Access Gateway — Database Schema
-- ============================================================

-- Audit trail of every access decision made by the gateway
CREATE TABLE IF NOT EXISTS audit_logs (
    id            BIGSERIAL    PRIMARY KEY,
    created_at    TIMESTAMP    NOT NULL DEFAULT NOW(),
    user_id       VARCHAR(128) NOT NULL,
    client_ip     VARCHAR(45)  NOT NULL,          -- supports IPv6
    endpoint      VARCHAR(512) NOT NULL,
    decision      VARCHAR(16)  NOT NULL CHECK (decision IN ('ALLOWED', 'DENIED')),
    risk_score    INTEGER      NOT NULL DEFAULT 0,
    reason        TEXT
);

CREATE INDEX idx_audit_logs_user      ON audit_logs (user_id);
CREATE INDEX idx_audit_logs_decision  ON audit_logs (decision);
CREATE INDEX idx_audit_logs_created   ON audit_logs (created_at DESC);

-- Persistent risk profile per identity
CREATE TABLE IF NOT EXISTS user_risk_profiles (
    user_id       VARCHAR(128) PRIMARY KEY,
    risk_score    INTEGER      NOT NULL DEFAULT 0,
    last_updated  TIMESTAMP    NOT NULL DEFAULT NOW()
);

-- ============================================================
-- Seed Data — realistic entries for testing
-- ============================================================

INSERT INTO user_risk_profiles (user_id, risk_score, last_updated) VALUES
    ('alice',   12, NOW() - INTERVAL '2 hours'),
    ('bob',     35, NOW() - INTERVAL '1 hour'),
    ('charlie', 65, NOW() - INTERVAL '30 minutes'),
    ('diana',    5, NOW() - INTERVAL '4 hours'),
    ('eve',     48, NOW() - INTERVAL '15 minutes'),
    ('frank',   72, NOW() - INTERVAL '10 minutes'),
    ('grace',   22, NOW() - INTERVAL '3 hours'),
    ('heidi',   90, NOW() - INTERVAL '5 minutes');

INSERT INTO audit_logs (created_at, user_id, client_ip, endpoint, decision, risk_score, reason) VALUES
    (NOW() - INTERVAL '60 minutes', 'alice',   '10.0.1.14',  '/api/v1/user/data',     'ALLOWED', 12, 'Policy passed — low risk, valid role'),
    (NOW() - INTERVAL '55 minutes', 'bob',     '10.0.1.20',  '/api/v1/user/data',     'ALLOWED', 35, 'Policy passed — moderate risk, valid role'),
    (NOW() - INTERVAL '50 minutes', 'charlie', '192.168.1.5', '/api/v1/admin/metrics', 'DENIED',  65, 'Risk score 65 exceeds threshold of 50'),
    (NOW() - INTERVAL '45 minutes', 'diana',   '172.16.0.8',  '/api/v1/user/data',     'ALLOWED',  5, 'Policy passed — low risk'),
    (NOW() - INTERVAL '40 minutes', 'eve',     '10.0.2.33',   '/api/v1/admin/metrics', 'DENIED',  48, 'Role "user" cannot access /api/v1/admin/*'),
    (NOW() - INTERVAL '35 minutes', 'frank',   '203.0.113.7', '/api/v1/user/data',     'DENIED',  72, 'Risk score 72 exceeds threshold of 50'),
    (NOW() - INTERVAL '30 minutes', 'alice',   '10.0.1.14',  '/api/v1/public/health',  'ALLOWED', 12, 'Policy passed — public endpoint'),
    (NOW() - INTERVAL '25 minutes', 'heidi',   '198.51.100.1','/api/v1/admin/metrics', 'DENIED',  90, 'Risk score 90 exceeds threshold of 50'),
    (NOW() - INTERVAL '20 minutes', 'bob',     '10.0.1.20',  '/api/v1/admin/metrics',  'DENIED',  35, 'Role "user" cannot access /api/v1/admin/*'),
    (NOW() - INTERVAL '15 minutes', 'grace',   '10.0.3.42',  '/api/v1/user/data',      'ALLOWED', 22, 'Policy passed — low risk, valid role'),
    (NOW() - INTERVAL '10 minutes', 'charlie', '192.168.1.5', '/api/v1/user/data',      'DENIED',  65, 'Risk score 65 exceeds threshold of 50'),
    (NOW() - INTERVAL '5 minutes',  'frank',   '203.0.113.7', '/api/v1/public/health',  'DENIED',  72, 'Risk score 72 exceeds threshold of 50');
