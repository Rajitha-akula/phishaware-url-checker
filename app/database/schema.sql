-- =====================================================================
-- Secure Phishing Awareness & URL Risk Checker - Database Schema
-- Design: 3NF Relational Structure with Foreign Key Cascades & Indexes
-- =====================================================================

CREATE DATABASE IF NOT EXISTS phishing_checker_db
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE phishing_checker_db;

-- ---------------------------------------------------------------------
-- Table 1: assessments
-- Stores individual URL risk evaluations with summary metrics.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assessments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    raw_url TEXT NOT NULL,
    normalized_url TEXT NOT NULL,
    host VARCHAR(255) NOT NULL,
    scheme VARCHAR(16) NOT NULL,
    risk_score INT NOT NULL,
    risk_level VARCHAR(32) NOT NULL,
    color VARCHAR(16) NOT NULL,
    breakdown_summary TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_host (host),
    INDEX idx_risk_level (risk_level),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ---------------------------------------------------------------------
-- Table 2: triggered_rules
-- Stores individual heuristic rules activated during an assessment.
-- Linked to assessments via Foreign Key with ON DELETE CASCADE.
-- ---------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS triggered_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    assessment_id INT NOT NULL,
    rule_id VARCHAR(16) NOT NULL,
    rule_name VARCHAR(128) NOT NULL,
    category VARCHAR(64) NOT NULL,
    weight INT NOT NULL,
    description TEXT,
    explanation TEXT,
    guidance TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_assessment_id (assessment_id),
    INDEX idx_rule_id (rule_id),
    CONSTRAINT fk_triggered_rules_assessment
        FOREIGN KEY (assessment_id)
        REFERENCES assessments(id)
        ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
