-- AGENTS-HQ MySQL schema
-- v2: added iocs table for IOC Correlation Engine

CREATE TABLE IF NOT EXISTS documents (
    id           VARCHAR(255)  NOT NULL PRIMARY KEY,
    collection   VARCHAR(100)  NOT NULL,
    content      LONGTEXT,
    source       VARCHAR(1000),
    doc_timestamp DATETIME,
    metadata     JSON,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_collection (collection),
    INDEX idx_source     (source(255)),
    FULLTEXT INDEX ft_content (content)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS threat_actors (
    id           VARCHAR(255)  NOT NULL PRIMARY KEY,
    name         VARCHAR(500)  NOT NULL,
    content      LONGTEXT,
    last_updated DATETIME,
    metadata     JSON,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_name (name(100)),
    FULLTEXT INDEX ft_profile (name, content)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS iocs (
    id          VARCHAR(255) NOT NULL PRIMARY KEY,
    type        ENUM('ip','domain','email','hash','cve','onion','wallet') NOT NULL,
    value       VARCHAR(500) NOT NULL,
    report_file VARCHAR(500) NOT NULL,
    agent_id    VARCHAR(10),
    seen_at     DATETIME,
    INDEX idx_type_value (type, value(200)),
    INDEX idx_report     (report_file(200)),
    INDEX idx_type       (type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
