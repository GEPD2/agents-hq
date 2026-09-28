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

-- v3: Case Files - grouped investigations
CREATE TABLE IF NOT EXISTS cases (
    id          VARCHAR(64)  NOT NULL PRIMARY KEY,
    name        VARCHAR(255) NOT NULL,
    description TEXT,
    tags        VARCHAR(500),
    brief       LONGTEXT,
    created_at  DATETIME,
    updated_at  DATETIME,
    INDEX idx_name (name(100))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS case_items (
    id         VARCHAR(64)  NOT NULL PRIMARY KEY,
    case_id    VARCHAR(64)  NOT NULL,
    item_type  ENUM('report','ioc','threat_actor') NOT NULL,
    ref        VARCHAR(500) NOT NULL,
    label      VARCHAR(500),
    added_at   DATETIME,
    INDEX idx_case (case_id),
    CONSTRAINT fk_case FOREIGN KEY (case_id) REFERENCES cases(id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- v4: IP geolocation cache for the map view
CREATE TABLE IF NOT EXISTS ip_geo (
    ip         VARCHAR(45)  NOT NULL PRIMARY KEY,
    lat        DOUBLE,
    lon        DOUBLE,
    country    VARCHAR(100),
    city       VARCHAR(150),
    cached_at  DATETIME
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
