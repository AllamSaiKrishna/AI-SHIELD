-- AI-SHIELD Database Schema

CREATE TABLE IF NOT EXISTS traffic_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    src_ip TEXT NOT NULL,
    dst_ip TEXT NOT NULL,
    protocol TEXT NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    duration REAL DEFAULT 0.0,
    byte_count INTEGER DEFAULT 0,
    packet_count INTEGER DEFAULT 0,
    packet_rate REAL DEFAULT 0.0,
    predicted_class TEXT NOT NULL,
    confidence REAL DEFAULT 0.0,
    source_mode TEXT DEFAULT 'live'
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    traffic_id INTEGER,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    status TEXT DEFAULT 'New', -- 'New', 'Acknowledged', 'Investigating', 'Resolved'
    details TEXT,
    src_ip TEXT,
    dst_ip TEXT,
    confidence REAL DEFAULT 0.0,
    FOREIGN KEY(traffic_id) REFERENCES traffic_records(id) ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS prevention_actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    target_ip TEXT NOT NULL,
    reason TEXT NOT NULL,
    rule_name TEXT NOT NULL,
    action_type TEXT DEFAULT 'BLOCK', -- 'BLOCK', 'UNBLOCK'
    status TEXT DEFAULT 'APPLIED',    -- 'APPLIED', 'VERIFIED', 'FAILED', 'EXPIRED', 'REMOVED'
    applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME,
    verified INTEGER DEFAULT 1
);

CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    event_type TEXT NOT NULL,
    actor TEXT DEFAULT 'SYSTEM',
    details TEXT NOT NULL,
    status TEXT DEFAULT 'SUCCESS' -- 'SUCCESS', 'WARNING', 'ERROR'
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Performance Indexes
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_records(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_class ON traffic_records(predicted_class);
CREATE INDEX IF NOT EXISTS idx_alerts_status ON alerts(status);
CREATE INDEX IF NOT EXISTS idx_prevention_ip ON prevention_actions(target_ip);
