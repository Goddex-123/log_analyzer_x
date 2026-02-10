"""
Log Analyzer X – Configuration & Settings
Central configuration for the entire platform.
"""

# ─── Application Metadata ──────────────────────────────────────────
APP_NAME = "Log Analyzer X"
APP_SUBTITLE = "Enterprise Security & Performance Intelligence Platform"
APP_VERSION = "1.0.0"

# ─── Color Palette (Dark-first Enterprise Theme) ───────────────────
COLORS = {
    "bg_primary": "#0a0e17",
    "bg_secondary": "#111827",
    "bg_card": "#1a1f2e",
    "bg_card_hover": "#242b3d",
    "accent_blue": "#3b82f6",
    "accent_cyan": "#06b6d4",
    "accent_purple": "#8b5cf6",
    "accent_green": "#10b981",
    "accent_amber": "#f59e0b",
    "accent_red": "#ef4444",
    "accent_pink": "#ec4899",
    "text_primary": "#f1f5f9",
    "text_secondary": "#94a3b8",
    "text_muted": "#64748b",
    "border": "#1e293b",
    "gradient_1": "linear-gradient(135deg, #3b82f6, #8b5cf6)",
    "gradient_2": "linear-gradient(135deg, #06b6d4, #10b981)",
    "gradient_3": "linear-gradient(135deg, #f59e0b, #ef4444)",
    "gradient_4": "linear-gradient(135deg, #ec4899, #8b5cf6)",
}

# ─── Severity Levels ───────────────────────────────────────────────
SEVERITY = {
    "INFO": {"color": "#3b82f6", "icon": "ℹ️", "label": "Info"},
    "WARNING": {"color": "#f59e0b", "icon": "⚠️", "label": "Warning"},
    "CRITICAL": {"color": "#ef4444", "icon": "🚨", "label": "Critical"},
}

# ─── RAG Status Colors ─────────────────────────────────────────────
RAG_STATUS = {
    "GREEN": {"color": "#10b981", "icon": "🟢", "label": "Healthy", "threshold": 0.85},
    "AMBER": {"color": "#f59e0b", "icon": "🟡", "label": "Degraded", "threshold": 0.60},
    "RED": {"color": "#ef4444", "icon": "🔴", "label": "Critical", "threshold": 0.0},
}

# ─── SLA Thresholds ────────────────────────────────────────────────
SLA_THRESHOLDS = {
    "latency_p95_ms": 500,
    "latency_p99_ms": 1000,
    "error_rate_pct": 5.0,
    "availability_pct": 99.5,
}

# ─── Security Detection Thresholds ─────────────────────────────────
SECURITY = {
    "brute_force_threshold": 5,         # failures from same IP in window
    "brute_force_window_min": 10,       # time window in minutes
    "credential_stuffing_threshold": 3, # unique users from single IP in window
    "credential_stuffing_window_min": 5,
    "high_risk_score": 70,
    "critical_risk_score": 85,
}

# ─── MITRE ATT&CK Mapping (Simulated) ──────────────────────────────
MITRE_MAPPING = {
    "brute_force": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversary attempts to gain access by systematically trying passwords.",
    },
    "credential_stuffing": {
        "technique_id": "T1110.004",
        "technique_name": "Credential Stuffing",
        "tactic": "Credential Access",
        "description": "Use of previously compromised credentials across multiple accounts.",
    },
    "valid_accounts": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion / Initial Access",
        "description": "Adversary uses legitimate credentials to access systems.",
    },
    "account_manipulation": {
        "technique_id": "T1098",
        "technique_name": "Account Manipulation",
        "tactic": "Persistence",
        "description": "Adversary manipulates accounts to maintain access.",
    },
    "remote_services": {
        "technique_id": "T1021",
        "technique_name": "Remote Services",
        "tactic": "Lateral Movement",
        "description": "Adversary uses remote services to move laterally.",
    },
}

# ─── Expected Log Schema ───────────────────────────────────────────
EXPECTED_COLUMNS = {
    "timestamp": ["timestamp", "time", "datetime", "date", "login_time", "event_time", "created_at", "log_time"],
    "user_id": ["user_id", "user", "username", "user_name", "uid", "account", "login"],
    "ip_address": ["ip_address", "ip", "src_ip", "source_ip", "client_ip", "remote_addr"],
    "status": ["status", "status_code", "http_status", "response_code", "result", "outcome"],
    "method": ["method", "http_method", "request_method", "action", "operation"],
    "endpoint": ["endpoint", "path", "url", "uri", "request_path", "route", "resource"],
    "service": ["service", "service_name", "app", "application", "module", "component"],
    "latency_ms": ["latency_ms", "latency", "response_time", "duration", "elapsed_ms", "time_ms", "response_time_ms"],
    "country": ["country", "geo_country", "location", "region", "geo"],
    "user_agent": ["user_agent", "ua", "browser", "client"],
    "session_id": ["session_id", "session", "sid", "request_id"],
    "bytes_sent": ["bytes_sent", "bytes", "response_size", "size", "content_length"],
}

# ─── ML Configuration ──────────────────────────────────────────────
ML_CONFIG = {
    "isolation_forest": {
        "contamination": 0.05,
        "n_estimators": 100,
        "random_state": 42,
    },
    "kmeans": {
        "n_clusters": 4,
        "random_state": 42,
    },
    "dbscan": {
        "eps": 0.5,
        "min_samples": 5,
    },
    "zscore_window": 20,
    "zscore_threshold": 2.5,
}

# ─── Page Configuration ────────────────────────────────────────────
PAGES = {
    "executive": {"icon": "📊", "label": "Executive Dashboard"},
    "security": {"icon": "🔐", "label": "Security Intelligence"},
    "performance": {"icon": "⚡", "label": "Performance & SRE"},
    "ml_insights": {"icon": "🤖", "label": "ML Insights"},
    "alerts": {"icon": "🚨", "label": "Alerts Center"},
    "reports": {"icon": "📝", "label": "Reports"},
}
