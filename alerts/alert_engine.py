"""
Log Analyzer X – Alert Engine
Rule-based alerting with severity levels, alert cards, history tracking, and CSV export.
"""

import pandas as pd
from datetime import datetime
from config.settings import SECURITY, SLA_THRESHOLDS


def generate_alerts(df: pd.DataFrame, security_results: dict = None,
                    performance_results: dict = None, anomaly_results: dict = None,
                    risk_results: dict = None) -> list:
    """
    Generate alerts based on all analysis results.
    Returns a list of alert dicts.
    """
    alerts = []
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ─── Security Alerts ──────────────────────────────────────
    if security_results:
        # Brute force detections
        bf = security_results.get("brute_force", pd.DataFrame())
        if not bf.empty:
            for _, row in bf.iterrows():
                alerts.append({
                    "id": f"SEC-BF-{len(alerts)+1:04d}",
                    "title": "Brute Force Attack Detected",
                    "description": f"IP {row.get('ip_address', 'N/A')} made {row.get('attempt_count', 0)} failed login attempts.",
                    "severity": row.get("severity", "CRITICAL"),
                    "category": "Security",
                    "timestamp": str(row.get("timestamp", now)),
                    "details": f"MITRE: {row.get('mitre_technique', 'T1110')} | Country: {row.get('country', 'N/A')}",
                    "source": "security_engine",
                })

        # Credential stuffing
        cs = security_results.get("credential_stuffing", pd.DataFrame())
        if not cs.empty:
            for _, row in cs.iterrows():
                alerts.append({
                    "id": f"SEC-CS-{len(alerts)+1:04d}",
                    "title": "Credential Stuffing Pattern",
                    "description": f"IP {row.get('ip_address', 'N/A')} targeted {row.get('unique_users_targeted', 0)} unique accounts.",
                    "severity": "CRITICAL",
                    "category": "Security",
                    "timestamp": str(row.get("timestamp", now)),
                    "details": f"Total attempts: {row.get('total_attempts', 0)} | MITRE: T1110.004",
                    "source": "security_engine",
                })

        # High-risk IPs
        high_risk_count = security_results.get("high_risk_ips", 0)
        if high_risk_count > 0:
            alerts.append({
                "id": f"SEC-IP-{len(alerts)+1:04d}",
                "title": "High-Risk IPs Detected",
                "description": f"{high_risk_count} IP addresses flagged with elevated risk scores.",
                "severity": "WARNING",
                "category": "Security",
                "timestamp": now,
                "details": f"Risk threshold: {SECURITY['high_risk_score']}+",
                "source": "ip_reputation",
            })

    # ─── Performance Alerts ───────────────────────────────────
    if performance_results:
        sla = performance_results.get("sla_breaches", pd.DataFrame())
        if not sla.empty:
            for _, row in sla.iterrows():
                alerts.append({
                    "id": f"PERF-SLA-{len(alerts)+1:04d}",
                    "title": f"SLA Breach: {row.get('service', 'N/A')}",
                    "description": row.get("breach_details", "SLA threshold exceeded."),
                    "severity": row.get("severity", "WARNING"),
                    "category": "Performance",
                    "timestamp": now,
                    "details": f"p95: {row.get('p95_latency', 0):.0f}ms | Error rate: {row.get('error_rate_pct', 0):.1f}%",
                    "source": "sla_monitor",
                })

        bottlenecks = performance_results.get("bottlenecks", [])
        for bn in bottlenecks:
            alerts.append({
                "id": f"PERF-BN-{len(alerts)+1:04d}",
                "title": f"Bottleneck: {bn.get('service', 'N/A')}",
                "description": bn.get("detail", "Performance bottleneck detected."),
                "severity": bn.get("severity", "WARNING"),
                "category": "Performance",
                "timestamp": now,
                "details": f"Type: {bn.get('type', 'Unknown')}",
                "source": "bottleneck_detector",
            })

    # ─── Anomaly Alerts ───────────────────────────────────────
    if anomaly_results:
        latency_spikes = anomaly_results.get("total_latency_spikes", 0)
        if latency_spikes > 0:
            alerts.append({
                "id": f"ANOM-LAT-{len(alerts)+1:04d}",
                "title": "Latency Anomalies Detected",
                "description": f"{latency_spikes} time periods with abnormal latency patterns.",
                "severity": "WARNING" if latency_spikes < 5 else "CRITICAL",
                "category": "Anomaly",
                "timestamp": now,
                "details": "Detected via rolling Z-score analysis",
                "source": "anomaly_engine",
            })

        error_spikes = anomaly_results.get("total_error_spikes", 0)
        if error_spikes > 0:
            alerts.append({
                "id": f"ANOM-ERR-{len(alerts)+1:04d}",
                "title": "Error Rate Anomalies",
                "description": f"{error_spikes} time periods with unusual error rate spikes.",
                "severity": "CRITICAL" if error_spikes > 3 else "WARNING",
                "category": "Anomaly",
                "timestamp": now,
                "details": "Detected via rolling Z-score analysis",
                "source": "anomaly_engine",
            })

    # ─── Risk Score Alerts ────────────────────────────────────
    if risk_results:
        critical_users = risk_results.get("critical_users", 0)
        if critical_users > 0:
            alerts.append({
                "id": f"RISK-USR-{len(alerts)+1:04d}",
                "title": "Critical-Risk Users Identified",
                "description": f"{critical_users} user(s) with risk scores above 75.",
                "severity": "CRITICAL",
                "category": "Risk",
                "timestamp": now,
                "details": "Composite risk score based on multiple signals",
                "source": "risk_scoring",
            })

    # Sort by severity
    severity_order = {"CRITICAL": 0, "WARNING": 1, "INFO": 2}
    alerts.sort(key=lambda x: severity_order.get(x["severity"], 3))

    return alerts


def alerts_to_dataframe(alerts: list) -> pd.DataFrame:
    """Convert alerts list to a pandas DataFrame for display and export."""
    if not alerts:
        return pd.DataFrame()
    return pd.DataFrame(alerts)


def export_alerts_csv(alerts: list) -> str:
    """Export alerts as CSV string for download."""
    df = alerts_to_dataframe(alerts)
    if df.empty:
        return ""
    return df.to_csv(index=False)


def get_alert_summary(alerts: list) -> dict:
    """Get a summary breakdown of alerts."""
    if not alerts:
        return {"total": 0, "critical": 0, "warning": 0, "info": 0, "by_category": {}}

    df = pd.DataFrame(alerts)
    return {
        "total": len(alerts),
        "critical": len(df[df["severity"] == "CRITICAL"]),
        "warning": len(df[df["severity"] == "WARNING"]),
        "info": len(df[df["severity"] == "INFO"]),
        "by_category": df["category"].value_counts().to_dict(),
    }
