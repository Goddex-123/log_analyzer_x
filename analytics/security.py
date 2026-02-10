"""
Log Analyzer X – Security Analytics
Detects brute force attacks, credential stuffing, IP reputation scoring,
geo-location anomalies, and MITRE ATT&CK technique mapping.
"""

import pandas as pd
import numpy as np
from config.settings import SECURITY, MITRE_MAPPING


def detect_brute_force(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect brute-force login attempts.
    Pattern: ≥N failed login attempts from the same IP within a time window.
    """
    if "timestamp" not in df.columns or "ip_address" not in df.columns:
        return pd.DataFrame()

    # Filter to auth-related failures
    auth_mask = df["is_failure"] == True
    if "endpoint" in df.columns:
        login_endpoints = ["/login", "/auth", "/signin", "/authenticate", "/token"]
        endpoint_mask = df["endpoint"].str.lower().isin(login_endpoints)
        auth_mask = auth_mask & endpoint_mask

    failures = df[auth_mask].copy()
    if failures.empty:
        return pd.DataFrame()

    # Group by IP and check for bursts within time windows
    window = f"{SECURITY['brute_force_window_min']}min"
    threshold = SECURITY["brute_force_threshold"]

    results = []
    for ip, group in failures.groupby("ip_address"):
        group = group.sort_values("timestamp")
        # Rolling window count
        group = group.set_index("timestamp")
        rolling_count = group.resample(window).size()
        breaches = rolling_count[rolling_count >= threshold]

        for ts, count in breaches.items():
            window_data = group.loc[ts:ts + pd.Timedelta(window)]
            targeted_users = window_data["user_id"].unique().tolist() if "user_id" in window_data.columns else []
            results.append({
                "detection_type": "brute_force",
                "ip_address": ip,
                "timestamp": ts,
                "attempt_count": int(count),
                "targeted_users": targeted_users[:5],
                "mitre_technique": MITRE_MAPPING["brute_force"]["technique_id"],
                "mitre_name": MITRE_MAPPING["brute_force"]["technique_name"],
                "severity": "CRITICAL" if count >= threshold * 2 else "WARNING",
                "country": window_data["country"].mode().iloc[0] if "country" in window_data.columns and len(window_data) > 0 else "Unknown",
            })

    return pd.DataFrame(results) if results else pd.DataFrame()


def detect_credential_stuffing(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect credential stuffing patterns.
    Pattern: Many unique usernames attempted from a single IP in a short window.
    """
    if "timestamp" not in df.columns or "ip_address" not in df.columns or "user_id" not in df.columns:
        return pd.DataFrame()

    auth_failures = df[df["is_failure"] == True].copy()
    if auth_failures.empty:
        return pd.DataFrame()

    window = f"{SECURITY['credential_stuffing_window_min']}min"
    threshold = SECURITY["credential_stuffing_threshold"]

    results = []
    for ip, group in auth_failures.groupby("ip_address"):
        group = group.sort_values("timestamp")
        # Check unique users within rolling windows
        for i in range(0, len(group), max(1, len(group) // 20)):
            row = group.iloc[i]
            ts = row["timestamp"]
            window_end = ts + pd.Timedelta(window)
            window_data = group[(group["timestamp"] >= ts) & (group["timestamp"] <= window_end)]
            unique_users = window_data["user_id"].nunique()

            if unique_users >= threshold:
                results.append({
                    "detection_type": "credential_stuffing",
                    "ip_address": ip,
                    "timestamp": ts,
                    "unique_users_targeted": int(unique_users),
                    "total_attempts": len(window_data),
                    "mitre_technique": MITRE_MAPPING["credential_stuffing"]["technique_id"],
                    "mitre_name": MITRE_MAPPING["credential_stuffing"]["technique_name"],
                    "severity": "CRITICAL",
                    "country": window_data["country"].mode().iloc[0] if "country" in window_data.columns and len(window_data) > 0 else "Unknown",
                })
                break  # One detection per IP

    return pd.DataFrame(results) if results else pd.DataFrame()


def calculate_ip_reputation(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculate IP reputation scores (rule-based simulation).
    Factors: failure ratio, request volume, geo-diversity, attack involvement.
    Score: 0 (trusted) to 100 (malicious).
    """
    if "ip_address" not in df.columns:
        return pd.DataFrame()

    ip_stats = df.groupby("ip_address").agg(
        total_requests=("ip_address", "size"),
        failure_count=("is_failure", "sum"),
        unique_users=("user_id", "nunique") if "user_id" in df.columns else ("ip_address", "size"),
        unique_endpoints=("endpoint", "nunique") if "endpoint" in df.columns else ("ip_address", "size"),
        unique_countries=("country", "nunique") if "country" in df.columns else ("ip_address", lambda x: 1),
    ).reset_index()

    ip_stats["failure_ratio"] = ip_stats["failure_count"] / ip_stats["total_requests"]

    # Score components (0–100 each, then weighted average)
    ip_stats["score_failure"] = (ip_stats["failure_ratio"] * 100).clip(0, 100)
    ip_stats["score_volume"] = np.where(
        ip_stats["total_requests"] > ip_stats["total_requests"].quantile(0.95),
        80, ip_stats["total_requests"] / ip_stats["total_requests"].quantile(0.95) * 40
    )
    ip_stats["score_user_spread"] = np.where(
        ip_stats["unique_users"] > 5, 60 + (ip_stats["unique_users"] - 5) * 4, 0
    ).clip(0, 100)

    # Weighted composite
    ip_stats["reputation_score"] = (
        ip_stats["score_failure"] * 0.50 +
        ip_stats["score_volume"] * 0.20 +
        ip_stats["score_user_spread"] * 0.30
    ).clip(0, 100).round(1)

    # Risk tier
    ip_stats["risk_tier"] = pd.cut(
        ip_stats["reputation_score"],
        bins=[-1, 25, 50, 70, 100],
        labels=["Low", "Medium", "High", "Critical"]
    )

    return ip_stats[["ip_address", "total_requests", "failure_count", "failure_ratio",
                      "unique_users", "reputation_score", "risk_tier"]].sort_values(
        "reputation_score", ascending=False
    )


def detect_geo_anomalies(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect geo-location anomalies: users accessing from unexpected countries.
    Flags users seen from multiple countries, especially if they deviate from their baseline.
    """
    if "user_id" not in df.columns or "country" not in df.columns:
        return pd.DataFrame()

    user_countries = df.groupby("user_id")["country"].agg(
        countries=lambda x: list(x.unique()),
        num_countries="nunique",
        primary_country=lambda x: x.mode().iloc[0] if len(x.mode()) > 0 else "Unknown",
    ).reset_index()

    # Flag users with access from 3+ countries
    anomalies = user_countries[user_countries["num_countries"] >= 3].copy()
    anomalies["severity"] = np.where(anomalies["num_countries"] >= 5, "CRITICAL", "WARNING")
    anomalies["anomaly_type"] = "geo_deviation"

    return anomalies


def map_mitre_techniques(detections: list) -> pd.DataFrame:
    """
    Map all detections to MITRE ATT&CK techniques.
    """
    mitre_records = []
    for detection_type, det_df in detections:
        if det_df.empty:
            continue
        for _, row in det_df.iterrows():
            technique_key = row.get("detection_type", detection_type)
            mitre_info = MITRE_MAPPING.get(technique_key, MITRE_MAPPING.get("valid_accounts"))
            mitre_records.append({
                "technique_id": mitre_info["technique_id"],
                "technique_name": mitre_info["technique_name"],
                "tactic": mitre_info["tactic"],
                "description": mitre_info["description"],
                "detection_source": detection_type,
                "severity": row.get("severity", "INFO"),
                "timestamp": row.get("timestamp", None),
                "ip_address": row.get("ip_address", "N/A"),
            })

    return pd.DataFrame(mitre_records) if mitre_records else pd.DataFrame()


def run_security_analysis(df: pd.DataFrame) -> dict:
    """
    Run the full security analysis pipeline.
    Returns a dict with all detection results.
    """
    brute_force = detect_brute_force(df)
    credential_stuffing = detect_credential_stuffing(df)
    ip_reputation = calculate_ip_reputation(df)
    geo_anomalies = detect_geo_anomalies(df)

    # MITRE mapping
    detections = [
        ("brute_force", brute_force),
        ("credential_stuffing", credential_stuffing),
    ]
    mitre_map = map_mitre_techniques(detections)

    # Security risk index (0-100)
    risk_score = 0
    risk_score += min(len(brute_force) * 5, 30)
    risk_score += min(len(credential_stuffing) * 10, 30)
    risk_score += min(len(geo_anomalies) * 3, 20)
    if not ip_reputation.empty:
        high_risk_ips = (ip_reputation["reputation_score"] >= SECURITY["high_risk_score"]).sum()
        risk_score += min(high_risk_ips * 2, 20)
    risk_score = min(risk_score, 100)

    # Total failure rate
    total = len(df)
    failure_count = df["is_failure"].sum() if "is_failure" in df.columns else 0
    failure_rate = (failure_count / total * 100) if total > 0 else 0

    return {
        "brute_force": brute_force,
        "credential_stuffing": credential_stuffing,
        "ip_reputation": ip_reputation,
        "geo_anomalies": geo_anomalies,
        "mitre_mapping": mitre_map,
        "risk_index": risk_score,
        "total_threats": len(brute_force) + len(credential_stuffing),
        "high_risk_ips": len(ip_reputation[ip_reputation["reputation_score"] >= SECURITY["high_risk_score"]]) if not ip_reputation.empty else 0,
        "failure_rate": round(failure_rate, 2),
    }
