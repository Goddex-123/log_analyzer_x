"""
Log Analyzer X – Risk Scoring
Composite risk score (0–100) per user/IP combining multiple signal sources.

Score Components (weighted):
- Failure rate:       25%  (high auth failure rates indicate compromise)
- Anomaly score:      25%  (Isolation Forest anomaly signal)
- Geo deviation:      15%  (access from unusual countries)
- Behavior cluster:   15%  (membership in suspicious cluster)
- Request volume:     10%  (anomalous request volumes)
- IP reputation:      10%  (associated with known-bad IPs)

Risk Tiers:
- 0-25:   Low      (normal activity)
- 26-50:  Medium   (minor deviations, monitor)
- 51-75:  High     (significant risk, investigate)
- 76-100: Critical (immediate action required)
"""

import pandas as pd
import numpy as np


def calculate_user_risk_scores(df: pd.DataFrame, security_results: dict = None,
                                ml_results: dict = None) -> pd.DataFrame:
    """
    Calculate composite risk scores per user.
    Combines multiple signal sources into a single 0-100 score.
    """
    if "user_id" not in df.columns:
        return pd.DataFrame()

    # Build base user metrics
    users = df.groupby("user_id").agg(
        total_requests=("user_id", "size"),
        failure_rate=("is_failure", "mean") if "is_failure" in df.columns else ("user_id", lambda x: 0),
        unique_ips=("ip_address", "nunique") if "ip_address" in df.columns else ("user_id", lambda x: 1),
        unique_countries=("country", "nunique") if "country" in df.columns else ("user_id", lambda x: 1),
        avg_latency=("latency_ms", "mean") if "latency_ms" in df.columns else ("user_id", lambda x: 0),
    ).reset_index()

    # ─── Component 1: Failure Rate Score (0-100) ──────────────
    users["score_failure"] = (users["failure_rate"] * 100).clip(0, 100)

    # ─── Component 2: Anomaly Score (0-100) ───────────────────
    users["score_anomaly"] = 0.0
    if ml_results and "isolation_forest" in ml_results:
        if_results = ml_results["isolation_forest"].get("results", pd.DataFrame())
        if not if_results.empty and "session_id" in df.columns and "user_id" in df.columns:
            # Map sessions to users, get average anomaly score
            session_user = df[["session_id", "user_id"]].drop_duplicates()
            if_with_user = if_results.merge(session_user, on="session_id", how="left")
            if "anomaly_score" in if_with_user.columns:
                user_anomaly = if_with_user.groupby("user_id")["anomaly_score"].mean().reset_index()
                user_anomaly.columns = ["user_id", "avg_anomaly_score"]
                users = users.merge(user_anomaly, on="user_id", how="left")
                # Convert: lower anomaly_score = higher risk
                users["score_anomaly"] = ((0 - users["avg_anomaly_score"].fillna(0)) * 50 + 50).clip(0, 100)

    # ─── Component 3: Geo Deviation Score (0-100) ─────────────
    users["score_geo"] = np.where(
        users["unique_countries"] >= 5, 100,
        np.where(users["unique_countries"] >= 3, 60,
                 np.where(users["unique_countries"] >= 2, 30, 0))
    )

    # ─── Component 4: Behavior Cluster Score (0-100) ──────────
    users["score_cluster"] = 0.0
    if ml_results and "kmeans" in ml_results:
        kmeans_results = ml_results["kmeans"].get("results", pd.DataFrame())
        if not kmeans_results.empty and "cluster_label" in kmeans_results.columns:
            cluster_risk = kmeans_results[["user_id", "cluster_label"]].copy()
            cluster_risk["score_cluster"] = cluster_risk["cluster_label"].apply(
                lambda x: 80 if "Suspicious" in str(x) else (20 if "Power" in str(x) else 0)
            )
            users = users.merge(cluster_risk[["user_id", "score_cluster"]], on="user_id", how="left", suffixes=("", "_new"))
            if "score_cluster_new" in users.columns:
                users["score_cluster"] = users["score_cluster_new"].fillna(users["score_cluster"])
                users = users.drop(columns=["score_cluster_new"])

    # ─── Component 5: Request Volume Score (0-100) ────────────
    q99 = users["total_requests"].quantile(0.99)
    users["score_volume"] = np.where(
        users["total_requests"] > q99, 70,
        np.where(users["total_requests"] > users["total_requests"].quantile(0.95), 40, 0)
    )

    # ─── Component 6: IP Reputation Score (0-100) ─────────────
    users["score_ip_rep"] = 0.0
    if security_results and "ip_reputation" in security_results:
        ip_rep = security_results["ip_reputation"]
        if not ip_rep.empty:
            # Map user's most common IP to its reputation
            user_ips = df.groupby("user_id")["ip_address"].agg(lambda x: x.mode().iloc[0] if len(x.mode()) > 0 else "unknown").reset_index()
            user_ips.columns = ["user_id", "primary_ip"]
            user_ips = user_ips.merge(ip_rep[["ip_address", "reputation_score"]], left_on="primary_ip", right_on="ip_address", how="left")
            users = users.merge(user_ips[["user_id", "reputation_score"]], on="user_id", how="left")
            users["score_ip_rep"] = users["reputation_score"].fillna(0)
            users = users.drop(columns=["reputation_score"], errors="ignore")

    # ─── Composite Risk Score ─────────────────────────────────
    users["risk_score"] = (
        users["score_failure"] * 0.25 +
        users["score_anomaly"] * 0.25 +
        users["score_geo"] * 0.15 +
        users["score_cluster"] * 0.15 +
        users["score_volume"] * 0.10 +
        users["score_ip_rep"] * 0.10
    ).clip(0, 100).round(1)

    # ─── Risk Tiers ───────────────────────────────────────────
    users["risk_tier"] = pd.cut(
        users["risk_score"],
        bins=[-1, 25, 50, 75, 100],
        labels=["Low", "Medium", "High", "Critical"]
    )

    return users.sort_values("risk_score", ascending=False)


def calculate_ip_risk_scores(df: pd.DataFrame, security_results: dict = None) -> pd.DataFrame:
    """Calculate risk scores per IP address."""
    if "ip_address" not in df.columns:
        return pd.DataFrame()

    ips = df.groupby("ip_address").agg(
        total_requests=("ip_address", "size"),
        failure_rate=("is_failure", "mean") if "is_failure" in df.columns else ("ip_address", lambda x: 0),
        unique_users=("user_id", "nunique") if "user_id" in df.columns else ("ip_address", lambda x: 1),
        unique_countries=("country", "nunique") if "country" in df.columns else ("ip_address", lambda x: 1),
    ).reset_index()

    # Simple composite for IPs
    ips["risk_score"] = (
        (ips["failure_rate"] * 100).clip(0, 100) * 0.40 +
        np.where(ips["unique_users"] > 5, 60, ips["unique_users"] * 10).clip(0, 100) * 0.30 +
        np.where(ips["total_requests"] > ips["total_requests"].quantile(0.95), 70, 20) * 0.30
    ).clip(0, 100).round(1)

    ips["risk_tier"] = pd.cut(
        ips["risk_score"],
        bins=[-1, 25, 50, 75, 100],
        labels=["Low", "Medium", "High", "Critical"]
    )

    return ips.sort_values("risk_score", ascending=False)


def get_risk_summary(user_risks: pd.DataFrame, ip_risks: pd.DataFrame) -> dict:
    """Get a summary of risk distribution."""
    summary = {
        "total_users_scored": len(user_risks) if not user_risks.empty else 0,
        "total_ips_scored": len(ip_risks) if not ip_risks.empty else 0,
    }

    if not user_risks.empty:
        summary["user_risk_distribution"] = user_risks["risk_tier"].value_counts().to_dict()
        summary["critical_users"] = len(user_risks[user_risks["risk_tier"] == "Critical"])
        summary["high_risk_users"] = len(user_risks[user_risks["risk_tier"] == "High"])
        summary["avg_risk_score"] = round(user_risks["risk_score"].mean(), 1)
    else:
        summary["user_risk_distribution"] = {}
        summary["critical_users"] = 0
        summary["high_risk_users"] = 0
        summary["avg_risk_score"] = 0

    if not ip_risks.empty:
        summary["ip_risk_distribution"] = ip_risks["risk_tier"].value_counts().to_dict()
        summary["critical_ips"] = len(ip_risks[ip_risks["risk_tier"] == "Critical"])
    else:
        summary["ip_risk_distribution"] = {}
        summary["critical_ips"] = 0

    return summary
