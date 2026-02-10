"""
Log Analyzer X – Usage Analytics
User behavior baselines, session reconstruction, activity heatmaps,
and session drop-off analysis.
"""

import pandas as pd
import numpy as np


def build_user_profiles(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build user behavior profiles with baseline metrics.
    """
    if "user_id" not in df.columns:
        return pd.DataFrame()

    agg_dict = {"user_id": "size"}
    if "is_failure" in df.columns:
        agg_dict["is_failure"] = "sum"
    if "latency_ms" in df.columns:
        agg_dict["latency_ms"] = "mean"
    if "bytes_sent" in df.columns:
        agg_dict["bytes_sent"] = "sum"

    profiles = df.groupby("user_id").agg(**{
        "total_requests": ("user_id", "size"),
        "failure_count": ("is_failure", "sum") if "is_failure" in df.columns else ("user_id", lambda x: 0),
        "avg_latency": ("latency_ms", "mean") if "latency_ms" in df.columns else ("user_id", lambda x: 0),
        "total_bytes": ("bytes_sent", "sum") if "bytes_sent" in df.columns else ("user_id", lambda x: 0),
        "unique_services": ("service", "nunique") if "service" in df.columns else ("user_id", lambda x: 0),
        "unique_ips": ("ip_address", "nunique") if "ip_address" in df.columns else ("user_id", lambda x: 0),
        "unique_endpoints": ("endpoint", "nunique") if "endpoint" in df.columns else ("user_id", lambda x: 0),
    }).reset_index()

    profiles["failure_rate"] = (profiles["failure_count"] / profiles["total_requests"] * 100).round(2)
    profiles["avg_latency"] = profiles["avg_latency"].round(1)

    # Classify user types
    p75_requests = profiles["total_requests"].quantile(0.75)
    p25_requests = profiles["total_requests"].quantile(0.25)

    def classify_user(row):
        if row["failure_rate"] > 50:
            return "Suspicious"
        if row["total_requests"] > p75_requests and row["unique_services"] > 3:
            return "Power User"
        if row["total_requests"] < p25_requests:
            return "Light User"
        return "Normal User"

    profiles["user_type"] = profiles.apply(classify_user, axis=1)

    return profiles.sort_values("total_requests", ascending=False)


def build_activity_heatmap_data(df: pd.DataFrame) -> pd.DataFrame:
    """
    Build hour-of-day × day-of-week activity heatmap data.
    """
    if "hour" not in df.columns or "day_of_week" not in df.columns:
        return pd.DataFrame()

    heatmap = df.groupby(["day_of_week", "hour"]).size().reset_index(name="count")

    # Ensure all hour/day combinations exist
    all_hours = pd.DataFrame({
        "day_of_week": sorted(heatmap["day_of_week"].unique().tolist() * 24),
        "hour": list(range(24)) * len(heatmap["day_of_week"].unique()),
    }).drop_duplicates()

    heatmap = all_hours.merge(heatmap, on=["day_of_week", "hour"], how="left").fillna(0)
    return heatmap


def analyze_sessions(df: pd.DataFrame) -> dict:
    """
    Session-level analysis: duration, request count, drop-off patterns.
    """
    if "session_id" not in df.columns or "timestamp" not in df.columns:
        return {"sessions": pd.DataFrame(), "stats": {}}

    session_stats = df.groupby("session_id").agg(
        start_time=("timestamp", "min"),
        end_time=("timestamp", "max"),
        request_count=("session_id", "size"),
        unique_services=("service", "nunique") if "service" in df.columns else ("session_id", lambda x: 1),
        failure_count=("is_failure", "sum") if "is_failure" in df.columns else ("session_id", lambda x: 0),
        avg_latency=("latency_ms", "mean") if "latency_ms" in df.columns else ("session_id", lambda x: 0),
    ).reset_index()

    session_stats["duration_sec"] = (
        session_stats["end_time"] - session_stats["start_time"]
    ).dt.total_seconds()

    session_stats["has_failure"] = session_stats["failure_count"] > 0

    # Drop-off analysis: sessions ending with errors
    last_requests = df.sort_values("timestamp").groupby("session_id").tail(1)
    sessions_ending_error = last_requests[last_requests["is_failure"] == True]["session_id"].nunique() if "is_failure" in last_requests.columns else 0

    total_sessions = session_stats["session_id"].nunique()
    stats = {
        "total_sessions": total_sessions,
        "avg_duration_sec": round(session_stats["duration_sec"].mean(), 1),
        "avg_requests_per_session": round(session_stats["request_count"].mean(), 1),
        "sessions_with_errors_pct": round((session_stats["has_failure"].sum() / total_sessions) * 100, 1) if total_sessions > 0 else 0,
        "drop_off_rate_pct": round((sessions_ending_error / total_sessions) * 100, 1) if total_sessions > 0 else 0,
    }

    return {"sessions": session_stats, "stats": stats}


def get_top_endpoints(df: pd.DataFrame, n: int = 10) -> pd.DataFrame:
    """Get top N most accessed endpoints."""
    if "endpoint" not in df.columns:
        return pd.DataFrame()

    top = df.groupby("endpoint").agg(
        request_count=("endpoint", "size"),
        avg_latency=("latency_ms", "mean") if "latency_ms" in df.columns else ("endpoint", lambda x: 0),
        error_rate=("is_failure", "mean") if "is_failure" in df.columns else ("endpoint", lambda x: 0),
    ).reset_index()

    top["avg_latency"] = top["avg_latency"].round(1)
    top["error_rate"] = (top["error_rate"] * 100).round(2)

    return top.sort_values("request_count", ascending=False).head(n)


def get_service_usage(df: pd.DataFrame) -> pd.DataFrame:
    """Get usage breakdown by service."""
    if "service" not in df.columns:
        return pd.DataFrame()

    usage = df.groupby("service").agg(
        request_count=("service", "size"),
        unique_users=("user_id", "nunique") if "user_id" in df.columns else ("service", lambda x: 0),
        avg_latency=("latency_ms", "mean") if "latency_ms" in df.columns else ("service", lambda x: 0),
        error_count=("is_failure", "sum") if "is_failure" in df.columns else ("service", lambda x: 0),
    ).reset_index()

    usage["error_rate"] = (usage["error_count"] / usage["request_count"] * 100).round(2)
    usage["avg_latency"] = usage["avg_latency"].round(1)

    return usage.sort_values("request_count", ascending=False)


def run_usage_analysis(df: pd.DataFrame) -> dict:
    """Run the full usage analysis pipeline."""
    profiles = build_user_profiles(df)
    heatmap = build_activity_heatmap_data(df)
    session_analysis = analyze_sessions(df)
    top_endpoints = get_top_endpoints(df)
    service_usage = get_service_usage(df)

    return {
        "user_profiles": profiles,
        "heatmap_data": heatmap,
        "session_analysis": session_analysis,
        "top_endpoints": top_endpoints,
        "service_usage": service_usage,
        "total_users": profiles["user_id"].nunique() if not profiles.empty else 0,
        "suspicious_users": len(profiles[profiles["user_type"] == "Suspicious"]) if not profiles.empty else 0,
    }
