"""
Log Analyzer X – Data Cleaner
Handles data validation, normalization, type coercion, and preprocessing.
"""

import pandas as pd
import numpy as np
from utils.helpers import classify_status, is_failure


def clean_and_normalize(df: pd.DataFrame, column_mapping: dict) -> pd.DataFrame:
    """
    Clean and normalize the ingested DataFrame.
    - Renames columns to standard names based on mapping
    - Coerces types (timestamps, numerics)
    - Fills nulls sensibly
    - Adds derived columns
    """
    df = df.copy()

    # ─── Rename columns to standard names ──────────────────────
    rename_map = {v: k for k, v in column_mapping.items()}
    df = df.rename(columns=rename_map)

    # ─── Timestamp parsing ─────────────────────────────────────
    if "timestamp" in df.columns:
        df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", infer_datetime_format=True)
        df = df.dropna(subset=["timestamp"])
        df = df.sort_values("timestamp").reset_index(drop=True)
        df["hour"] = df["timestamp"].dt.hour
        df["day_of_week"] = df["timestamp"].dt.dayofweek
        df["date"] = df["timestamp"].dt.date
        df["hour_bucket"] = df["timestamp"].dt.floor("1h")

    # ─── Numeric coercion ──────────────────────────────────────
    for col in ["latency_ms", "bytes_sent", "status"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    # ─── Status classification ─────────────────────────────────
    if "status" in df.columns:
        df["status_category"] = df["status"].apply(classify_status)
        df["is_failure"] = df["status"].apply(is_failure)
    else:
        df["status_category"] = "unknown"
        df["is_failure"] = False

    # ─── Fill defaults ─────────────────────────────────────────
    fill_defaults = {
        "user_id": "unknown",
        "ip_address": "0.0.0.0",
        "method": "GET",
        "endpoint": "/unknown",
        "service": "unknown-service",
        "country": "UNKNOWN",
        "user_agent": "unknown",
        "session_id": "unknown",
    }
    for col, default in fill_defaults.items():
        if col in df.columns:
            df[col] = df[col].fillna(default).astype(str)
        else:
            df[col] = default

    if "latency_ms" in df.columns:
        df["latency_ms"] = df["latency_ms"].fillna(df["latency_ms"].median())
    if "bytes_sent" in df.columns:
        df["bytes_sent"] = df["bytes_sent"].fillna(0)

    return df


def get_data_quality_report(df: pd.DataFrame) -> dict:
    """Generate a data quality report for the cleaned DataFrame."""
    total = len(df)
    report = {
        "total_records": total,
        "date_range": None,
        "columns_available": list(df.columns),
        "quality_score": 100.0,
        "issues": [],
    }

    if "timestamp" in df.columns and not df["timestamp"].isnull().all():
        report["date_range"] = {
            "start": df["timestamp"].min().strftime("%Y-%m-%d %H:%M"),
            "end": df["timestamp"].max().strftime("%Y-%m-%d %H:%M"),
            "span_hours": round((df["timestamp"].max() - df["timestamp"].min()).total_seconds() / 3600, 1),
        }

    # Check for quality issues
    penalty = 0
    for col in df.columns:
        null_pct = (df[col].isnull().sum() / total) * 100
        if null_pct > 20:
            report["issues"].append(f"Column '{col}' has {null_pct:.1f}% null values")
            penalty += min(null_pct / 10, 5)

    if "latency_ms" in df.columns:
        neg_count = (df["latency_ms"] < 0).sum()
        if neg_count > 0:
            report["issues"].append(f"{neg_count} records with negative latency")
            penalty += 2

    report["quality_score"] = max(0, 100 - penalty)
    return report
